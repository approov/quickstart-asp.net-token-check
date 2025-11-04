namespace Hello.Middleware;

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Hello.Helpers;
using Microsoft.Extensions.Options;

public class MessageSigningMiddleware
{
    private static readonly TimeSpan FutureTimestampSkewTolerance = TimeSpan.FromSeconds(30);

    private readonly RequestDelegate _next;
    private readonly AppSettings _settings;
    private readonly ILogger<MessageSigningMiddleware> _logger;

    public MessageSigningMiddleware(RequestDelegate next, IOptions<AppSettings> settings, ILogger<MessageSigningMiddleware> logger)
    {
        _next = next;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_settings.MessageSigningMode == MessageSigningMode.None)
        {
            await _next(context);
            return;
        }

        if (!context.Items.TryGetValue(ApproovTokenContextKeys.ApproovToken, out var tokenObject) || tokenObject is not string approovToken)
        {
            _logger.LogWarning("Approov token not found in context items. Message signing verification aborted.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var signatureHeader = context.Request.Headers["Signature"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(signatureHeader))
        {
            _logger.LogInformation("Missing Signature header.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (!HttpSignatureParser.TryParseSignature(signatureHeader, out var signatureEntry, out var signatureError))
        {
            _logger.LogInformation("Invalid Signature header: {Error}", signatureError);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        HttpSignatureInput? signatureInput = null;
        var signatureInputHeader = context.Request.Headers["Signature-Input"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(signatureInputHeader))
        {
            if (!HttpSignatureParser.TryParseSignatureInput(signatureInputHeader, signatureEntry.Label, out signatureInput, out var inputError))
            {
                _logger.LogInformation("Invalid Signature-Input header: {Error}", inputError);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
        }
        else if (_settings.MessageSigningMaxAgeSeconds > 0 || _settings.RequireSignatureNonce)
        {
            _logger.LogInformation("Missing Signature-Input header required for metadata validation.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (!ValidateMetadata(signatureInput, out var metadataError))
        {
            _logger.LogInformation("Message signature metadata validation failed: {Error}", metadataError);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var headerNames = DetermineHeaderNames(signatureInput?.Components);
        var canonicalMessage = await MessageSigningUtilities.BuildCanonicalMessageAsync(context.Request, headerNames);

        var verified = _settings.MessageSigningMode switch
        {
            MessageSigningMode.Installation => VerifyInstallationSignature(context, canonicalMessage, signatureEntry.Signature),
            MessageSigningMode.Account => VerifyAccountSignature(context, canonicalMessage, signatureEntry.Signature),
            _ => false
        };

        if (!verified)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        _logger.LogDebug("Approov message signature verified using {Mode} mode.", _settings.MessageSigningMode);
        await _next(context);
    }

    private bool VerifyInstallationSignature(HttpContext context, byte[] canonicalMessage, string encodedSignature)
    {
        if (!context.Items.TryGetValue(ApproovTokenContextKeys.InstallationPublicKey, out var publicKeyObj) ||
            publicKeyObj is not string installationPublicKey)
        {
            _logger.LogInformation("Installation public key not found in Approov token.");
            return false;
        }

        if (!MessageSigningUtilities.VerifyInstallationSignature(canonicalMessage, encodedSignature, installationPublicKey))
        {
            _logger.LogInformation("Installation message signature verification failed.");
            return false;
        }

        return true;
    }

    private bool VerifyAccountSignature(HttpContext context, byte[] canonicalMessage, string encodedSignature)
    {
        if (_settings.AccountMessageBaseSecretBytes is null || _settings.AccountMessageBaseSecretBytes.Length == 0)
        {
            _logger.LogError("Account message signing base secret not configured.");
            return false;
        }

        if (!context.Items.TryGetValue(ApproovTokenContextKeys.DeviceId, out var deviceIdObj) ||
            deviceIdObj is not string deviceId || string.IsNullOrWhiteSpace(deviceId))
        {
            _logger.LogInformation("Device ID not present in Approov token.");
            return false;
        }

        if (!context.Items.TryGetValue(ApproovTokenContextKeys.TokenExpiry, out var expiryObj) ||
            expiryObj is not DateTimeOffset tokenExpiry)
        {
            _logger.LogInformation("Token expiry missing from Approov token context.");
            return false;
        }

        byte[] derivedSecret;
        try
        {
            derivedSecret = MessageSigningUtilities.DeriveSecret(_settings.AccountMessageBaseSecretBytes, deviceId, tokenExpiry);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException)
        {
            _logger.LogInformation("Failed to derive account message signing secret: {Message}", ex.Message);
            return false;
        }

        if (!MessageSigningUtilities.VerifyAccountSignature(canonicalMessage, encodedSignature, derivedSecret))
        {
            _logger.LogInformation("Account message signature verification failed.");
            return false;
        }

        return true;
    }

    private bool ValidateMetadata(HttpSignatureInput? signatureInput, out string? error)
    {
        error = null;

        if (signatureInput is null)
        {
            return true;
        }

        if (_settings.RequireSignatureNonce && string.IsNullOrWhiteSpace(signatureInput.Nonce))
        {
            error = "Signature nonce required but not provided.";
            return false;
        }

        if (_settings.MessageSigningMaxAgeSeconds > 0)
        {
            if (!signatureInput.Created.HasValue)
            {
                error = "Signature-Input missing 'created' parameter.";
                return false;
            }

            var createdAt = DateTimeOffset.FromUnixTimeSeconds(signatureInput.Created.Value);
            var now = DateTimeOffset.UtcNow;

            if (now - createdAt > TimeSpan.FromSeconds(_settings.MessageSigningMaxAgeSeconds))
            {
                error = "Signature creation time outside allowable age.";
                return false;
            }

            if (createdAt - now > FutureTimestampSkewTolerance)
            {
                error = "Signature creation time is in the future.";
                return false;
            }
        }

        if (signatureInput.Expires.HasValue)
        {
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(signatureInput.Expires.Value);
            if (DateTimeOffset.UtcNow > expiresAt)
            {
                error = "Signature has expired.";
                return false;
            }
        }

        return true;
    }

    private List<string> DetermineHeaderNames(IReadOnlyList<string>? components)
    {
        var headers = new List<string>();

        if (components is not null && components.Count > 0)
        {
            foreach (var component in components)
            {
                if (string.IsNullOrWhiteSpace(component) || component.StartsWith("@", StringComparison.Ordinal))
                {
                    continue;
                }

                headers.Add(component);
            }
        }
        else if (_settings.MessageSigningHeaderNames.Length > 0)
        {
            headers.AddRange(_settings.MessageSigningHeaderNames);
        }

        if (!headers.Any(header => string.Equals(header, "Approov-Token", StringComparison.OrdinalIgnoreCase)))
        {
            headers.Insert(0, "Approov-Token");
        }

        return headers;
    }
}
