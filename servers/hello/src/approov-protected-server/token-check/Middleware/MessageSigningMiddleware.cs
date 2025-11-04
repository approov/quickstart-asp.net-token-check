namespace Hello.Middleware;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
        await LogRequestAsync(context);

        if (_settings.MessageSigningMode == MessageSigningMode.None)
        {
            var originalBodyStream = context.Response.Body;
            using var buffer = new MemoryStream();
            context.Response.Body = buffer;

            try
            {
                await _next(context);
            }
            finally
            {
                context.Response.Body = originalBodyStream;
                await LogResponseAsync(context, buffer, originalBodyStream);
            }
            return;
        }

        var originalResponseStream = context.Response.Body;
        using var responseBuffer = new MemoryStream();
        context.Response.Body = responseBuffer;

        if (!context.Items.TryGetValue(ApproovTokenContextKeys.ApproovToken, out var tokenObject) || tokenObject is not string approovToken)
        {
            _logger.LogWarning("DebugLogToRemove: Approov token not found in context items. Message signing verification aborted.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Body = originalResponseStream;
            await LogResponseAsync(context, responseBuffer, originalResponseStream);
            return;
        }

        var signatureHeader = context.Request.Headers["Signature"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(signatureHeader))
        {
            _logger.LogInformation("DebugLogToRemove: Missing Signature header.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Body = originalResponseStream;
            await LogResponseAsync(context, responseBuffer, originalResponseStream);
            return;
        }

        _logger.LogInformation("DebugLogToRemove: Raw Signature header value: {SignatureHeader}", signatureHeader);

        if (!HttpSignatureParser.TryParseSignature(signatureHeader, out var signatureEntry, out var signatureError))
        {
            _logger.LogInformation("DebugLogToRemove: Invalid Signature header: {Error}", signatureError);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Body = originalResponseStream;
            await LogResponseAsync(context, responseBuffer, originalResponseStream);
            return;
        }

        _logger.LogInformation("DebugLogToRemove: Parsed signature entry label={Label} signature={Signature}", signatureEntry.Label, signatureEntry.Signature);

        HttpSignatureInput? signatureInput = null;
        var signatureInputHeader = context.Request.Headers["Signature-Input"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(signatureInputHeader))
        {
            if (!HttpSignatureParser.TryParseSignatureInput(signatureInputHeader, signatureEntry.Label, out signatureInput, out var inputError))
            {
                _logger.LogInformation("DebugLogToRemove: Invalid Signature-Input header: {Error}", inputError);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Body = originalResponseStream;
                await LogResponseAsync(context, responseBuffer, originalResponseStream);
                return;
            }

            var inputDetails = signatureInput!;
            _logger.LogInformation(
                "DebugLogToRemove: Signature-Input components={Components} created={Created} expires={Expires} nonce={Nonce}",
                inputDetails.Components == null ? "<null>" : string.Join(",", inputDetails.Components),
                inputDetails.Created,
                inputDetails.Expires,
                inputDetails.Nonce ?? "<none>");
        }
        else if (_settings.MessageSigningMaxAgeSeconds > 0 || _settings.RequireSignatureNonce)
        {
            _logger.LogInformation("DebugLogToRemove: Missing Signature-Input header required for metadata validation.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Body = originalResponseStream;
            await LogResponseAsync(context, responseBuffer, originalResponseStream);
            return;
        }

        if (!ValidateMetadata(signatureInput, out var metadataError))
        {
            _logger.LogInformation("DebugLogToRemove: Message signature metadata validation failed: {Error}", metadataError);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Body = originalResponseStream;
            await LogResponseAsync(context, responseBuffer, originalResponseStream);
            return;
        }

        var headerNames = DetermineHeaderNames(signatureInput?.Components);
        _logger.LogInformation("DebugLogToRemove: Canonical header selection => {Headers}", string.Join(",", headerNames));

        var canonicalMessage = await MessageSigningUtilities.BuildCanonicalMessageAsync(context.Request, headerNames);

        _logger.LogInformation("DebugLogToRemove: Canonical message method={Method} path+query={Path} bodyHash={BodyHash}",
            canonicalMessage.Method,
            canonicalMessage.PathAndQuery,
            canonicalMessage.BodyHashBase64 ?? "<none>");

        if (canonicalMessage.Headers.Count > 0)
        {
            foreach (var kvp in canonicalMessage.Headers)
            {
                _logger.LogInformation("DebugLogToRemove: Canonical header entry {Header} => {Value}", kvp.Key, kvp.Value);
            }
        }

        _logger.LogInformation("DebugLogToRemove: Canonical payload string=\n{Payload}", canonicalMessage.Payload);

        _logger.LogInformation("DebugLogToRemove: Performing verification in {Mode} mode", _settings.MessageSigningMode);

        var verified = _settings.MessageSigningMode switch
        {
            MessageSigningMode.Installation => VerifyInstallationSignature(context, canonicalMessage.PayloadBytes, signatureEntry.Signature),
            MessageSigningMode.Account => VerifyAccountSignature(context, canonicalMessage.PayloadBytes, signatureEntry.Signature),
            _ => false
        };

        if (!verified)
        {
            _logger.LogInformation("DebugLogToRemove: Verification failed for mode {Mode}", _settings.MessageSigningMode);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Body = originalResponseStream;
            await LogResponseAsync(context, responseBuffer, originalResponseStream);
            return;
        }

        try
        {
            _logger.LogInformation("DebugLogToRemove: Approov message signature verified using {Mode} mode.", _settings.MessageSigningMode);
            await _next(context);
        }
        finally
        {
            context.Response.Body = originalResponseStream;
            await LogResponseAsync(context, responseBuffer, originalResponseStream);
        }
    }

    private bool VerifyInstallationSignature(HttpContext context, byte[] canonicalMessage, string encodedSignature)
    {
        if (!context.Items.TryGetValue(ApproovTokenContextKeys.InstallationPublicKey, out var publicKeyObj) ||
            publicKeyObj is not string installationPublicKey)
        {
            _logger.LogInformation("DebugLogToRemove: Installation public key not found in Approov token.");
            return false;
        }

        _logger.LogInformation("DebugLogToRemove: Installation public key (base64)={PublicKey}", installationPublicKey);
        _logger.LogInformation("DebugLogToRemove: Installation signature (base64)={Signature}", encodedSignature);

        if (!MessageSigningUtilities.VerifyInstallationSignature(canonicalMessage, encodedSignature, installationPublicKey))
        {
            _logger.LogInformation("DebugLogToRemove: Installation message signature verification failed.");
            return false;
        }

        _logger.LogInformation("DebugLogToRemove: Installation signature verification succeeded.");
        return true;
    }

    private bool VerifyAccountSignature(HttpContext context, byte[] canonicalMessage, string encodedSignature)
    {
        if (_settings.AccountMessageBaseSecretBytes is null || _settings.AccountMessageBaseSecretBytes.Length == 0)
        {
            _logger.LogError("DebugLogToRemove: Account message signing base secret not configured.");
            return false;
        }

        if (!context.Items.TryGetValue(ApproovTokenContextKeys.DeviceId, out var deviceIdObj) ||
            deviceIdObj is not string deviceId || string.IsNullOrWhiteSpace(deviceId))
        {
            _logger.LogInformation("DebugLogToRemove: Device ID not present in Approov token.");
            return false;
        }

        if (!context.Items.TryGetValue(ApproovTokenContextKeys.TokenExpiry, out var expiryObj) ||
            expiryObj is not DateTimeOffset tokenExpiry)
        {
            _logger.LogInformation("DebugLogToRemove: Token expiry missing from Approov token context.");
            return false;
        }

        byte[] derivedSecret;
        try
        {
            derivedSecret = MessageSigningUtilities.DeriveSecret(_settings.AccountMessageBaseSecretBytes, deviceId, tokenExpiry);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException)
        {
            _logger.LogInformation("DebugLogToRemove: Failed to derive account message signing secret: {Message}", ex.Message);
            return false;
        }

        _logger.LogInformation("DebugLogToRemove: Account verification metadata deviceId={DeviceId} expiry={Expiry} derivedSecretLength={Length}", deviceId, tokenExpiry, derivedSecret.Length);
        _logger.LogInformation("DebugLogToRemove: Account derived secret (base64)={DerivedSecret}", Convert.ToBase64String(derivedSecret));
        _logger.LogInformation("DebugLogToRemove: Account signature (base64)={Signature}", encodedSignature);

        if (!MessageSigningUtilities.VerifyAccountSignature(canonicalMessage, encodedSignature, derivedSecret))
        {
            _logger.LogInformation("DebugLogToRemove: Account message signature verification failed.");
            return false;
        }

        _logger.LogInformation("DebugLogToRemove: Account signature verification succeeded.");
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

            _logger.LogInformation("DebugLogToRemove: Signature creation timestamp {Created} (UTC {CreatedUtc}) current UTC {Now}", signatureInput.Created.Value, createdAt, now);

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
            _logger.LogInformation("DebugLogToRemove: Signature expires at {Expires} (UTC {ExpiresUtc})", signatureInput.Expires.Value, expiresAt);
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

    private async Task LogRequestAsync(HttpContext context)
    {
        var request = context.Request;
        request.EnableBuffering();
        string bodyText = "<empty>";
        if (request.Body.CanSeek)
        {
            request.Body.Position = 0;
            using var reader = new StreamReader(request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            var content = await reader.ReadToEndAsync();
            if (!string.IsNullOrEmpty(content))
            {
                bodyText = content;
            }
            request.Body.Position = 0;
        }

        var headerText = string.Join(", ", request.Headers.Select(h => $"{h.Key}:{h.Value}"));
        _logger.LogInformation(
            "DebugLogToRemove: Incoming request {Method} {Path}{Query} from {RemoteIp} headers={Headers} body={Body}",
            request.Method,
            request.Path,
            request.QueryString,
            context.Connection.RemoteIpAddress?.ToString() ?? "<unknown>",
            headerText,
            bodyText);
    }

    private async Task LogResponseAsync(HttpContext context, MemoryStream buffer, Stream originalBodyStream)
    {
        buffer.Position = 0;
        string bodyText;
        using (var reader = new StreamReader(buffer, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true))
        {
            var content = await reader.ReadToEndAsync();
            bodyText = string.IsNullOrEmpty(content) ? "<empty>" : content;
        }

        var headerText = string.Join(", ", context.Response.Headers.Select(h => $"{h.Key}:{h.Value}"));
        _logger.LogInformation(
            "DebugLogToRemove: Outgoing response status={Status} headers={Headers} body={Body}",
            context.Response.StatusCode,
            headerText,
            bodyText);

        buffer.Position = 0;
        await buffer.CopyToAsync(originalBodyStream);
        await originalBodyStream.FlushAsync();
    }
}
