namespace Hello.Middleware;

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Hello.Helpers;
using Microsoft.Extensions.Options;

// Confirms that the pay claim matches the configured binding header values before continuing the request.
public class ApproovTokenBindingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AppSettings _appSettings;
    private readonly ILogger<ApproovTokenBindingMiddleware> _logger;

    public ApproovTokenBindingMiddleware(
        RequestDelegate next,
        IOptions<AppSettings> appSettings,
        ILogger<ApproovTokenBindingMiddleware> logger)
    {
        _next = next;
        _appSettings = appSettings.Value;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var tokenBindingClaim = context.Items.TryGetValue(ApproovTokenContextKeys.TokenBinding, out var bindingObject)
            ? bindingObject as string
            : null;
        if (string.IsNullOrWhiteSpace(tokenBindingClaim))
        {
            _logger.LogDebug("Approov token binding: skipping because pay claim is missing");
            await _next(context);
            return;
        }

        var headerNames = _appSettings.TokenBindingHeaders;
        if (headerNames is null || headerNames.Count == 0)
        {
            _logger.LogDebug("Token binding claim present but no binding header configured; skipping verification.");
            await _next(context);
            return;
        }

        // This method concatenates multiple header values before hashing. We mirror that
        var concatenatedBinding = new StringBuilder();
        var missingHeaders = new List<string>();

        foreach (var headerName in headerNames)
        {
            var value = context.Request.Headers[headerName].ToString();
            if (string.IsNullOrWhiteSpace(value))
            {
                missingHeaders.Add(headerName);
                _logger.LogDebug("Approov token binding: header {Header} missing/empty", headerName);
                continue;
            }

            concatenatedBinding.Append(value.Trim());
        }

        if (missingHeaders.Count > 0)
        {
            _logger.LogInformation(
                "Approov token binding requested but required header(s) '{Headers}' are missing or empty.",
                string.Join(", ", missingHeaders));
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var bindingValue = concatenatedBinding.ToString();

        if (string.IsNullOrWhiteSpace(bindingValue))
        {
            _logger.LogInformation("Approov token binding requested but concatenated header values are empty.");
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        if (!VerifyApproovTokenBinding(bindingValue, tokenBindingClaim))
        {
            _logger.LogInformation(
                "Invalid Approov token binding: expected={Expected} actual={Actual}",
                Sha256Base64Encoded(bindingValue),
                tokenBindingClaim);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        _logger.LogDebug("Approov token binding: binding verified for headers {Headers}", string.Join(",", headerNames));
        context.Items[ApproovTokenContextKeys.TokenBindingVerified] = true;
        await _next(context);
    }

    // Recomputes the binding hash and checks it matches the pay claim in a timing-safe manner.
    private static bool VerifyApproovTokenBinding(string headerValue, string tokenBinding)
    {
        var computedHash = Sha256Base64Encoded(headerValue);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(tokenBinding),
            Encoding.UTF8.GetBytes(computedHash));
    }

    // Helper to keep hashing/encoding consistent with the mobile SDK implementation.
    private static string Sha256Base64Encoded(string input)
    {
        using var sha256 = SHA256.Create();
        var inputBytes = Encoding.UTF8.GetBytes(input);
        var hashBytes = sha256.ComputeHash(inputBytes);
        return Convert.ToBase64String(hashBytes);
    }
}
