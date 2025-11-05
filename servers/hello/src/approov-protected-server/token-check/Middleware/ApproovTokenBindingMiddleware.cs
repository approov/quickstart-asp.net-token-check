namespace Hello.Middleware;

using System.Security.Cryptography;
using System.Text;
using Hello.Helpers;
using Microsoft.Extensions.Options;

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
            await _next(context);
            return;
        }

        var headerName = _appSettings.TokenBindingHeader;
        if (string.IsNullOrWhiteSpace(headerName))
        {
            _logger.LogDebug("Token binding claim present but no binding header configured; skipping verification.");
            await _next(context);
            return;
        }

        var headerValue = context.Request.Headers[headerName].ToString().Trim();
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            _logger.LogInformation(
                "Approov token binding requested but required header '{Header}' is missing or empty.",
                headerName);
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        if (!VerifyApproovTokenBinding(headerValue, tokenBindingClaim))
        {
            _logger.LogInformation("Invalid Approov token binding.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Items[ApproovTokenContextKeys.TokenBindingVerified] = true;
        await _next(context);
    }

    private static bool VerifyApproovTokenBinding(string headerValue, string tokenBinding)
    {
        var computedHash = Sha256Base64Encoded(headerValue);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(tokenBinding),
            Encoding.UTF8.GetBytes(computedHash));
    }

    private static string Sha256Base64Encoded(string input)
    {
        using var sha256 = SHA256.Create();
        var inputBytes = Encoding.UTF8.GetBytes(input);
        var hashBytes = sha256.ComputeHash(inputBytes);
        return Convert.ToBase64String(hashBytes);
    }
}
