namespace Hello.Middleware;

using System.Security.Cryptography;
using System.Text;
using Hello.Helpers;

public class ApproovTokenBindingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ApproovTokenBindingMiddleware> _logger;

    public ApproovTokenBindingMiddleware(RequestDelegate next, ILogger<ApproovTokenBindingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var tokenBinding = context.Items.TryGetValue(ApproovTokenContextKeys.TokenBinding, out var bindingValue)
            ? bindingValue as string
            : null;

        if (string.IsNullOrWhiteSpace(tokenBinding))
        {
            await _next(context);
            return;
        }

        var authorizationToken = context.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(authorizationToken))
        {
            _logger.LogInformation("Approov token binding requested but Authorization header is missing.");
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        if (!VerifyApproovTokenBinding(authorizationToken, tokenBinding))
        {
            _logger.LogInformation("Invalid Approov token binding.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Items[ApproovTokenContextKeys.TokenBindingVerified] = true;
        await _next(context);
    }

    private static bool VerifyApproovTokenBinding(string authorizationToken, string tokenBinding)
    {
        var computedHash = Sha256Base64Encoded(authorizationToken);
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
