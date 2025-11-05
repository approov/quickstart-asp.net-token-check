namespace Hello.Middleware;

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Hello.Helpers;

public class MessageSigningMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<MessageSigningMiddleware> _logger;
    private readonly ApproovMessageSignatureVerifier _verifier;

    public MessageSigningMiddleware(RequestDelegate next, ILogger<MessageSigningMiddleware> logger, ApproovMessageSignatureVerifier verifier)
    {
        _next = next;
        _logger = logger;
        _verifier = verifier;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers["Approov-Token"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(token))
        {
            await _next(context);
            return;
        }

        var installationPublicKey = ExtractInstallationPublicKey(token);
        if (string.IsNullOrWhiteSpace(installationPublicKey))
        {
            await _next(context);
            return;
        }

        var result = await _verifier.VerifyAsync(context, installationPublicKey);
        if (!result.Success)
        {
            _logger.LogInformation("DebugLogToRemove: message signing verification failed: {Reason}", result.Error);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Invalid Token");
            return;
        }

        _logger.LogDebug("DebugLogToRemove: message signature verified");
        await _next(context);
    }

    private static string? ExtractInstallationPublicKey(string token)
    {
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var ipkClaim = jwt.Claims.FirstOrDefault(claim => string.Equals(claim.Type, "ipk", StringComparison.OrdinalIgnoreCase));
            return ipkClaim?.Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
