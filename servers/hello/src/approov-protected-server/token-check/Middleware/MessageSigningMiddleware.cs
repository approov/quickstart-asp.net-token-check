namespace Hello.Middleware;

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Hello.Helpers;

// Validates Approov HTTP message signatures when the token carries an installation public key.
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
            _logger.LogDebug("Message signature check skipped, no Approov token");
            await _next(context);
            return;
        }

        // The ipk claim in Approov token carries the installation public key used to verify the
        // raw HTTP message signature.
        var installationPublicKey = ExtractInstallationPublicKey(token);
        if (string.IsNullOrWhiteSpace(installationPublicKey))
        {
            // If the token doesn't contain the ipk claim then we cannot verify a message signature
            // even if one is provided. (Note that the Approov failover doesn't support adding the
            // IPK claim and so it is important not to reject requests where the ipk is
            // unavailable)
            _logger.LogDebug("Message signature check skipped, no extractable ipk claim");
            await _next(context);
            return;
        }

        var result = await _verifier.VerifyAsync(context, installationPublicKey);
        if (!result.Success)
        {
            _logger.LogWarning("Message signing verification failed: {Reason}", result.Error);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Invalid Token");
            return;
        }

        _logger.LogDebug("Message signature verified");
        await _next(context);
    }

    // Extracts the ipk claim from the JWT token
    private static string? ExtractInstallationPublicKey(string token)
    {
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var ipkClaim = jwt.Claims.FirstOrDefault(claim => string.Equals(claim.Type, "ipk", StringComparison.OrdinalIgnoreCase));
            return ipkClaim?.Value;
        }
        catch (Exception e)
        {
            // log error and return null
            _logger.LogDebug(e, "Error extracting ipk claim");
            return null;
        }
    }
}
