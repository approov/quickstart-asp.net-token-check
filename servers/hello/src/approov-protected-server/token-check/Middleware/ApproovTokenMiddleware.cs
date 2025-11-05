namespace Hello.Middleware;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Hello.Helpers;
using System.Security.Claims;

// Enforces Approov JWT validation before the application pipeline sees the request.
public class ApproovTokenMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AppSettings _appSettings;
    private readonly ILogger<ApproovTokenMiddleware> _logger;

    public ApproovTokenMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings, ILogger<ApproovTokenMiddleware> logger)
    {
        _next = next;
        _appSettings = appSettings.Value;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var path = context.Request.Path.Value;
        if (IsBypassedPath(path))
        {
            await _next(context);
            return;
        }

        var token = context.Request.Headers["Approov-Token"].FirstOrDefault();

        if (token == null) {
            _logger.LogDebug("Missing Approov-Token header.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (verifyApproovToken(context, token)) {
            await _next(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    // Validates the JWT signature, extracts convenience claims, and caches them in HttpContext.Items.
    private bool verifyApproovToken(HttpContext context, string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_appSettings.ApproovSecretBytes),
                ValidateIssuer = false,
                ValidateAudience = false,
                // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            if (validatedToken is JwtSecurityToken jwtToken)
            {
                context.Items[ApproovTokenContextKeys.ApproovToken] = jwtToken;
                context.Items[ApproovTokenContextKeys.TokenExpiry] = jwtToken.ValidTo;

                var claims = jwtToken.Claims;
                var deviceId = claims.FirstOrDefault(c => string.Equals(c.Type, "did", StringComparison.OrdinalIgnoreCase))?.Value;
                if (!string.IsNullOrWhiteSpace(deviceId))
                {
                    context.Items[ApproovTokenContextKeys.DeviceId] = deviceId;
                }

                var payClaim = claims.FirstOrDefault(c => string.Equals(c.Type, "pay", StringComparison.OrdinalIgnoreCase))?.Value;
                if (!string.IsNullOrWhiteSpace(payClaim))
                {
                    context.Items[ApproovTokenContextKeys.TokenBinding] = payClaim;
                }

                var installationPublicKey = claims.FirstOrDefault(c => string.Equals(c.Type, "ipk", StringComparison.OrdinalIgnoreCase))?.Value;
                if (!string.IsNullOrWhiteSpace(installationPublicKey))
                {
                    context.Items[ApproovTokenContextKeys.InstallationPublicKey] = installationPublicKey;
                }
            }

            return true;
        } catch (SecurityTokenExpiredException) {
            _logger.LogDebug("Approov token rejected: expired");
            return false;
        } catch (SecurityTokenNoExpirationException) {
            _logger.LogDebug("Approov token rejected: missing expiration");
            return false;
        } catch (SecurityTokenInvalidSignatureException) {
            _logger.LogDebug("Approov token rejected: invalid signature");
            return false;
        } catch (SecurityTokenException) {
            _logger.LogDebug("Approov token rejected: failed validation");
            return false;
        } catch (Exception exception) {
            _logger.LogError(exception, "Unexpected error during Approov token validation");
            return false;
        }
    }

    // Skips token enforcement for internal test endpoints that operate without Approov headers.
    private static bool IsBypassedPath(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        return path.Equals("/sfv_test", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/ipk_test", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/ipk_message_sign_test", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/hello", StringComparison.OrdinalIgnoreCase);
    }
}
