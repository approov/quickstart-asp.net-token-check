namespace Hello.Middleware;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Hello.Helpers;

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
        var token = context.Request.Headers["Approov-Token"].FirstOrDefault();

        if (string.IsNullOrWhiteSpace(token)) {
            _logger.LogInformation("Missing Approov-Token header.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (verifyApproovToken(context, token)) {
            context.Items[ApproovTokenContextKeys.ApproovToken] = token;
            await _next(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    private bool verifyApproovToken(HttpContext context, string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            if (_appSettings.ApproovSecretBytes == null || _appSettings.ApproovSecretBytes.Length == 0)
            {
                _logger.LogError("Approov secret bytes not configured.");
                return false;
            }

            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_appSettings.ApproovSecretBytes),
                ValidateIssuer = false,
                ValidateAudience = false,
                // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            captureApproovTokenMetadata(context, jwtToken);

            return true;
        } catch (SecurityTokenException exception) {
            _logger.LogInformation(exception.Message);
            return false;
        } catch (Exception exception) {
            _logger.LogInformation(exception.Message);
            return false;
        }
    }

    private static void captureApproovTokenMetadata(HttpContext context, JwtSecurityToken jwtToken)
    {
        var deviceId = jwtToken.Claims.FirstOrDefault(claim =>
            string.Equals(claim.Type, "did", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(claim.Type, "device_id", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(claim.Type, "device", StringComparison.OrdinalIgnoreCase))
            ?.Value;

        if (!string.IsNullOrWhiteSpace(deviceId))
        {
            context.Items[ApproovTokenContextKeys.DeviceId] = deviceId;
        }

        var expiryUnixSeconds = jwtToken.Payload.Exp;
        if (expiryUnixSeconds.HasValue)
        {
            try
            {
                context.Items[ApproovTokenContextKeys.TokenExpiry] = DateTimeOffset.FromUnixTimeSeconds(expiryUnixSeconds.Value);
            }
            catch (ArgumentOutOfRangeException)
            {
                // Leave unset if the exp claim contains an invalid value.
            }
        }
        else
        {
            var expClaim = jwtToken.Claims.FirstOrDefault(claim => string.Equals(claim.Type, JwtRegisteredClaimNames.Exp, StringComparison.OrdinalIgnoreCase))?.Value;
            if (expClaim != null && long.TryParse(expClaim, out var parsedExp))
            {
                context.Items[ApproovTokenContextKeys.TokenExpiry] = DateTimeOffset.FromUnixTimeSeconds(parsedExp);
            }
        }

        var installationPubKey = jwtToken.Claims.FirstOrDefault(claim =>
            string.Equals(claim.Type, "ipk", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(claim.Type, "installation_pubkey", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(claim.Type, "installation_public_key", StringComparison.OrdinalIgnoreCase))
            ?.Value;

        if (!string.IsNullOrWhiteSpace(installationPubKey))
        {
            context.Items[ApproovTokenContextKeys.InstallationPublicKey] = installationPubKey;
        }
    }
}
