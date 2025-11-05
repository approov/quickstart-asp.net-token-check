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

        if (token == null) {
            _logger.LogInformation("Missing Approov-Token header.");
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

            return true;
        } catch (SecurityTokenException exception) {
            _logger.LogInformation(exception.Message);
            return false;
        } catch (Exception exception) {
            _logger.LogInformation(exception.Message);
            return false;
        }
    }
}
