namespace Hello.Middleware;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Hello.Helpers;


public class ApproovTokenBindingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AppSettings _appSettings;
    private readonly ILogger<ApproovTokenBindingMiddleware> _logger;

    public ApproovTokenBindingMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings, ILogger<ApproovTokenBindingMiddleware> logger)
    {
        _next = next;
        _appSettings = appSettings.Value;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var tokenBinding = context.Items["ApproovTokenBinding"]?.ToString();

        if (tokenBinding == null) {
            _logger.LogInformation("The pay claim is missing in the Approov token.");
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var authorizationToken = context.Request.Headers["Authorization"].FirstOrDefault();

        if (authorizationToken == null) {
            _logger.LogInformation("Missing the Authorization token header to use for the Approov token binding.");
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        if (verifyApproovTokenBinding(authorizationToken, tokenBinding)) {
            await _next(context);
            return;
        }

        _logger.LogInformation("Invalid Approov token binding.");
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    private bool verifyApproovTokenBinding(string authorizationToken, string tokenBinding)
    {
        var hash = sha256Base64Endoded(authorizationToken);

        StringComparer comparer = StringComparer.OrdinalIgnoreCase;

        return comparer.Compare(tokenBinding, hash) == 0;
    }

    public static string sha256Base64Endoded(string input)
    {
        try
        {
            SHA256 sha256 = SHA256.Create();

            byte[] inputBytes = new UTF8Encoding().GetBytes(input);
            byte[] hashBytes = sha256.ComputeHash(inputBytes);

            sha256.Dispose();

            return Convert.ToBase64String(hashBytes);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message, ex);
        }
    }
}
