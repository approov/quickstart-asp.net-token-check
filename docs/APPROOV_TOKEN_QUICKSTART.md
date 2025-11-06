# Approov Token Quickstart

This quickstart shows how to enforce Approov tokens in an existing ASP.NET 8 API. The code samples match the implementation in `servers/hello/src/approov-protected-server/token-check`, so you can copy/paste with confidence and review the complete project for context.

- [Why](#why)
- [Requirements](#requirements)
- [Approov setup](#approov-setup)
- [Server changes](#server-changes)
- [Testing](#testing)


## Why

Approov ensures that API requests originate from attested builds of your mobile apps. Tokens issued by the Approov cloud service are presented in the `Approov-Token` header by the mobile SDK and must be validated by your backend before the request is processed. See the [Approov Overview](../OVERVIEW.md) for background on the end-to-end flow.


## Requirements

- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- [Approov CLI](https://approov.io/docs/latest/approov-installation/#approov-tool)
- Access to an Approov account with permission to manage API domains and secrets


## Approov Setup

1. **Register your API domain**  
   Inform Approov which API hostname will be protected:
   ```bash
   approov api -add your.api.domain.com
   ```

   By default Approov uses a symmetric key (HS256) to sign tokens for the domain. You may switch to asymmetric signing (for example RS256) by adding a new keyset and associating it with the domain. Refer to [Managing Key Sets](https://approov.io/docs/latest/approov-usage-documentation/#managing-key-sets) for the complete workflow.

2. **Export the Approov secret**  
   Enable the admin role in your shell and retrieve the token verification secret:
   ```bash
   eval `approov role admin`          # Unix shells
   # or
   set APPROOV_ROLE=admin:<account>   # Windows PowerShell

   approov secret -get base64
   ```

3. **Provide the secret to your server**  
   Store the base64 value in an environment variable or configuration source. In this quickstart we expect it in `.env`:
   ```env
   APPROOV_BASE64_SECRET=approov_base64_secret_here
   ```


## Server Changes

1. **Add the required packages**  
   Ensure your project references the JWT libraries used for validation. The sample project uses:
   ```xml
   <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.19" />
   <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.1.2" />
   <PackageReference Include="DotNetEnv" Version="2.3.0" /> <!-- optional: used to load .env -->
   ```

2. **Create a settings class**  
   Configure dependency injection to supply the secret bytes at runtime:
   ```csharp
   namespace YourApp.Helpers;

   public class AppSettings
   {
       public byte[]? ApproovSecretBytes { get; set; }
   }
   ```

3. **Load the secret in `Program.cs`**  
   Convert the base64 string to bytes and register `AppSettings`:
   ```csharp
   DotNetEnv.Env.Load();

   var secretBase64 = DotNetEnv.Env.GetString("APPROOV_BASE64_SECRET")
       ?? throw new Exception("APPROOV_BASE64_SECRET is missing");
   var approovSecretBytes = Convert.FromBase64String(secretBase64);

   builder.Services.Configure<AppSettings>(settings =>
   {
       settings.ApproovSecretBytes = approovSecretBytes;
   });
   ```

4. **Add the middleware**  
   Copy the middleware below (the full reference implementation lives in `Middleware/ApproovTokenMiddleware.cs`):
   ```csharp
   namespace YourApp.Middleware;

   using System.IdentityModel.Tokens.Jwt;
   using Microsoft.Extensions.Options;
   using Microsoft.IdentityModel.Tokens;
   using YourApp.Helpers;

   public class ApproovTokenMiddleware
   {
       private readonly RequestDelegate _next;
       private readonly AppSettings _settings;
       private readonly ILogger<ApproovTokenMiddleware> _logger;

       public ApproovTokenMiddleware(
           RequestDelegate next,
           IOptions<AppSettings> settings,
           ILogger<ApproovTokenMiddleware> logger)
       {
           _next = next;
           _settings = settings.Value;
           _logger = logger;
       }

       public async Task Invoke(HttpContext context)
       {
           var token = context.Request.Headers["Approov-Token"].FirstOrDefault();
           if (string.IsNullOrWhiteSpace(token))
           {
               _logger.LogDebug("Approov-Token header is missing");
               context.Response.StatusCode = StatusCodes.Status401Unauthorized;
               return;
           }

           if (!ValidateToken(context, token))
           {
               context.Response.StatusCode = StatusCodes.Status401Unauthorized;
               return;
           }

           await _next(context);
       }

       private bool ValidateToken(HttpContext context, string token)
       {
           try
           {
               var handler = new JwtSecurityTokenHandler();
               handler.ValidateToken(token, new TokenValidationParameters
               {
                   ValidateIssuerSigningKey = true,
                   IssuerSigningKey = new SymmetricSecurityKey(_settings.ApproovSecretBytes),
                   ValidateIssuer = false,
                   ValidateAudience = false,
                   ClockSkew = TimeSpan.Zero
               }, out var validatedToken);

               if (validatedToken is JwtSecurityToken jwtToken)
               {
                   context.Items["ApproovToken"] = jwtToken;
                   context.Items["ApproovTokenExpiry"] = jwtToken.ValidTo;
               }

               return true;
           }
           catch (SecurityTokenException ex)
           {
               _logger.LogDebug("Approov token rejected: {Message}", ex.Message);
               return false;
           }
       }
   }
   ```

5. **Register the middleware early in the pipeline**  
   In `Program.cs` insert the middleware before your endpoints:
   ```csharp
   var app = builder.Build();

   app.UseMiddleware<YourApp.Middleware.ApproovTokenMiddleware>();
   app.MapControllers();
   app.Run();
   ```

The middleware rejects requests lacking a valid token with HTTP 401. On success it caches the parsed JWT and expiry in `HttpContext.Items` so downstream components can access the claims if required.


## Testing

Use the Approov CLI to generate example tokens for your API domain:

```bash
# Valid token
approov token -genExample your.api.domain.com

# Invalid example
approov token -type invalid -genExample your.api.domain.com
```

Then invoke your endpoint with `curl`:

```bash
curl -i https://your.api.domain.com/hello \
  -H "Approov-Token: <PASTE_VALID_TOKEN>"
```

Expect a 200 response with the valid token and a 401 with the invalid token. See [TESTING.md](../TESTING.md) for additional options, including the dummy secret used by the repository’s integration scripts.
