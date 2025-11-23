# Approov Token Binding Quickstart

This guide builds on the [Approov token quickstart](APPROOV_TOKEN_QUICKSTART.md) to enforce token binding. Binding ties the `Approov-Token` to one or more request headers (for example the `Authorization` header) so an attacker cannot replay a token with a different credential.

- [Overview](#overview)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Middleware](#middleware)
- [Testing](#testing)


## Overview

The Approov mobile SDK hashes selected header values and places the result in the `pay` claim inside the Approov token. The backend recomputes the hash using the request headers and compares it against the claim. If any header is missing or the hashes differ, the request is rejected.

The sample implementation is available in `Middleware/ApproovTokenBindingMiddleware.cs`.


## Requirements

- Complete the [token validation quickstart](APPROOV_TOKEN_QUICKSTART.md). Token binding builds on the middleware and configuration shown there.
- Approov CLI 3.2 or later (required to generate example tokens with binding claims).


## Configuration

1. **Extend the settings class**  
   Add a header list to `AppSettings` so the binding middleware knows which headers to hash:
   ```csharp
   public class AppSettings
   {
       public byte[]? ApproovSecretBytes { get; set; }
       public IList<string> TokenBindingHeaders { get; set; } = new List<string>();
   }
   ```

2. **Parse the binding headers in `Program.cs`**  
   Accept a comma-separated list via the environment:
   ```csharp
   var bindingHeaderRaw = DotNetEnv.Env.GetString("APPROOV_TOKEN_BINDING_HEADER");
   var bindingHeaders = (bindingHeaderRaw ?? string.Empty)
       .Split(',', StringSplitOptions.RemoveEmptyEntries)
       .Select(value => value.Trim())
       .Where(value => value.Length > 0)
       .ToList();

   builder.Services.Configure<AppSettings>(settings =>
   {
       settings.ApproovSecretBytes = approovSecretBytes;
       settings.TokenBindingHeaders = bindingHeaders;
   });
   ```

   In `.env` supply the headers that must be present on each request. When multiple headers are listed their trimmed values are concatenated before hashing:
   ```env
   APPROOV_TOKEN_BINDING_HEADER=Authorization, X-Device-Id
   ```
    It's crucial that client mobile app mirrors the server configuration exactly. In case you are using multiple headers as binding tokens, please note that order of the headers matters.

3. **Share context keys**  
   The token middleware stores the `pay` claim in `HttpContext.Items`. Keep the keys in one place:
   ```csharp
   namespace YourApp.Helpers;

   public static class ApproovTokenContextKeys
   {
       public const string TokenBinding = "ApproovTokenBinding";
       public const string TokenBindingVerified = "ApproovTokenBindingVerified";
   }
   ```


## Middleware

Insert the binding middleware immediately after the token middleware. It recomputes the SHA-256 hash of the configured headers and compares it against the `pay` claim.

```csharp
namespace YourApp.Middleware;

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using YourApp.Helpers;

public class ApproovTokenBindingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AppSettings _settings;
    private readonly ILogger<ApproovTokenBindingMiddleware> _logger;

    public ApproovTokenBindingMiddleware(
        RequestDelegate next,
        IOptions<AppSettings> settings,
        ILogger<ApproovTokenBindingMiddleware> logger)
    {
        _next = next;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var payClaim = context.Items.TryGetValue(ApproovTokenContextKeys.TokenBinding, out var value)
            ? value as string
            : null;

        if (string.IsNullOrWhiteSpace(payClaim))
        {
            _logger.LogDebug("Token binding skipped: pay claim missing");
            await _next(context);
            return;
        }

        if (_settings.TokenBindingHeaders is null || _settings.TokenBindingHeaders.Count == 0)
        {
            _logger.LogDebug("Token binding skipped: no headers configured");
            await _next(context);
            return;
        }

        var builder = new StringBuilder();
        var missingHeaders = new List<string>();

        foreach (var header in _settings.TokenBindingHeaders)
        {
            var valueToHash = context.Request.Headers[header].ToString();
            if (string.IsNullOrWhiteSpace(valueToHash))
            {
                missingHeaders.Add(header);
                continue;
            }

            builder.Append(valueToHash.Trim());
        }

        if (missingHeaders.Count > 0)
        {
            _logger.LogInformation("Token binding header(s) missing: {Headers}", string.Join(", ", missingHeaders));
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var concatenated = builder.ToString();
        var computedHash = Sha256Base64(concatenated);

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(payClaim),
                Encoding.UTF8.GetBytes(computedHash)))
        {
            _logger.LogInformation("Token binding verification failed");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Items[ApproovTokenContextKeys.TokenBindingVerified] = true;
        await _next(context);
    }

    private static string Sha256Base64(string input)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }
}
```

Register the middleware in `Program.cs` after the token middleware:

```csharp
app.UseMiddleware<YourApp.Middleware.ApproovTokenMiddleware>();
app.UseMiddleware<YourApp.Middleware.ApproovTokenBindingMiddleware>();
```


## Testing

1. Generate a bound token example. The string supplied to `-setDataHashInToken` must exactly match the header value(s) that the client will send. For a bearer token:
   ```bash
   approov token \
     -setDataHashInToken 'Bearer authorizationtoken' \
     -genExample your.api.domain.com
   ```

2. Call your endpoint with both the `Approov-Token` and `Authorization` headers:
   ```bash
   curl -i https://your.api.domain.com/hello \
     -H "Authorization: Bearer authorizationtoken" \
     -H "Approov-Token: <PASTE_BOUND_TOKEN>"
   ```

   Expect HTTP 200 for matching values, HTTP 400 if the binding header is missing, and HTTP 401 if the header value differs.

Refer to [TESTING.md](../TESTING.md) for additional tooling options and ready-made scripts that exercise the binding logic.
