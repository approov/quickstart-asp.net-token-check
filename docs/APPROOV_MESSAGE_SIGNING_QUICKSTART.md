# Approov Message Signing Quickstart

Message signing protects against tampering and replay by requiring each request to carry an HTTP message signature generated on the device. This guide explains how the ASP.NET quickstart verifies those signatures using the *installation public key* (`ipk`) delivered inside the Approov token.

- [Overview](#overview)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Message signature verifier](#message-signature-verifier)
- [Middleware registration](#middleware-registration)
- [Testing](#testing)


## Overview

When the Approov SDK is configured for message signing it embeds an installation public key in the `ipk` claim of the Approov token. The SDK also signs a canonical representation of the HTTP request and sends the components via the `Signature` and `Signature-Input` headers, as defined by [IETF RFC 9421](https://www.rfc-editor.org/rfc/rfc9421).

On the server we:

1. Extract the `ipk` claim in the token middleware.
2. Rebuild the canonical message using the component identifiers from `Signature-Input`.
3. Verify that the supplied signature (`Signature` header) matches the canonical message using ECDSA P-256.
4. Optionally enforce signature freshness (`created`, `expires`) and verify the message body using the `Content-Digest` header.

The full implementation is in `Helpers/ApproovMessageSignatureVerifier.cs` and `Middleware/MessageSigningMiddleware.cs`.


## Requirements

- Complete the [token validation](APPROOV_TOKEN_QUICKSTART.md) quickstart so the `Approov-Token` header is already enforced.
- Approov mobile SDK configured to enable message signing and include the `ipk` claim.
- `StructuredFieldValues` NuGet package (the sample uses version `0.7.6`) to parse [IETF RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) structured fields as referenced RFC 9421. (Note that RFC 8941 was superseded by [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651) in September 2024 which added direct support for dates and added a new string type: *display strings* which supports a larger character set than the straight *string* type. These changes are strictly additive but have yet to be adopted by the NuGet package. Care should be taken to ensure both the client and the server components use a set of structured field value types that both support.)


## Configuration

The verifier exposes a few policy knobs that you can tune via configuration. In `.env` they are named:

```env
APPROOV_SIGNATURE_REQUIRE_CREATED=true
APPROOV_SIGNATURE_REQUIRE_EXPIRES=false
APPROOV_SIGNATURE_MAX_AGE_SECONDS=
APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS=
```

- `APPROOV_SIGNATURE_REQUIRE_CREATED` - require the `created` parameter. Defaults to `true`.
- `APPROOV_SIGNATURE_REQUIRE_EXPIRES` - require the `expires` parameter. Defaults to `false`.
- `APPROOV_SIGNATURE_MAX_AGE_SECONDS` - reject signatures older than the configured window.
- `APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS` - allow small clock differences between client and server.

Load the settings in `Program.cs` and bind them to `MessageSignatureValidationOptions`:

```csharp
builder.Services.Configure<MessageSignatureValidationOptions>(options =>
{
    options.RequireCreated = ReadBoolean(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_REQUIRE_CREATED"), true);
    options.RequireExpires = ReadBoolean(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_REQUIRE_EXPIRES"), false);
    options.MaximumSignatureAge = ReadTimeSpanFromSeconds(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_MAX_AGE_SECONDS"));
    options.AllowedClockSkew = ReadTimeSpanFromSeconds(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS")) ?? TimeSpan.Zero;
});

builder.Services.AddSingleton<ApproovMessageSignatureVerifier>();
```

The helper methods `ReadBoolean` and `ReadTimeSpanFromSeconds` are shown in the sample `Program.cs`.


## Message Signature Verifier

The verifier reconstructs the canonical message, validates the metadata, and checks the signature. A simplified version of the entry point is shown below:

- Combine split header values using `StructuredFieldFormatter.CombineHeaderValues`.
- Parse the `Signature` and `Signature-Input` dictionaries with `SfvParser.ParseDictionary`, ensuring both share the same label (`install`).
- Extract and validate the metadata parameters (algorithm, `created`, `expires`, `nonce`, `tag`) using `TryExtractSignatureMetadata`.
- Rebuild the canonical payload via `BuildCanonicalMessageAsync`, honouring pseudo headers such as `@method` and `@target-uri`.
- Optionally verify `Content-Digest` headers (currently supports `sha-256` and `sha-512`) so the request body cannot be manipulated.
- Validate the ECDSA P-256 signature with `TryVerifySignature`, using the decoded installation public key from the Approov token.

See `Helpers/ApproovMessageSignatureVerifier.cs` for the full implementation along with detailed error reporting and logging hooks.


## Middleware Registration

Add the message signing middleware after the token binding middleware (if used). It extracts the `ipk` claim and invokes the verifier whenever a signature is present:

```csharp
public class MessageSigningMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<MessageSigningMiddleware> _logger;
    private readonly ApproovMessageSignatureVerifier _verifier;

    public MessageSigningMiddleware(
        RequestDelegate next,
        ILogger<MessageSigningMiddleware> logger,
        ApproovMessageSignatureVerifier verifier)
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
            _logger.LogWarning("Message signing verification failed: {Reason}", result.Error);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Invalid Token");
            return;
        }

        await _next(context);
    }
}
```

Register it after the token (and token binding) middleware:

```csharp
app.UseMiddleware<YourApp.Middleware.ApproovTokenMiddleware>();
app.UseMiddleware<YourApp.Middleware.ApproovTokenBindingMiddleware>(); // optional
app.UseMiddleware<YourApp.Middleware.MessageSigningMiddleware>();
```


## Testing

1. Start the sample backend with the dummy secret from [TESTING.md](../TESTING.md#the-dummy-secret).
2. Use the helper script to generate deterministic signatures and send requests:
   ```bash
   ./test-scripts/request_tests_approov_msg.sh 8111
   ```
   The script exercises GET and POST requests, canonical component ordering, and `Content-Digest` enforcement.
3. For manual testing:
   - Obtain a valid Approov token containing an `ipk` claim.
   - Compute the canonical message base used by the SDK (method, target URI, headers).
   - Sign the canonical payload with the matching private key (ECDSA P-256, IEEE P1363 format).
   - Send the request with `Approov-Token`, `Signature`, and `Signature-Input` headers.

If the signature is missing, malformed, or fails verification the middleware returns HTTP 401. Missing headers listed in the signature components yield HTTP 400 with an explanatory log entry.
