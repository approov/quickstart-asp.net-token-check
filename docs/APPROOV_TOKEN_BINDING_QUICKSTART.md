# Approov Token Binding Quickstart

This quickstart is for developers familiar with ASP.Net who are looking for a quick intro into how they can add [Approov](https://approov.io) into an existing project. Therefore this will guide you through the necessary steps for adding Approov with token binding to an existing ASP.Net API server.

## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Approov Setup](#approov-setup)
* [Approov Token Check](#approov-token-check)
* [Try the Approov Integration Example](#try-the-approov-integration-example)


## Why?

To lock down your API server to your mobile app. Please read the brief summary in the [Approov Overview](/OVERVIEW.md#why) at the root of this repo or visit our [website](https://approov.io/product) for more details.

[TOC](#toc---table-of-contents)


## How it works?

For more background, see the [Approov Overview](/OVERVIEW.md#how-it-works) at the root of this repo.

Take a look at the `verifyApproovToken()` function at the [ApproovTokenMiddleware](/servers/hello/src/approov-protected-server/token-bindingcheck/Middleware/ApproovTokenMiddleware.cs) class to see the simple code for the Approov Token check. To also see the code for the Approov token binding check you just need to look for the `verifyApproovTokenBinding()` function at the [ApproovTokenMiddleware](/servers/hello/src/approov-protected-server/token-bindingcheck/Middleware/ApproovTokenBindingMiddleware.cs) class.

[TOC](#toc---table-of-contents)


## Requirements

To complete this quickstart you will need both the .Net SDK and the Approov CLI tool installed.

* [.NET 6 SDK](https://docs.microsoft.com/en-us/dotnet/core/install/)
* Approov CLI - Follow our [installation instructions](https://approov.io/docs/latest/approov-installation/#approov-tool) and read more about each command and its options in the [documentation reference](https://approov.io/docs/latest/approov-cli-tool-reference/)

[TOC](#toc---table-of-contents)


## Approov Setup

To use Approov with the ASP.Net API server we need a small amount of configuration. First, Approov needs to know the API domain that will be protected. Second, the ASP.Net API server needs the Approov Base64 encoded secret that will be used to verify the tokens generated by the Approov cloud service.

### Configure API Domain

Approov needs to know the domain name of the API for which it will issue tokens.

Add it with:

```bash
approov api -add your.api.domain.com
```

> **NOTE:** By default a symmetric key (HS256) is used to sign the Approov token on a valid attestation of the mobile app for each API domain it's added with the Approov CLI, so that all APIs will share the same secret and the backend needs to take care to keep this secret secure.
>
> A more secure alternative is to use asymmetric keys (RS256 or others) that allows for a different keyset to be used on each API domain and for the Approov token to be verified with a public key that can only verify, but not sign, Approov tokens.
>
> To implement the asymmetric key you need to change from using the symmetric HS256 algorithm to an asymmetric algorithm, for example RS256, that requires you to first [add a new key](https://approov.io/docs/latest/approov-usage-documentation/#adding-a-new-key), and then specify it when [adding each API domain](https://approov.io/docs/latest/approov-usage-documentation/#keyset-key-api-addition). Please visit [Managing Key Sets](https://approov.io/docs/latest/approov-usage-documentation/#managing-key-sets) on the Approov documentation for more details.

Adding the API domain also configures the [dynamic certificate pinning](https://approov.io/docs/latest/approov-usage-documentation/#dynamic-pinning) setup, out of the box.

> **NOTE:** By default the pin is extracted from the public key of the leaf certificate served by the domain, as visible to the box issuing the Approov CLI command and the Approov servers.

### Approov Secret

Approov tokens are signed with a symmetric secret. To verify tokens, we need to grab the secret using the [Approov secret command](https://approov.io/docs/latest/approov-cli-tool-reference/#secret-command) and plug it into the ASP.Net API server environment to check the signatures of the [Approov Tokens](https://www.approov.io/docs/latest/approov-usage-documentation/#approov-tokens) that it processes.

First, enable your Approov `admin` role with:

```bash
eval `approov role admin`
````

For the Windows powershell:

```bash
set APPROOV_ROLE=admin:___YOUR_APPROOV_ACCOUNT_NAME_HERE___
```

Next, retrieve the Approov secret with:

```bash
approov secret -get base64
```

#### Set the Approov Secret

Open the `.env` file and add the Approov secret to the var:

```bash
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

[TOC](#toc---table-of-contents)


## Approov Token Check

First, add to your `appname.csproj` file the dependencies:

```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.0" />
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="6.15.0" />

<!-- Optional in the case you prefer to load the secret with another approach -->
<PackageReference Include="DotNetEnv" Version="2.3.0" />
```

Next, let's add the class to load the app settings:

```c#
namespace AppName.Helpers;

public class AppSettings
{
    public byte[] ?ApproovSecretBytes { get; set; }
}
```

Now, add the `ApproovTokenMiddleware` class to your project:

```c#
namespace AppName.Middleware;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using AppName.Helpers;
using System.Security.Claims;

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
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
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

            var jwtToken = (JwtSecurityToken)validatedToken;
            var claims = jwtToken.Claims;

            var payClaim = claims.FirstOrDefault(x => x.Type == "pay")?.Value;

            context.Items["ApproovTokenBinding"] = payClaim;

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
```

Next, add the `ApproovTokenBindingMiddleware` class:

```c#
namespace AppName.Middleware;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using AppName.Helpers;


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
```

Now, in `Program.cs` load the secrets from the `.env` file and inject it into `AppSettiongs`:

```c#
using AppName.Helpers;

DotNetEnv.Env.Load();

var approovBase64Secret = DotNetEnv.Env.GetString("APPROOV_BASE64_SECRET");

if(approovBase64Secret == null) {
    throw new Exception("Missing the env var APPROOV_BASE64_SECRET or its empty.");
}

var approovSecretBytes = System.Convert.FromBase64String(approovBase64Secret);

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<AppSettings>(appSettings => {
    appSettings.ApproovSecretBytes = approovSecretBytes;
});

// ... omitted boilerplate and/or your code

var app = builder.Build();

// Needs to be the first. No need to process other stuff in the request if the
// request isn't deemed as trustworthy by having a valid Approov token that
// hasn't expired yet.
app.UseMiddleware<AppName.Middleware.ApproovTokenMiddleware>();
app.UseMiddleware<AppName.Middleware.ApproovTokenBindingMiddleware>();

// ... omitted boilerplate and/or your code
```

> **NOTE:** When the Approov token validation fails we return a `401` with an empty body, because we don't want to give clues to an attacker about the reason the request failed, and you can go even further by returning a `400`.

A full working example for a simple Hello World server can be found at [servers/hello/src/approov-protected-server/token-check](/servers/hello/src/approov-protected-server/token-check).

[TOC](#toc---table-of-contents)


## Test your Approov Integration

The following examples below use cURL, but you can also use the [Postman Collection](/README.md#testing-with-postman) to make the API requests. Just remember that you need to adjust the urls and tokens defined in the collection to match your deployment. Alternatively, the above README also contains instructions for using the preset _dummy_ secret to test your Approov integration.

#### With Valid Approov Tokens

Generate a valid token example from the Approov Cloud service:

```bash
approov token -setDataHashInToken 'Bearer authorizationtoken' -genExample your.api.domain.com
```

Then make the request with the generated token:

```bash
curl -i --request GET 'https://your.api.domain.com/v1/shapes' \
  --header 'Authorization: Bearer authorizationtoken' \
  --header 'Approov-Token: APPROOV_TOKEN_EXAMPLE_HERE'
```

The request should be accepted. For example:

```text
HTTP/2 200

...

{"message": "Hello, World!"}
```

#### With Invalid Approov Tokens

##### No Authorization Token

Let's just remove the Authorization header from the request:

```bash
curl -i --request GET 'https://your.api.domain.com/v1/shapes' \
  --header 'Approov-Token: APPROOV_TOKEN_EXAMPLE_HERE'
```

The above request should fail with an Unauthorized error. For example:

```text
HTTP/2 401

...

{}
```

##### Same Approov Token with a Different Authorization Token

Make the request with the same generated token, but with another random authorization token:

```bash
curl -i --request GET 'https://your.api.domain.com/v1/shapes' \
  --header 'Authorization: Bearer anotherauthorizationtoken' \
  --header 'Approov-Token: APPROOV_TOKEN_EXAMPLE_HERE'
```

The above request should also fail with an Unauthorized error. For example:

```text
HTTP/2 401

...

{}
```

[TOC](#toc---table-of-contents)


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-asp.net-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


[TOC](#toc---table-of-contents)


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.io/contact)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)

[TOC](#toc---table-of-contents)
