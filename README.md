# Approov QuickStart - ASP.Net Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code for the ASP.Net framework, which performs the verification check before allowing valid traffic to be processed by the API endpoint.


## Approov Integration Quickstart

The quickstart was tested with the following Operating Systems:

* Ubuntu 20.04
* MacOS Big Sur
* Windows 10 WSL2 - Ubuntu 20.04

First, setup the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli).

Now, register the API domain for which Approov will issues tokens:

```bash
approov api -add api.example.com
```

> **NOTE:** By default a symmetric key (HS256) is used to sign the Approov token on a valid attestation of the mobile app for each API domain it's added with the Approov CLI, so that all APIs will share the same secret and the backend needs to take care to keep this secret secure.
>
> A more secure alternative is to use asymmetric keys (RS256 or others) that allows for a different keyset to be used on each API domain and for the Approov token to be verified with a public key that can only verify, but not sign, Approov tokens.
>
> To implement the asymmetric key you need to change from using the symmetric HS256 algorithm to an asymmetric algorithm, for example RS256, that requires you to first [add a new key](https://approov.io/docs/latest/approov-usage-documentation/#adding-a-new-key), and then specify it when [adding each API domain](https://approov.io/docs/latest/approov-usage-documentation/#keyset-key-api-addition). Please visit [Managing Key Sets](https://approov.io/docs/latest/approov-usage-documentation/#managing-key-sets) on the Approov documentation for more details.

Next, enable your Approov `admin` role with:

```bash
eval `approov role admin`
````

For the Windows powershell:

```bash
set APPROOV_ROLE=admin:___YOUR_APPROOV_ACCOUNT_NAME_HERE___
```

Now, get your Approov Secret with the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli):

```bash
approov secret -get base64
```

Next, add the [Approov secret](https://approov.io/docs/latest/approov-usage-documentation/#account-secret-key-export) to your project `.env` file:

```env
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

Now, add to your `appname.csproj` file the dependencies:

```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.0" />
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="6.15.0" />

<!-- Optional in the case you prefer to load the secret with another approach -->
<PackageReference Include="DotNetEnv" Version="2.3.0" />
```

Next, in `Program.cs` load the secrets from the `.env` file and inject it into `AppSettiongs`:

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

// ... omitted boilerplate and/or your code
```

Now, let's add the class to load the app settings:

```c#
namespace AppName.Helpers;

public class AppSettings
{
    public byte[] ?ApproovSecretBytes { get; set; }
}
```

Next, add the `ApproovTokenMiddleware` class to your project:

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

> **NOTE:** When the Approov token validation fails we return a `401` with an empty body, because we don't want to give clues to an attacker about the reason the request failed, and you can go even further by returning a `400`.

Not enough details in the bare bones quickstart? No worries, check the [detailed quickstarts](QUICKSTARTS.md) that contain a more comprehensive set of instructions, including how to test the Approov integration.


## More Information

* [Approov Overview](OVERVIEW.md)
* [Detailed Quickstarts](QUICKSTARTS.md)
* [Examples](EXAMPLES.md)
* [Testing](TESTING.md)

### System Clock

In order to correctly check for the expiration times of the Approov tokens is very important that the backend server is synchronizing automatically the system clock over the network with an authoritative time source. In Linux this is usually done with a NTP server.


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
