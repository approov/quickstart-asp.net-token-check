# APPROOV ASP.Net TOKEN CHECK

This repository demonstrates a basic integration of an Approov token check with ASP.Net Core 2.0. Thanks to Jon Hilton for [this great blog](https://jonhilton.net/security/apis/secure-your-asp.net-core-2.0-api-part-2---jwt-bearer-authentication/) which formed the basis for this example.

## TOC

* [Approov Validation Process](./README.md#approov-validation-process)
* [System Clock](./README.md#system-clock)
* [Localhost Setup](./README.md#localhost-setup)
* [Play with the API server on Localhost](./README.md#play-with-the-api-server-on-localhost)
* [How to Add the Approov Token Check](./README.md#how-to-add-the-approov-token-check)
* [Production Deployment](./README.md#production-deployment)


## APPROOV VALIDATION PROCESS

Before we dive into the code we need to understand the Approov validation
process on the back-end side.

### The Approov Token

API calls protected by Approov will typically include a header holding an Approov
JWT token. This token must be checked to ensure it has not expired and that it is
properly signed with the secret shared between the back-end and the Approov cloud
service.

> **NOTE**
>
> Just to be sure that we are on the same page, a JWT token has 3 parts, that
> are separated by dots and represented in the format of `header.payload.signature`,
> were each part is a base64-encoded string. Read more about JWT tokens [here](https://jwt.io/introduction/).

[Back to TOC](./README.md#toc)


## SYSTEM CLOCK

In order to correctly check for the expiration times of the Approov tokens, it is
very important that the server is synchronizing automatically the system clock
over the network with an authoritative time source.

[Back to TOC](./README.md#toc)


## LOCALHOST SETUP

### Git Clone

```
git clone https://github.com/approov/ASP.Net-Token-Check.git
```

### Editor

* Open this project in Visual Studio or Monodevelop and build it.
* Run the project in order to start the web server on `http://localhost:5000`.

### Postman

Add [this collection](https://raw.githubusercontent.com/approov/ASP.Net-Token-Check/dev/postman/approov-dotnet-example.postman_collection.json) into Postman,
that contains some examples for valid and invalid requests.

[Back to TOC](./README.md#toc)


## PLAY WITH THE API SERVER ON LOCALHOST

You can easily inspect the codes used in the Postman request by copy paste them
into [this online decoder](https://jwt.io) but always strip the word `Bearer` from
them.

To create new tokens for further playing with this API you can use [this online tool](http://jwtbuilder.jamiekurtz.com/) to build them.


### Valid Request

**With a correctly signed Approov Token that has not expired yet:**

![Valid Approov Token](./docs/img/valid-approov-token.png)

**Request Overview:**

With a valid and not expired Approov token we get a `200` response.

**The token decoded:**

![Valid Approov Token Decoded](./docs/img/valid-approov-token-decoded.png)


### Invalid Requests

**With a correctly signed Approov token, but already expired:**

![Expired Approov Token](./docs/img/expired-approov-token.png)

**Request Overview:**

As we can see we got a `401` response because the token is expired.

**The token decoded:**

![Expired Approov Token Decoded](./docs/img/expired-approov-token-decoded.png)


**With a malformed JWT token:**

![Malformed Approov Token](./docs/img/malformed-approov-token.png)

**Request Overview:**

Again we get a `401` response. but the cause now is that we have a malformed JWT token.

**The token decoded:**

![Malformed Approov Token Decoded](./docs/img/malformed-approov-token-decoded.png)


**Without a any token at all:**

![Missing Approov Token](./docs/img/missing-approov-token.png)

**Request Overview:**

As expected without providing the Approov token we also get a denied request with the `401` response.

**The token decoded:**

Well the token is missing in this request example, therefore nothing to show you here...

[Back to TOC](./README.md#toc)


## HOW TO ADD THE APPROOV TOKEN CHECK

This is a simplified overview of how you can integrate the Approov Token check as
an authorization middle-ware check in your dotnet API. Please feel free to
[contact us](https://info.approov.io/contact-us) for further assistance in your
integration with Approov.

### Setup Authentication

Approov tokens are [JWT](https://jwt.io/) tokens and they are configured in [Startup.cs](./Startup.cs):

```c#
// file: Startup.cs

public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateLifetime = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(0),
                IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(_configuration["ApproovTokenSecret"]))
            };
        });

    services.AddMvc();
}
```

The above code is configuring the Authentication service to check the Approov Tokens
with the Approov base64 encoded secret provided in [appsettings.json](./appsettings.json).

To make the Approov Token check available we also need to configure the 
application to use the authentication service in [Startup.cs](./Startup.cs:

```c#
// file: Startup.cs

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    app.UseAuthentication();

    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }

    app.UseMvcWithDefaultRoute();
}
```

### Require Authentication by API Endpoint

We need to add the `[Authorize]` attribute to get our API endpoint to have the
check performed for the Approov Token.

[ApiController.cs](./Controllers/ApiController.cs) example:

```c#
// file: Controllers/ApiController.cs

[Authorize]
[Produces("application/json")]
[Route("api/test")]
public class ApiController : Controller
{
    // some code here...
}
```

[Back to TOC](./README.md#toc)


## PRODUCTION DEPLOYMENT

In order to protect the communication between your mobile app and the API server
it is important to only communicate over a secure communication channel, using HTTPS.

> **NOTE:** We do not use https and certificate pinning in this Approov integration example
because we want to be able to run this demo in localhost.

However in production your mobile app will have the connection pinned to the API 
server without the need to implement or manage it. For more details read the
[dynamic pinning](https://approov.io/docs/latest/approov-usage-documentation/#approov-dynamic-pinning) section in our docs.

### The Approov Secret

In production we don't use a custom dummy secret as we do in this demo, instead 
we need to use the same one used by the Approov Cloud service to sign the Approov 
Tokens issued to our mobile app.

We will use the [Approov CLI Tool](https://approov.io/docs/latest/approov-installation/#approov-tool) to download the [Approov secret](https://approov.io/docs/latest/approov-cli-tool-reference/#secret-command) to 
retrieve it:

```
approov secret -get base64
```

### Configure the Approov Token Check

Approov tokens are [JWT](https://jwt.io/) tokens and they are configured and
checked in [Startup.cs](./Startup.cs).

The Approov Token Secret bytes are stored as a base64 encoded string. To use the
secret we must first decode it back into bytes.

In a production application we need to update [appsettings.json](./appsettings.json)
with the Approov Base64 encoded secret that you obtained above with the Approov CLI tool:

[appsettings.json](./appsettings.json):

```json
{
  "ApproovTokenSecret": "The Approov Base64 encoded secret"
}

```

> **IMPORTANT:** 
> 
>Bear in mind that in a production project the [appsettings.json](./appsettings.json)
>file must be in `.gitignore`, because you do not want to commit your secret into
>your repository, and you may want to read more about that in [this article](https://blog.approov.io/is-your-mobile-app-leaking-secrets).


### The API Server Domain

The Approov Cloud service needs to know what is the API server domain in order 
to be able to issue valid tokens for your API on each mobile app attestation, 
and for the Approov Framework in your mobile app be able to perform the 
dynamic certificate pinning.

Add it with the Approov CLI tool:

```
approov api -add api.example.com
```

### Test the API Server with Approov Tokens signed by the Approov Cloud Service

#### Get a Valid Approov Token with:

```
approov token -genExample api.example.com
```

#### Test the API server

##### request:

```
curl -I -X GET \                                                           
  https://api.example.com/protected/endpoint \
  -H 'Authorization: Bearer VALID_APPROOV_TOKEN_HERE'
```

##### response:

```
HTTP/1.1 200 OK
Date: Thu, 04 Jun 2020 16:49:18 GMT
Content-Type: application/json; charset=utf-8
Server: Kestrel
Transfer-Encoding: chunked
```

#### Get an Invalid Approov Token with:

```
approov token -type invalid -genExample api.example.com
```

#### Test the API server

##### request:

```
curl -I -X GET \                                                           
  https://api.example.com/protected/endpoint \
  -H 'Authorization: Bearer INVALID_APPROOV_TOKEN_HERE'
```

##### response:

```
HTTP/1.1 401 Unauthorized
Date: Thu, 04 Jun 2020 17:23:35 GMT
Server: Kestrel
Content-Length: 0
WWW-Authenticate: Bearer error="invalid_token", error_description="The signature key was not found"
```

[Back to TOC](./README.md#toc)
