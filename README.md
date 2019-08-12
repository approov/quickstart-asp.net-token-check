# APPROOV ASP.Net TOKEN CHECK

> **IMPORTANT:** This repository relates to Approov 1 and has not been updated to reflect the [new features](https://approov.io/docs/v2.0/changelog/) and [usage](https://approov.io/docs/v2.0/approov-usage-documentation/) of [Approov 2](https://approov.io/docs/v2.0/approov-installation/), the latest version of Approov. We will be updating the repository soon. Meanwhile, please refer to the [guide](https://approov.io/docs/v2.0/approov-usage-documentation/#migrating-from-approov-1) for migrating from Approov 1 to Approov 2.

This repository demonstrates a basic integration of an Approov token check with ASP.Net Core 2.0. Thanks to Jon Hilton for [this great blog](https://jonhilton.net/security/apis/secure-your-asp.net-core-2.0-api-part-2---jwt-bearer-authentication/) which formed the basis for this example.


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



## SYSTEM CLOCK

In order to correctly check for the expiration times of the Approov tokens, it is
very important that the server is synchronizing automatically the system clock
over the network with an authoritative time source.


## SETUP

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


## PLAYING WITH THE API

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


## HOW TO USE IN YOUR CODE

This is a simplified overview of how you can integrate the Approov Token check as
an authorization middle-ware check in your dotnet API. Please feel free to
[contact us](https://info.approov.io/contact-us) for further assistance in your
integration with Approov.

### Require Authentication

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

## PRODUCTION

In order to protect the communication between your mobile app and the API server
it is important to only communicate over a secure communication channel, using HTTPS.

Please bear in mind that https on its own is not enough, certificate pinning
must be also used to pin the connection between the mobile app and the API
server in order to prevent [Man in the Middle Attacks](https://approov.io/docs/mitm-detection.html).

We do not use https and certificate pinning in this Approov integration example
because we want to be able to run this demo in localhost.

However in production we strongly recommend implementing
[static pinning](https://approov.io/docs/mitm-detection.html#id1)
or [dynamic pinning](https://approov.io/docs/mitm-detection.html#dynamic-pinning).


### Configure the Approov Token Check

Approov tokens are [JWT](https://jwt.io/) tokens and they are configured and
checked in [Startup.cs](./Startup.cs).

The Approov Token Secret bytes are stored as a base64 encoded string. To use the
secret we must first decode it back into bytes.

In a production application we need to update [appsettings.json](./appsettings.json)
with the Approov Base64 encoded secret that you obtained from the Approov portal.

[appsettings.json](./appsettings.json):

```json
{
  "ApproovTokenSecret": "The Approov Base64 encoded secret"
}

```

Bear in mind that in a production project the [appsettings.json](./appsettings.json)
file must be in `.gitignore`, because you do not want to commit your secret into
your repository, and you may want to read more about that in [this article](https://blog.approov.io/is-your-mobile-app-leaking-secrets).

https://github.com/approov/ASP.Net-Token-Check/blob/dev/postman/approov-dotnet-example.postman_collection.json
