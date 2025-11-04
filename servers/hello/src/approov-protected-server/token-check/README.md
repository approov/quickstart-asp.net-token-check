# Approov Token Integration Example

This Approov integration example is from where the code example for the [Approov token check quickstart](/docs/APPROOV_TOKEN_QUICKSTART.md) is extracted, and you can use it as a playground to better understand how simple and easy it is to implement [Approov](https://approov.io) in an ASP.Net API server.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try the Approov Integration Example](#try-the-approov-integration-example)


## Why?

To lock down your API server to your mobile app. Please read the brief summary in the [Approov Overview](/OVERVIEW.md#why) at the root of this repo or visit our [website](https://approov.io/product) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The API server is very simple and is defined at [src/approov-protected-server/token-check](src/approov-protected-server/token-check), and only responds to the endpoint `/` with this message:

```json
{"message": "Hello, World!"}
```

The `200` response is only sent when a valid Approov token is present on the header of the request, otherwise a `401` response is sent back.

Take a look at the `verifyApproovToken()` function at the [ApproovTokenMiddleware](/servers/hello/src/approov-protected-server/token-check/Middleware/ApproovTokenMiddleware.cs) class to see the simple code for the check.

For more background on Approov, see the [Approov Overview](/OVERVIEW.md#how-it-works) at the root of this repo.


[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have installed:

* [.NET 6 SDK](https://docs.microsoft.com/en-us/dotnet/core/install/)


[TOC](#toc---table-of-contents)


## Setup Env File

From `servers/hello/src/approov-protected-server/token-check` execute the following:

```bash
cp .env.example .env
```

Edit the `.env` file and add the [dummy secret](/TESTING.md#the-dummy-secret) to it in order to be able to test the Approov integration with the provided [Postman collection](https://github.com/approov/postman-collections/blob/master/quickstarts/hello-world/hello-world.postman_curl_requests_examples.md).

[TOC](#toc---table-of-contents)

## Message Signing Configuration

After the Approov token is validated the API can optionally verify an [Approov Message Signing](https://approov.io/docs/latest/approov-usage-documentation/#installation-message-signing) signature. Configure the behaviour in `appsettings.json`:

```jsonc
"Approov": {
  "MessageSigningMode": "Installation",   // None | Installation | Account
  "AccountMessageBaseSecret": "",         // Required when Account mode is selected
  "MessageSigningMaxAgeSeconds": 300,      // Reject signatures older than this age
  "RequireSignatureNonce": false,          // Enforce nonce presence if you track replay protection
  "SignedHeaders": [
    "Approov-Token",
    "Content-Type"
  ]
}
```

* **None** — message signing checks are skipped and only the token is validated.
* **Installation** — expects an `ipk` claim in the Approov token. The middleware extracts the Elliptic Curve public key and verifies an ECDSA P-256/SHA-256 signature over the canonical request representation (HTTP method, path + query, configured headers and body hash when present).
* **Account** — derives a per-token HMAC key using the configured base secret, the device ID (`did` claim) and token expiry. The base secret can be provided in base64 or base32 form exactly as exported by `approov secret -messageSigningKey`.

The canonical message always includes the `Approov-Token` header to prevent replay. If the client supplies a [`Signature-Input`](https://www.rfc-editor.org/rfc/rfc9421) header its declared components are honoured; otherwise the server falls back to the `SignedHeaders` list. Set `MessageSigningMaxAgeSeconds` and `RequireSignatureNonce` to mirror your policy for timestamp freshness and nonce enforcement.

[TOC](#toc---table-of-contents)


## Try the Approov Integration Example

First, you need to run this example from the `src/approov-protected-server/token-check` folder with:

```bash
dotnet run
```

Next, you can test that it works with:

```bash
curl -iX GET 'http://localhost:8002'
```

The response will be a `401` unauthorized request:

```text
HTTP/1.1 401 Unauthorized
Content-Length: 0
Date: Wed, 01 Jun 2022 11:42:42 GMT
Server: Kestrel
```

The reason you got a `401` is because the Approoov token isn't provided in the headers of the request.

Finally, you can test that the Approov integration example works as expected with this [Postman collection](/TESTING.md#testing-with-postman) or with some cURL requests [examples](/TESTING.md#testing-with-curl).

Run the automated unit tests with:

```bash
dotnet test ../../../../tests/Hello.Tests/Hello.Tests.csproj
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
