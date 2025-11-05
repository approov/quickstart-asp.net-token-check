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

The sample API exposes the following endpoints:

* `/hello` – plain text check that the service is alive.
* `/token` – validates the Approov token and, when the `ipk` claim is present, verifies the Approov installation message signature. Success returns `Good Token`; failures return a `401` with `Invalid Token`.
* `/ipk_test` – development helper. Without an `ipk` header it generates and logs a fresh P-256 key pair. With an `ipk` header it validates that the provided public key can be decoded.
* `/ipk_message_sign_test` – accepts a `private-key` (base64 DER) and a `msg` (base64 canonical message) header and returns an ECDSA P-256/SHA-256 raw signature. The scripts call this to create deterministic signatures.
* `/sfv_test` – parses and reserialises Structured Field Value headers. The OpenResty quickstart invokes this when running `request_tests_sfv.sh`.

Approov tokens are validated by the [ApproovTokenMiddleware](/servers/hello/src/approov-protected-server/token-check/Middleware/ApproovTokenMiddleware.cs). Token binding is enforced by the [ApproovTokenBindingMiddleware](/servers/hello/src/approov-protected-server/token-check/Middleware/ApproovTokenBindingMiddleware.cs), and message signing is handled by [MessageSigningMiddleware](/servers/hello/src/approov-protected-server/token-check/Middleware/MessageSigningMiddleware.cs) which shares the same canonical string construction, structured field parsing, and ECDSA verification logic.

You can tune which request headers participate in the binding by setting the `APPROOV_TOKEN_BINDING_HEADER` environment variable (for example `Authorization`). When the variable is unset or empty the server skips token binding checks.

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

Edit the `.env` file and add the [dummy secret](/TESTING.md#the-dummy-secret) to the `APPROOV_BASE64_SECRET` entry.

[TOC](#toc---table-of-contents)


## Try the Approov Integration Example

The quickest way to bring up the sample backends (unprotected and Approov-protected) is:

```bash
./scripts/run-local.sh all
```

The quickstart scripts expect the token-check server on `http://0.0.0.0:8111`. Once the service is running you can execute the shell helpers that ship with the OpenResty repo, for example:

```bash
./request_tests_approov_msg.sh 8111
./request_tests_sfv.sh 8111
```

The commands above exercise the `/token`, `/ipk_message_sign_test`, `/ipk_test` and `/sfv_test` endpoints. You can also interact with the endpoints manually:

```bash
# basic token check (replace with a valid Approov token)
curl -H "Approov-Token: <token>" http://localhost:8111/token

# generate a deterministic signature for a canonical message
curl -H "private-key: <base64 DER EC private key>" \
     -H "msg: <base64 canonical message>" \
     http://localhost:8111/ipk_message_sign_test

# verify Structured Field Value parsing
curl -H "sfv:?1;param=123" -H "sfvt:ITEM" http://localhost:8111/sfv_test
```

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
