# Approov QuickStart - ASP.NET Token Check

[Approov](https://approov.io) validates that requests reaching your backend originate from trusted builds of your mobile apps. This quickstart demonstrates how to enforce Approov tokens in ASP.NET 8, optionally add [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding), and verify [HTTP message signatures](https://approov.io/docs/latest/approov-usage-documentation/#message-signing) produced by the Approov SDK.

The sample backend that accompanies this guide lives at `servers/hello/src/approov-protected-server/token-check`. It exposes minimal endpoints that illustrate each protection layer:
- `/token` returns `Good Token` after validating the Approov token.
- `/token_binding` echoes `Good Token Binding` when the configured headers hash to the `pay` claim.
- `/ipk_message_sign_test` and `/ipk_test` generate deterministic signatures and validate installation public keys for local testing.

An unprotected reference backend lives at `servers/hello/src/unprotected-server` so you can compare behaviour with and without Approov.


## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download) for building/running the samples.
- [Approov CLI](https://approov.io/docs/latest/approov-installation/#approov-tool) with an account that can manage API domains and secrets.
- An API domain registered with Approov: `approov api -add your.api.domain.com`.
- The account secret exported in base64 form. Enable the admin role (`eval \`approov role admin\`` on Unix shells or `set APPROOV_ROLE=admin:<approov-account>` in PowerShell) and run `approov secret -get base64`.

When using symmetric signing (HS256) you must keep the secret confidential. Approov also supports asymmetric keys; see [Managing Key Sets](https://approov.io/docs/latest/approov-usage-documentation/#managing-key-sets) for guidance.


## Getting Started

1. Copy the environment template and add your secret:
   ```bash
   cp servers/hello/src/approov-protected-server/token-check/.env.example \
      servers/hello/src/approov-protected-server/token-check/.env
   ```
   Edit `.env` and set `APPROOV_BASE64_SECRET` to the value returned by `approov secret -get base64`. The optional variables in that file enable token binding and message signature policy enforcement.

2. Run the sample APIs with the local .NET SDK:
   ```bash
   ./scripts/run-local.sh all
   ```
   The script launches the unprotected server on `8001` and the Approov-protected server on `8111`. Press `Ctrl+C` to stop both. Launch a single backend with `./scripts/run-local.sh token-check`.

3. Exercise the protections using the helper scripts:
   ```bash
   ./test-scripts/request_tests_approov_msg.sh 8111
   ./test-scripts/request_tests_sfv.sh 8111
   ```
   These scripts cover token validation, token binding, canonical message reconstruction, and signature verification.


## Implementing Approov in Your Project

Follow the detailed quickstarts to bring the same protections into your own API:

- [Token validation quickstart](docs/APPROOV_TOKEN_QUICKSTART.md) - integrate the middleware that enforces Approov tokens.
- [Token binding quickstart](docs/APPROOV_TOKEN_BINDING_QUICKSTART.md) - bind Approov tokens to request headers such as `Authorization`.
- [Message signing quickstart](docs/APPROOV_MESSAGE_SIGNING_QUICKSTART.md) - verify HTTP message signatures using the installation public key included in the Approov token.

Each guide includes package requirements, configuration snippets, and testing instructions that match the code in this repository.


## Testing and Examples

- [TESTING.md](TESTING.md) summarises manual and automated test options, including how to use the published dummy secret for local verification.
- [EXAMPLES.md](EXAMPLES.md) explains the sample server layout and optional Docker workflow.
- Run unit tests for the helper components with `dotnet test tests/Hello.Tests/Hello.Tests.csproj`.


## Additional Resources

- [Approov Overview](OVERVIEW.md)
- [Approov Quickstarts](QUICKSTARTS.md)
- [Approov Integration Examples](EXAMPLES.md)

Keep the backend clock synchronised with an authoritative time source (for example via NTP). Accurate clocks are essential when checking JWT expiry times and HTTP message signature lifetimes.


## Issues

Report problems or request enhancements via [GitHub issues](https://github.com/approov/quickstart-asp.net-token-check/issues). Include reproduction steps so we can assist quickly.


## Useful Links

- [Approov Free Trial](https://approov.io/signup) (no credit card needed)
- [Approov Product Tour](https://approov.io/product/demo)
- [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
- [Approov Docs](https://approov.io/docs)
- [Approov Blog](https://approov.io/blog/)
- [Approov Resources](https://approov.io/resource/)
- [Approov Customer Stories](https://approov.io/customer)
- [Approov Support](https://approov.io/contact)
