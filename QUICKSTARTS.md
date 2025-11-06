# Approov Integration Quickstarts

[Approov](https://approov.io) ensures that API traffic reaching your backend originates from trusted versions of your mobile apps. This repository collects the server-side quickstarts for ASP.NET 8 and reuses a single reference implementation at `servers/hello/src/approov-protected-server/token-check`.


## The Quickstarts

Pick the guide that matches the level of protection you want to implement:

- [Approov token check](docs/APPROOV_TOKEN_QUICKSTART.md) - validate the JWT presented in the `Approov-Token` header.
- [Approov token binding](docs/APPROOV_TOKEN_BINDING_QUICKSTART.md) - bind tokens to headers such as `Authorization` to prevent replay.
- [Approov message signing](docs/APPROOV_MESSAGE_SIGNING_QUICKSTART.md) - verify HTTP message signatures using the installation public key (IPK).

Each build upon the previous one, so start with the token quickstart before layering binding or message signing.


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-asp.net-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

- [Approov Free Trial](https://approov.io/signup) (no credit card needed)
- [Approov Get Started](https://approov.io/product/demo)
- [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
- [Approov Docs](https://approov.io/docs)
- [Approov Blog](https://approov.io/blog/)
- [Approov Resources](https://approov.io/resource/)
- [Approov Customer Stories](https://approov.io/customer)
- [Approov Support](https://approov.io/contact)
- [About Us](https://approov.io/company)
- [Contact Us](https://approov.io/contact)
