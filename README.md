# ASP.Net-Token-Check

This repository demonstrates a basic integration of an Approov token check with ASP.Net Core 2.0. Thanks to Jon Hilton for [this great blog](https://jonhilton.net/security/apis/secure-your-asp.net-core-2.0-api-part-2---jwt-bearer-authentication/) which formed the basis for this example.

## Steps
1. Require Authentication for our API controllers
2. Configure JWT Auth in startup.cs

### Require Authentication

We need to add the [Authorize] attribute to get our API to check for some authentication.

### Configure JWT Auth

Approov tokens are [JWTs](https://jwt.io/). To add JWT auth you need to configure it in startup.cs.

The Approov Token Secret bytes are stored as a base64 encoded string, to use the secret we must decode it back into bytes. If _configuration is missing you can include with the constructor.
