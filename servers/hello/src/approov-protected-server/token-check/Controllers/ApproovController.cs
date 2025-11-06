using Hello.Helpers;
using Microsoft.AspNetCore.Mvc;
using StructuredFieldValues;
using System.Security.Cryptography;

namespace Hello.Controllers;

[ApiController]
[Produces("text/plain")]
public class ApproovController : ControllerBase
{
    private readonly ILogger<ApproovController> _logger;

    public ApproovController(ILogger<ApproovController> logger)
    {
        _logger = logger;
    }

    [HttpGet("/hello")]
    // Serves a minimal plaintext response to act as an HTTP liveness probe.
    public IActionResult Hello() => Content("hello, world", "text/plain");

    [HttpGet("/token")]
    [HttpPost("/token")]
    // Confirms the caller presented a valid Approov token by echoing a success sentinel.
    public IActionResult Token() => Content("Good Token", "text/plain");

    [HttpGet("/token_binding")]
    // Verifies that the binding middleware accepted the pay claim before acknowledging the request.
    public IActionResult TokenBinding()
    {
        var payClaim = HttpContext.Items.TryGetValue(ApproovTokenContextKeys.TokenBinding, out var value)
            ? value as string
            : null;

        var bindingVerified = HttpContext.Items.TryGetValue(ApproovTokenContextKeys.TokenBindingVerified, out var verifiedValue)
            && verifiedValue is bool verifiedFlag
            && verifiedFlag;

        if (string.IsNullOrWhiteSpace(payClaim) || !bindingVerified)
        {
            return Unauthorized();
        }

        return Content("Good Token Binding", "text/plain");
    }

    [HttpGet("/ipk_test")]
    // Exercises import/export of an installation public key so clients can validate the DER encoding roundtrip.
    public IActionResult IpkTest()
    {
        var ipkHeader = Request.Headers["ipk"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(ipkHeader))
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKeyDer = key.ExportECPrivateKey();
            var publicKeyDer = key.ExportSubjectPublicKeyInfo();

            var privateKeyBase64 = Convert.ToBase64String(privateKeyDer);
            var publicKeyBase64 = Convert.ToBase64String(publicKeyDer);
            //_logger.LogDebug("Generated EC key pair for testing. Private DER (b64)={Private} Public DER (b64)={Public}", privateKeyBase64, publicKeyBase64);

            return Content("No IPK header provided", "text/plain");
        }

        try
        {
            var publicKey = Convert.FromBase64String(ipkHeader);
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return Content("IPK roundtrip OK", "text/plain");
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to import IPK header - {Message}", ex.Message);
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Content("Failed: failed to create public key", "text/plain");
        }
    }
    /* 
    Sending cryptographic values across an insecure network without encrypting them is extremely unsafe, 
    as anyone that intercepts these values can then decrypt your data. This endpoint exposes private keys to interception,
    logging by web servers and proxies, and storage in browser history.
    Make sure this endpoint is only used in a secure testing environment and never in production.
    */
    [HttpGet("/ipk_message_sign_test")]
    // Signs an arbitrary message with a caller-supplied EC private key to help generate deterministic test vectors.
    public IActionResult IpkMessageSignTest()
    {
        var privateKeyBase64 = Request.Headers["private-key"].FirstOrDefault();
        var messageBase64 = Request.Headers["msg"].FirstOrDefault();

        if (string.IsNullOrWhiteSpace(privateKeyBase64) || string.IsNullOrWhiteSpace(messageBase64))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Content("Missing private-key or msg header", "text/plain");
        }

        try
        {
            var privateKey = Convert.FromBase64String(privateKeyBase64);
            var messageBytes = Convert.FromBase64String(messageBase64);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey(privateKey, out _);
            var signature = ecdsa.SignData(messageBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return Content(Convert.ToBase64String(signature), "text/plain");
        }
        catch (FormatException ex)
        {
            _logger.LogWarning("Invalid input for signing - {Message}", ex.Message);
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Content("Failed to generate signature", "text/plain");
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Cryptographic failure during signing");
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Content("Failed to generate signature", "text/plain");
        }
    }

    [HttpGet("/sfv_test")]
    // Validates HTTP Structured Field parsing and serialization against the caller-provided sample.
    public IActionResult StructuredFieldTest()
    {
        var sfvType = Request.Headers["sfvt"].FirstOrDefault();
        var sfvHeader = StructuredFieldFormatter.CombineHeaderValues(Request.Headers["sfv"]);

        if (string.IsNullOrWhiteSpace(sfvType) || string.IsNullOrWhiteSpace(sfvHeader))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Content("Missing sfv or sfvt header", "text/plain");
        }

        sfvType = sfvType.Trim().ToUpperInvariant();
        string serialized;
        ParseError? error;

        switch (sfvType)
        {
            case "ITEM":
                error = SfvParser.ParseItem(sfvHeader, out var item);
                if (error.HasValue)
                {
            return StructuredFieldFailure(error.Value.Message);
                }
                serialized = StructuredFieldFormatter.SerializeItem(item);
                break;
            case "LIST":
                error = SfvParser.ParseList(sfvHeader, out var list);
                if (error.HasValue || list is null)
                {
                    return StructuredFieldFailure(error?.Message ?? "Invalid list header");
                }
                serialized = StructuredFieldFormatter.SerializeList(list);
                break;
            case "DICTIONARY":
                error = SfvParser.ParseDictionary(sfvHeader, out var dictionary);
                if (error.HasValue || dictionary is null)
                {
                    return StructuredFieldFailure(error?.Message ?? "Invalid dictionary header");
                }
                serialized = StructuredFieldFormatter.SerializeDictionary(dictionary);
                break;
            default:
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Content($"Unsupported sfvt value '{sfvType}'", "text/plain");
        }

        if (!string.Equals(serialized, sfvHeader, StringComparison.Ordinal))
        {
            return StructuredFieldFailure($"Serialized object does not match original: {serialized} != {sfvHeader}");
        }

        return Content("SFV roundtrip OK", "text/plain");
    }

    // Centralised failure path for structured field tests to keep logging and status consistent.
    private IActionResult StructuredFieldFailure(string message)
    {
        _logger.LogDebug("Structured field roundtrip failure - {Message}", message);
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Content("Failed SFV roundtrip", "text/plain");
    }


}
