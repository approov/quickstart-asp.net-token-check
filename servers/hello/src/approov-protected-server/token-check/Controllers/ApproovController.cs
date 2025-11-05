using Hello.Helpers;
using Microsoft.AspNetCore.Mvc;
using StructuredFieldValues;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

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
    public IActionResult Hello() => Content("hello, world", "text/plain");

    [HttpGet("/token")]
    [HttpPost("/token")]
    public IActionResult Token() => Content("Good Token", "text/plain");

    [HttpGet("/token_binding")]
    public IActionResult TokenBinding()
    {
        var payClaim = HttpContext.Items.TryGetValue(ApproovTokenContextKeys.TokenBinding, out var value)
            ? value as string
            : null;

        if (string.IsNullOrWhiteSpace(payClaim))
        {
            return Unauthorized();
        }

        var combinedBinding = BuildBindingValue(new[] { "Authorization", "X-Device-Id" });
        if (!combinedBinding.Success)
        {
            return Unauthorized();
        }

        var computedHash = ComputeSha256Base64(combinedBinding.Value);
        if (!HashesMatch(payClaim, computedHash))
        {
            return Unauthorized();
        }

        return Content("Good Token Binding", "text/plain");
    }

    [HttpGet("/ipk_test")]
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
            _logger.LogDebug("Generated EC key pair for testing. Private DER (b64)={Private} Public DER (b64)={Public}", privateKeyBase64, publicKeyBase64);

            return Content("No IPK header, generated keys logged", "text/plain");
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

    [HttpGet("/ipk_message_sign_test")]
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
    public IActionResult StructuredFieldTest()
    {
        var sfvType = Request.Headers["sfvt"].FirstOrDefault();
        var sfvHeader = CombineHeaderValues(Request.Headers["sfv"]);

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

    private IActionResult StructuredFieldFailure(string message)
    {
            _logger.LogDebug("Structured field roundtrip failure - {Message}", message);
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Content("Failed SFV roundtrip", "text/plain");
    }

    private static string CombineHeaderValues(IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return string.Empty;
        }

        if (values.Count == 1)
        {
            return values[0].Trim();
        }

        var builder = new StringBuilder();
        for (var i = 0; i < values.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            builder.Append(values[i].Trim());
        }

        return builder.ToString();
    }

    private (bool Success, string Value) BuildBindingValue(IEnumerable<string> headerNames)
    {
        var builder = new StringBuilder();
        foreach (var headerName in headerNames)
        {
            if (!Request.Headers.TryGetValue(headerName, out var values) || values.Count == 0)
            {
                return (false, string.Empty);
            }

            builder.Append(CombineHeaderValues(values));
        }

        return (true, builder.ToString());
    }

    private static string ComputeSha256Base64(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    private static bool HashesMatch(string expectedBase64, string actualBase64)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expectedBase64);
        var actualBytes = Encoding.UTF8.GetBytes(actualBase64);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}
