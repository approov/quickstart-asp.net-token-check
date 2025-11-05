namespace Hello.Tests;

using System.Security.Cryptography;
using System.Text;
using Hello.Controllers;
using Hello.Helpers;
using Hello.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;

public class MessageSigningVerifierTests
{
    internal const string TestPrivateKey = "MHcCAQEEIHWZ2Ueq6odQNG+aaYmEbp7C6nujYNGr7nYKK2jqQ2asoAoGCCqGSM49AwEHoUQDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";
    private const string TestPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";
    private const string ApproovToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHByb292LmlvIiwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IkFwcHJvb3ZBY2NvdW50SUQuYXBwcm9vdi5pbyIsInN1YiI6ImFwcHJvb3Z8RXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwiaXAiOiIxLjIuMy40IiwiaXBrIjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSlNtNERNY2l2QXd2aE0rS05jZTJDL1gyNmNqM29HeVV3V1ZVUHVOdVpIdGQycXlWc00rMGc3cVg3M1FoME9mNmZuMTBBQXBMbmw4dlJRc3Z4OTRmWlE9PSIsImRpZCI6IkV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSJ9.hV6xTkGsp9uWwrD-yKkIGTBJawbofJEsuRLw9Qa5YXY";

    [Fact]
    public async Task VerifyAsync_WithValidSignature_ReturnsSuccess()
    {
        var (context, signatureInput) = BuildRequest();
        var canonicalMessage = BuildCanonicalMessage(signatureInput);
        var signature = SignCanonicalMessage(canonicalMessage);

        context.Request.Headers["Signature"] = $"install=:{signature}:";

        var verifier = new ApproovMessageSignatureVerifier(NullLogger<ApproovMessageSignatureVerifier>.Instance);
        var result = await verifier.VerifyAsync(context, TestPublicKey);

        Assert.True(result.Success);
    }

    [Fact]
    public async Task VerifyAsync_WithInvalidSignature_ReturnsFailure()
    {
        var (context, signatureInput) = BuildRequest();
        var canonicalMessage = BuildCanonicalMessage(signatureInput);
        var signature = SignCanonicalMessage(canonicalMessage);
        var tampered = signature[..^1] + (signature[^1] == 'A' ? "B" : "A");

        context.Request.Headers["Signature"] = $"install=:{tampered}:";

        var verifier = new ApproovMessageSignatureVerifier(NullLogger<ApproovMessageSignatureVerifier>.Instance);
        var result = await verifier.VerifyAsync(context, TestPublicKey);

        Assert.False(result.Success);
    }

    private static (DefaultHttpContext Context, string SignatureInput) BuildRequest()
    {
        const string signatureInput = "(\"@method\" \"approov-token\");alg=\"ecdsa-p256-sha256\";created=1744292750;expires=1999999999";

        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("0.0.0.0", 8002);
        context.Request.Path = "/token";
        context.Request.QueryString = new QueryString("?param1=value1&param2=value2");
        context.Request.Headers["Approov-Token"] = ApproovToken;
        context.Request.Headers["Signature-Input"] = $"install={signatureInput}";

        return (context, signatureInput);
    }

    private static string BuildCanonicalMessage(string signatureInput)
    {
        var builder = new StringBuilder();
        builder.AppendLine("\"@method\": GET");
        builder.AppendLine($"\"approov-token\": {ApproovToken}");
        builder.Append("\"@signature-params\": ");
        builder.Append(signatureInput);
        return builder.ToString();
    }

    private static string SignCanonicalMessage(string canonicalMessage)
    {
        var messageBytes = Encoding.UTF8.GetBytes(canonicalMessage);
        using var ecdsa = ECDsa.Create();
        var privateKey = Convert.FromBase64String(TestPrivateKey);
        ecdsa.ImportECPrivateKey(privateKey, out _);
        var signature = ecdsa.SignData(messageBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Convert.ToBase64String(signature);
    }
}

public class ControllerSmokeTests
{
    [Fact]
    public void IpkTest_GeneratesKeysWhenHeaderMissing()
    {
        var controller = new ApproovController(NullLogger<ApproovController>.Instance);
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        var result = controller.IpkTest() as ContentResult;

        Assert.NotNull(result);
        Assert.Equal("No IPK header, generated keys logged", result!.Content);
    }

    [Fact]
    public void IpKMessageSign_ReturnsSignature()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["private-key"] = MessageSigningVerifierTests.TestPrivateKey;
        context.Request.Headers["msg"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("payload"));

        var controller = new ApproovController(NullLogger<ApproovController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };

        var actionResult = controller.IpkMessageSignTest() as ContentResult;

        Assert.NotNull(actionResult);
        Assert.False(string.IsNullOrEmpty(actionResult!.Content));
    }
}
