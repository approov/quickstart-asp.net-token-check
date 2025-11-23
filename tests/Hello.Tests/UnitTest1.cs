namespace Hello.Tests;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Hello.Controllers;
using Hello.Helpers;
using Hello.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using StructuredFieldValues;

public class MessageSigningVerifierTests
{
    internal const string TestPrivateKey = "MHcCAQEEIHWZ2Ueq6odQNG+aaYmEbp7C6nujYNGr7nYKK2jqQ2asoAoGCCqGSM49AwEHoUQDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";
    private const string TestPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";
    private const string ApproovToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHByb292LmlvIiwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IkFwcHJvb3ZBY2NvdW50SUQuYXBwcm9vdi5pbyIsInN1YiI6ImFwcHJvb3Z8RXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwiaXAiOiIxLjIuMy40IiwiaXBrIjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSlNtNERNY2l2QXd2aE0rS05jZTJDL1gyNmNqM29HeVV3V1ZVUHVOdVpIdGQycXlWc00rMGc3cVg3M1FoME9mNmZuMTBBQXBMbmw4dlJRc3Z4OTRmWlE9PSIsImRpZCI6IkV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSJ9.hV6xTkGsp9uWwrD-yKkIGTBJawbofJEsuRLw9Qa5YXY";

    [Fact]
    public async Task VerifyAsync_WithValidSignature_ReturnsSuccess()
    {
        var context = BuildRequest();
        var canonicalMessage = BuildCanonicalMessage(context);
        var signature = SignCanonicalMessage(canonicalMessage);

        context.Request.Headers["Signature"] = $"install=:{signature}:";

        var verifier = CreateVerifier();
        var result = await verifier.VerifyAsync(context, TestPublicKey);

        Assert.True(result.Success);
    }

    [Fact]
    public async Task VerifyAsync_WithInvalidSignature_ReturnsFailure()
    {
        var context = BuildRequest();
        var canonicalMessage = BuildCanonicalMessage(context);
        var signature = SignCanonicalMessage(canonicalMessage);
        var tampered = signature[..^1] + (signature[^1] == 'A' ? "B" : "A");

        context.Request.Headers["Signature"] = $"install=:{tampered}:";

        var verifier = CreateVerifier();
        var result = await verifier.VerifyAsync(context, TestPublicKey);

        Assert.False(result.Success);
    }

    private static DefaultHttpContext BuildRequest()
    {
        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30;
        var expires = created + 600;
        var signatureInput = $"(\"@method\" \"approov-token\");alg=\"ecdsa-p256-sha256\";created={created};expires={expires}";

        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("0.0.0.0", 8111);
        context.Request.Path = "/token";
        context.Request.QueryString = new QueryString("?param1=value1&param2=value2");
        context.Request.Headers["Approov-Token"] = ApproovToken;
        context.Request.Headers["Signature-Input"] = $"install={signatureInput}";

        return context;
    }

    private static string BuildCanonicalMessage(DefaultHttpContext context)
    {
        var signatureInputHeader = StructuredFieldFormatter.CombineHeaderValues(context.Request.Headers["Signature-Input"]);
        var parseError = SfvParser.ParseDictionary(signatureInputHeader, out var dictionary);
        Assert.False(parseError.HasValue, parseError?.Message ?? "Failed to parse Signature-Input header");
        Assert.NotNull(dictionary);
        Assert.True(dictionary.TryGetValue("install", out var signatureInputItem));

        var components = Assert.IsAssignableFrom<IReadOnlyList<ParsedItem>>(signatureInputItem.Value);
        var lines = new List<string>();

        foreach (var component in components)
        {
            var identifier = Assert.IsType<string>(component.Value);
            var value = ResolveComponentValue(context, identifier);
            var label = StructuredFieldFormatter.SerializeItem(component);
            lines.Add($"{label}: {value}");
        }

        var signatureParams = StructuredFieldFormatter.SerializeInnerList(components, signatureInputItem.Parameters);
        lines.Add("\"@signature-params\": " + signatureParams);

        return string.Join('\n', lines);
    }

    private static string ResolveComponentValue(DefaultHttpContext context, string identifier)
    {
        if (identifier == "@method")
        {
            return context.Request.Method;
        }

        Assert.True(context.Request.Headers.TryGetValue(identifier, out var values), $"Missing header '{identifier}'");
        return StructuredFieldFormatter.CombineHeaderValues(values);
    }

    private static string SignCanonicalMessage(string canonicalMessage)
    {
        var messageBytes = Encoding.UTF8.GetBytes(canonicalMessage);
        using var ecdsa = ECDsa.Create();
        var privateKey = Convert.FromBase64String(TestPrivateKey);
        ecdsa.ImportECPrivateKey(privateKey, out _);
        var signature = ecdsa.SignData(
            messageBytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Convert.ToBase64String(signature);
    }

    private static ApproovMessageSignatureVerifier CreateVerifier()
    {
        var options = Options.Create(new MessageSignatureValidationOptions
        {
            RequireCreated = true,
            RequireExpires = false,
            MaximumSignatureAge = null,
            AllowedClockSkew = TimeSpan.FromMinutes(5)
        });

        return new ApproovMessageSignatureVerifier(
            NullLogger<ApproovMessageSignatureVerifier>.Instance,
            options);
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
        Assert.Equal("No IPK header provided", result!.Content);
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
