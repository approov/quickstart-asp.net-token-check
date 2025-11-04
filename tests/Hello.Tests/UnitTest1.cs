namespace Hello.Tests;

using System.Security.Cryptography;
using System.Text;
using Hello.Helpers;
using Hello.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

public class MessageSigningUtilitiesTests
{
    [Fact]
    public async Task BuildCanonicalMessageAsync_ComposesExpectedString()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/api/test";
        context.Request.QueryString = new QueryString("?q=1");
        context.Request.Headers["Approov-Token"] = "token123";
        context.Request.Headers["Custom-Header"] = "SomeValue";
        context.Request.Headers["Content-Type"] = "application/json";

        var bodyBytes = Encoding.UTF8.GetBytes("{\"hello\":\"world\"}");
        context.Request.Body = new MemoryStream(bodyBytes);
        context.Request.ContentLength = bodyBytes.Length;

        var canonical = await MessageSigningUtilities.BuildCanonicalMessageAsync(
            context.Request,
            new[] { "Approov-Token", "Custom-Header" });

        var bodyHash = Convert.ToBase64String(SHA256.HashData(bodyBytes));
        var expected = string.Join('\n', new[]
        {
            "POST",
            "/api/test?q=1",
            "approov-token:token123",
            "custom-header:SomeValue",
            bodyHash
        });

        Assert.Equal(expected, canonical.Payload);
        Assert.Equal(bodyHash, canonical.BodyHashBase64);
        Assert.Equal("POST", canonical.Method);
        Assert.Equal("/api/test?q=1", canonical.PathAndQuery);
        Assert.Equal("token123", canonical.Headers["approov-token"]);
    }

    [Fact]
    public void VerifyInstallationSignature_ReturnsTrueForValidSignature()
    {
        var message = Encoding.UTF8.GetBytes("installation-message");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = Convert.ToBase64String(ecdsa.SignData(message, HashAlgorithmName.SHA256));
        var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        Assert.True(MessageSigningUtilities.VerifyInstallationSignature(message, signature, publicKey));
        Assert.False(MessageSigningUtilities.VerifyInstallationSignature(Encoding.UTF8.GetBytes("tampered"), signature, publicKey));
    }

    [Fact]
    public void VerifyAccountSignature_ReturnsTrueForValidSignature()
    {
        var baseSecret = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
        var deviceIdBytes = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var deviceId = Convert.ToBase64String(deviceIdBytes);
        var tokenExpiry = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        var derivedSecret = MessageSigningUtilities.DeriveSecret(baseSecret, deviceId, tokenExpiry);
        var messageBytes = Encoding.UTF8.GetBytes("account-message");
        using var hmac = new HMACSHA256(derivedSecret);
        var signature = Convert.ToBase64String(hmac.ComputeHash(messageBytes));

        Assert.True(MessageSigningUtilities.VerifyAccountSignature(messageBytes, signature, derivedSecret));

        var tamperedSignature = signature[..^1] + (signature[^1] == 'A' ? "B" : "A");
        Assert.False(MessageSigningUtilities.VerifyAccountSignature(messageBytes, tamperedSignature, derivedSecret));
    }
}

public class MessageSigningMiddlewareTests
{
    [Fact]
    public async Task NoneMode_BypassesVerification()
    {
        var settings = Options.Create(new AppSettings
        {
            MessageSigningMode = MessageSigningMode.None
        });

        var invoked = false;
        RequestDelegate next = _ =>
        {
            invoked = true;
            return Task.CompletedTask;
        };

        var middleware = new MessageSigningMiddleware(next, settings, NullLogger<MessageSigningMiddleware>.Instance);
        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        Assert.True(invoked);
    }

    [Fact]
    public async Task InstallationMode_ValidSignature_AllowsRequest()
    {
        var settings = Options.Create(new AppSettings
        {
            MessageSigningMode = MessageSigningMode.Installation,
            MessageSigningHeaderNames = new[] { "Approov-Token", "Content-Type" },
            MessageSigningMaxAgeSeconds = 300
        });

        var called = false;
        RequestDelegate next = _ =>
        {
            called = true;
            return Task.CompletedTask;
        };

        var middleware = new MessageSigningMiddleware(next, settings, NullLogger<MessageSigningMiddleware>.Instance);
        var context = BuildHttpContext();

        var headerNames = new[] { "Approov-Token", "Content-Type" };
        var canonicalMessage = await MessageSigningUtilities.BuildCanonicalMessageAsync(context.Request, headerNames);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = Convert.ToBase64String(ecdsa.SignData(canonicalMessage.PayloadBytes, HashAlgorithmName.SHA256));
        var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        context.Request.Headers["Signature-Input"] = "sig1=(\"@method\" \"@path\" \"approov-token\" \"content-type\");created=" + created;
        context.Request.Headers["Signature"] = "sig1=:" + signature + ":";
        context.Items[ApproovTokenContextKeys.ApproovToken] = context.Request.Headers["Approov-Token"].ToString();
        context.Items[ApproovTokenContextKeys.InstallationPublicKey] = publicKey;

        await middleware.InvokeAsync(context);

        Assert.True(called);
        Assert.NotEqual(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task InstallationMode_InvalidSignature_DeniesRequest()
    {
        var settings = Options.Create(new AppSettings
        {
            MessageSigningMode = MessageSigningMode.Installation,
            MessageSigningHeaderNames = new[] { "Approov-Token" },
            MessageSigningMaxAgeSeconds = 300
        });

        var middleware = new MessageSigningMiddleware(_ => Task.CompletedTask, settings, NullLogger<MessageSigningMiddleware>.Instance);
        var context = BuildHttpContext();

        context.Request.Headers["Signature-Input"] = "sig1=(\"@method\" \"@path\" \"approov-token\");created=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        context.Request.Headers["Signature"] = "sig1=:invalid:";
        context.Items[ApproovTokenContextKeys.ApproovToken] = context.Request.Headers["Approov-Token"].ToString();
        context.Items[ApproovTokenContextKeys.InstallationPublicKey] = Convert.ToBase64String(ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportSubjectPublicKeyInfo());

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task AccountMode_ValidSignature_AllowsRequest()
    {
        var baseSecret = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
        var deviceIdBytes = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var deviceId = Convert.ToBase64String(deviceIdBytes);
        var tokenExpiry = DateTimeOffset.UtcNow.AddMinutes(2);

        var settings = Options.Create(new AppSettings
        {
            MessageSigningMode = MessageSigningMode.Account,
            AccountMessageBaseSecretBytes = baseSecret,
            MessageSigningHeaderNames = new[] { "Approov-Token", "Content-Type" },
            MessageSigningMaxAgeSeconds = 300
        });

        var called = false;
        RequestDelegate next = _ =>
        {
            called = true;
            return Task.CompletedTask;
        };

        var middleware = new MessageSigningMiddleware(next, settings, NullLogger<MessageSigningMiddleware>.Instance);
        var context = BuildHttpContext();

        var headerNames = new[] { "Approov-Token", "Content-Type" };
        var canonicalMessage = await MessageSigningUtilities.BuildCanonicalMessageAsync(context.Request, headerNames);
        var derivedSecret = MessageSigningUtilities.DeriveSecret(baseSecret, deviceId, tokenExpiry);
        using var hmac = new HMACSHA256(derivedSecret);
        var signature = Convert.ToBase64String(hmac.ComputeHash(canonicalMessage.PayloadBytes));

        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        context.Request.Headers["Signature-Input"] = "sig1=(\"@method\" \"@path\" \"approov-token\" \"content-type\");created=" + created;
        context.Request.Headers["Signature"] = "sig1=:" + signature + ":";
        context.Items[ApproovTokenContextKeys.ApproovToken] = context.Request.Headers["Approov-Token"].ToString();
        context.Items[ApproovTokenContextKeys.DeviceId] = deviceId;
        context.Items[ApproovTokenContextKeys.TokenExpiry] = tokenExpiry;

        await middleware.InvokeAsync(context);

        Assert.True(called);
        Assert.NotEqual(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task AccountMode_ExpiredSignature_DeniesRequest()
    {
        var baseSecret = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
        var deviceId = Convert.ToBase64String(Enumerable.Range(1, 16).Select(i => (byte)i).ToArray());

        var settings = Options.Create(new AppSettings
        {
            MessageSigningMode = MessageSigningMode.Account,
            AccountMessageBaseSecretBytes = baseSecret,
            MessageSigningHeaderNames = new[] { "Approov-Token" },
            MessageSigningMaxAgeSeconds = 60
        });

        var middleware = new MessageSigningMiddleware(_ => Task.CompletedTask, settings, NullLogger<MessageSigningMiddleware>.Instance);
        var context = BuildHttpContext();

        var created = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds();
        context.Request.Headers["Signature-Input"] = "sig1=(\"@method\" \"@path\" \"approov-token\");created=" + created;
        context.Request.Headers["Signature"] = "sig1=:invalid:";
        context.Items[ApproovTokenContextKeys.ApproovToken] = context.Request.Headers["Approov-Token"].ToString();
        context.Items[ApproovTokenContextKeys.DeviceId] = deviceId;
        context.Items[ApproovTokenContextKeys.TokenExpiry] = DateTimeOffset.UtcNow;

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    private static DefaultHttpContext BuildHttpContext()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.Request.Method = "POST";
        context.Request.Path = "/resource";
        context.Request.QueryString = new QueryString("?id=123");
        context.Request.Headers["Approov-Token"] = "token-value";
        context.Request.Headers["Content-Type"] = "application/json";

        var body = Encoding.UTF8.GetBytes("{\"key\":\"value\"}");
        context.Request.Body = new MemoryStream(body);
        context.Request.ContentLength = body.Length;

        return context;
    }
}
