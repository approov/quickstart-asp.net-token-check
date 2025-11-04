namespace Hello.Helpers;

using System;
using System.Buffers.Binary;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

public sealed record CanonicalMessage(
    string Method,
    string PathAndQuery,
    IReadOnlyDictionary<string, string> Headers,
    string? BodyHashBase64,
    byte[] PayloadBytes)
{
    public string Payload => Encoding.UTF8.GetString(PayloadBytes);
}

public static class MessageSigningUtilities
{
    public static async Task<CanonicalMessage> BuildCanonicalMessageAsync(HttpRequest request, IEnumerable<string> headerNames)
    {
        var orderedHeaders = headerNames
            .Select(name => name.Trim())
            .Where(name => !string.IsNullOrEmpty(name))
            .Select(name => name.ToLowerInvariant())
            .Distinct()
            .ToList();

        var method = request.Method.ToUpperInvariant();
        var pathAndQuery = BuildPathAndQuery(request);
        var headerMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var parts = new List<string>
        {
            method,
            pathAndQuery
        };

        foreach (var headerName in orderedHeaders)
        {
            if (!request.Headers.TryGetValue(headerName, out var values))
            {
                var match = request.Headers.FirstOrDefault(pair => string.Equals(pair.Key, headerName, StringComparison.OrdinalIgnoreCase));
                values = match.Value;
            }

            var canonicalValue = values.Count > 0
                ? string.Join(", ", values.Select(v => v.Trim()))
                : string.Empty;

            headerMap[headerName] = canonicalValue;
            parts.Add($"{headerName}:{canonicalValue}");
        }

        var bodyHash = await ComputeBodyHashAsync(request).ConfigureAwait(false);
        string? bodyHashBase64 = null;
        if (bodyHash != null)
        {
            bodyHashBase64 = Convert.ToBase64String(bodyHash);
            parts.Add(bodyHashBase64);
        }

        var payloadBytes = Encoding.UTF8.GetBytes(string.Join('\n', parts));
        return new CanonicalMessage(method, pathAndQuery, headerMap, bodyHashBase64, payloadBytes);
    }

    public static bool VerifyInstallationSignature(byte[] message, string signature, string publicKeyBase64)
    {
        if (!TryDecodeBase64(signature, out var signatureBytes))
        {
            return false;
        }

        byte[] publicKeyBytes;
        try
        {
            publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
        }
        catch (CryptographicException)
        {
            return false;
        }

        if (ecdsa.VerifyData(message, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
        {
            return true;
        }

        if (signatureBytes.Length == 64 &&
            ecdsa.VerifyData(message, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            return true;
        }

        return false;
    }

    public static byte[] DeriveSecret(byte[] baseSecret, string deviceId, DateTimeOffset tokenExpiry)
    {
        if (baseSecret.Length == 0)
        {
            throw new ArgumentException("Base secret must not be empty.", nameof(baseSecret));
        }

        byte[] deviceIdBytes;
        try
        {
            deviceIdBytes = Convert.FromBase64String(deviceId);
        }
        catch (FormatException)
        {
            deviceIdBytes = Encoding.UTF8.GetBytes(deviceId);
        }

        Span<byte> expiryBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(expiryBytes, tokenExpiry.ToUnixTimeSeconds());

        var payloadLength = deviceIdBytes.Length + expiryBytes.Length;
        var payload = new byte[payloadLength];
        Buffer.BlockCopy(deviceIdBytes, 0, payload, 0, deviceIdBytes.Length);
        expiryBytes.CopyTo(payload.AsSpan(deviceIdBytes.Length));

        using var hmac = new HMACSHA256(baseSecret);
        return hmac.ComputeHash(payload);
    }

    public static bool VerifyAccountSignature(byte[] message, string signature, byte[] derivedSecret)
    {
        if (!TryDecodeBase64(signature, out var signatureBytes))
        {
            return false;
        }

        using var hmac = new HMACSHA256(derivedSecret);
        var expectedSignature = hmac.ComputeHash(message);

        if (signatureBytes.Length != expectedSignature.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(signatureBytes, expectedSignature);
    }

    private static async Task<byte[]?> ComputeBodyHashAsync(HttpRequest request)
    {
        request.EnableBuffering();
        if (!request.Body.CanRead)
        {
            return null;
        }

        request.Body.Position = 0;

        using var sha256 = SHA256.Create();
        var buffer = new byte[8192];
        long totalRead = 0;
        int bytesRead;

        while ((bytesRead = await request.Body.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false)) > 0)
        {
            sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
            totalRead += bytesRead;
        }

        sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        request.Body.Position = 0;

        return totalRead > 0 ? sha256.Hash : null;
    }

    private static string BuildPathAndQuery(HttpRequest request)
    {
        var path = request.Path.HasValue ? request.Path.Value : "/";
        var query = request.QueryString.HasValue ? request.QueryString.Value : string.Empty;
        return string.Concat(path, query);
    }

    private static bool TryDecodeBase64(string value, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();

        try
        {
            bytes = Convert.FromBase64String(trimmed);
            return true;
        }
        catch (FormatException)
        {
            // Fall through and try Base64Url decoding.
        }

        var normalized = trimmed.Replace('-', '+').Replace('_', '/');
        switch (normalized.Length % 4)
        {
            case 2:
                normalized += "==";
                break;
            case 3:
                normalized += "=";
                break;
        }

        try
        {
            bytes = Convert.FromBase64String(normalized);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
