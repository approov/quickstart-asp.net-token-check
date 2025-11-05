namespace Hello.Helpers;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using StructuredFieldValues;

// Reconstructs the HTTP message signature base and validates ECDSA P-256 signatures from the Approov SDK.
public sealed class ApproovMessageSignatureVerifier
{
    private static readonly ISet<string> SupportedContentDigestAlgorithms = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "sha-256",
        "sha-512"
    };

    private readonly ILogger<ApproovMessageSignatureVerifier> _logger;

    public ApproovMessageSignatureVerifier(ILogger<ApproovMessageSignatureVerifier> logger)
    {
        _logger = logger;
    }

    // Entry point used by middleware to validate signatures referenced by the 'install' label.
    public async Task<MessageSignatureResult> VerifyAsync(HttpContext context, string publicKeyBase64)
    {
        var signatureHeader = CombineHeaderValues(context.Request.Headers["Signature"]);
        var signatureInputHeader = CombineHeaderValues(context.Request.Headers["Signature-Input"]);

        if (string.IsNullOrWhiteSpace(signatureHeader) || string.IsNullOrWhiteSpace(signatureInputHeader))
        {
            return MessageSignatureResult.Failure("Missing Signature or Signature-Input headers");
        }

        var signatureParseError = SfvParser.ParseDictionary(signatureHeader, out var signatureDictionary);
        if (signatureParseError.HasValue || signatureDictionary is null)
        {
            return MessageSignatureResult.Failure($"Failed to parse signature header: {signatureParseError?.Message ?? "Unknown error"}");
        }

        var signatureInputParseError = SfvParser.ParseDictionary(signatureInputHeader, out var signatureInputDictionary);
        if (signatureInputParseError.HasValue || signatureInputDictionary is null)
        {
            return MessageSignatureResult.Failure($"Failed to parse signature-input header: {signatureInputParseError?.Message ?? "Unknown error"}");
        }

        if (!signatureDictionary.TryGetValue("install", out var signatureItem))
        {
            return MessageSignatureResult.Failure("Signature header missing 'install' entry");
        }

        if (!signatureInputDictionary.TryGetValue("install", out var signatureInputItem))
        {
            return MessageSignatureResult.Failure("Signature-Input header missing 'install' entry");
        }

        if (signatureItem.Value is not ReadOnlyMemory<byte> signatureBytes)
        {
            return MessageSignatureResult.Failure("Signature item is not encoded as a byte sequence");
        }

        if (signatureInputItem.Value is not IReadOnlyList<ParsedItem> componentIdentifiers)
        {
            return MessageSignatureResult.Failure("Signature-Input entry does not contain an inner list of components");
        }

        var signatureParameters = signatureInputItem.Parameters ?? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        if (!TryGetAlgorithm(signatureParameters, out var algorithm) || !string.Equals(algorithm, "ecdsa-p256-sha256", StringComparison.OrdinalIgnoreCase))
        {
            return MessageSignatureResult.Failure($"Unsupported signature algorithm '{algorithm ?? "<missing>"}'");
        }

        if (!TryGetUnixEpoch(signatureParameters, "created", out var createdUnix))
        {
            return MessageSignatureResult.Failure("Signature missing 'created' parameter");
        }
        // TODO: enforce a freshness window for the 'created' timestamp to guard against replayed signatures.

        var canonicalBase = await BuildCanonicalMessageAsync(context, componentIdentifiers, signatureInputItem.Parameters);
        if (!canonicalBase.Success)
        {
            return MessageSignatureResult.Failure(canonicalBase.Error!);
        }

        var canonicalPayloadBytes = Encoding.UTF8.GetBytes(canonicalBase.Payload!);

        var contentDigestValidation = await VerifyContentDigestAsync(context);
        if (!contentDigestValidation.Success)
        {
            return MessageSignatureResult.Failure(contentDigestValidation.Error!);
        }

        if (!TryVerifySignature(publicKeyBase64, signatureBytes, canonicalPayloadBytes))
        {
            return MessageSignatureResult.Failure("Signature verification failed");
        }

        return MessageSignatureResult.Succeeded(canonicalBase.Payload ?? string.Empty);
    }

    // Reconstructs the canonical message according to the Structured Field component list supplied by the client.
    private Task<(bool Success, string? Payload, string? Error)> BuildCanonicalMessageAsync(HttpContext context, IReadOnlyList<ParsedItem> components, IReadOnlyDictionary<string, object>? parameters)
    {
        context.Request.EnableBuffering();

        var lines = new List<string>();
        foreach (var component in components)
        {
            if (component.Value is not string identifier)
            {
                return Task.FromResult<(bool Success, string? Payload, string? Error)>((false, null, $"Unsupported component type '{component.Value?.GetType()}' in signature input"));
            }

            string value;
            try
            {
                value = ResolveComponentValue(context, identifier, component.Parameters);
            }
            catch (MessageSignatureException ex)
            {
                return Task.FromResult<(bool Success, string? Payload, string? Error)>((false, null, ex.Message));
            }

            var label = StructuredFieldFormatter.SerializeItem(component);
            lines.Add($"{label}: {value}");
        }

        var signatureParams = StructuredFieldFormatter.SerializeInnerList(components, parameters);
        lines.Add("\"@signature-params\": " + signatureParams);

        var payload = string.Join('\n', lines);
        return Task.FromResult<(bool Success, string? Payload, string? Error)>((true, payload, (string?)null));
    }

    // Ensures any Content-Digest headers align with the current request body bytes.
    private async Task<(bool Success, string? Error)> VerifyContentDigestAsync(HttpContext context)
    {
        var contentDigestHeader = CombineHeaderValues(context.Request.Headers["Content-Digest"]);
        if (string.IsNullOrWhiteSpace(contentDigestHeader))
        {
            return (true, null);
        }

        var parseError = SfvParser.ParseDictionary(contentDigestHeader, out var digestDictionary);
        if (parseError.HasValue || digestDictionary is null)
        {
            return (false, $"Failed to parse content-digest header: {parseError?.Message ?? "Unknown error"}");
        }

        context.Request.EnableBuffering();
        context.Request.Body.Position = 0;
        using var memoryStream = new MemoryStream();
        await context.Request.Body.CopyToAsync(memoryStream);
        var bodyBytes = memoryStream.ToArray();
        context.Request.Body.Position = 0;

        foreach (var entry in digestDictionary)
        {
            if (!SupportedContentDigestAlgorithms.Contains(entry.Key))
            {
                return (false, $"Unsupported content-digest algorithm '{entry.Key}'");
            }

            if (entry.Value.Value is not string && entry.Value.Value is not ReadOnlyMemory<byte>)
            {
                return (false, "Content-Digest entry is not a string or byte sequence");
            }

            var expectedDigest = entry.Value.Value is string text
                ? text
                : ":" + Convert.ToBase64String(((ReadOnlyMemory<byte>)entry.Value.Value!).ToArray()) + ":";

            var actualDigest = ComputeDigest(entry.Key, bodyBytes);

            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expectedDigest), Encoding.ASCII.GetBytes(actualDigest)))
            {
                return (false, $"Content digest verification failed for algorithm '{entry.Key}'");
            }
        }

        return (true, null);
    }

    // Computes the HTTP message digest value for supported algorithms.
    private static string ComputeDigest(string algorithm, byte[] body)
    {
        return algorithm.Equals("sha-512", StringComparison.OrdinalIgnoreCase)
            ? ":" + Convert.ToBase64String(SHA512.HashData(body)) + ":"
            : ":" + Convert.ToBase64String(SHA256.HashData(body)) + ":";
    }

    // Imports the EC public key and validates the raw signature bytes against the canonical payload.
    private bool TryVerifySignature(string publicKeyBase64, ReadOnlyMemory<byte> signatureBytes, byte[] canonicalPayload)
    {
        try
        {
            var publicKey = Convert.FromBase64String(publicKeyBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);

            var signature = signatureBytes.ToArray();
            return ecdsa.VerifyData(canonicalPayload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (FormatException ex)
        {
            _logger.LogWarning("Invalid public key format - {Message}", ex.Message);
            return false;
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Cryptographic failure during signature verification");
            return false;
        }
    }

    // Normalises multi-value Structured Field headers into a single string for parsing.
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

    // Extracts the 'alg' parameter from the signature input metadata.
    private static bool TryGetAlgorithm(IReadOnlyDictionary<string, object> parameters, out string? algorithm)
    {
        if (parameters.TryGetValue("alg", out var value) && value is string text)
        {
            algorithm = text;
            return true;
        }

        algorithm = null;
        return false;
    }

    // Looks for unix-timestamp style parameters (created, expires, etc.).
    private static bool TryGetUnixEpoch(IReadOnlyDictionary<string, object> parameters, string key, out long value)
    {
        if (parameters.TryGetValue(key, out var parameterValue) && parameterValue is long integer)
        {
            value = integer;
            return true;
        }

        value = default;
        return false;
    }

    // Resolves each structured field component identifier into the actual HTTP request value.
    private string ResolveComponentValue(HttpContext context, string identifier, IReadOnlyDictionary<string, object>? parameters)
    {
        switch (identifier)
        {
            case "@method":
                return context.Request.Method;
            case "@target-uri":
                return BuildTargetUri(context.Request);
            case "@authority":
                return context.Request.Host.ToUriComponent();
            case "@scheme":
                return context.Request.Scheme;
            case "@path":
                return context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty;
            case "@query":
                return context.Request.QueryString.HasValue ? context.Request.QueryString.Value!.TrimStart('?') : string.Empty;
            case "@request-target":
                return BuildRequestTarget(context.Request);
            case "@query-param":
                return ResolveQueryParam(context, parameters);
            default:
                return ResolveHeaderComponent(context, identifier, parameters);
        }
    }

    private static string BuildTargetUri(HttpRequest request)
    {
        var builder = new StringBuilder();
        builder.Append(request.Scheme);
        builder.Append("://");
        builder.Append(request.Host.ToUriComponent());
        builder.Append(request.Path.ToString());
        builder.Append(request.QueryString.ToString());
        return builder.ToString();
    }

    // Constructs the origin-form request-target as per RFC 9421
    private static string BuildRequestTarget(HttpRequest request)
    {
        var builder = new StringBuilder();
        builder.Append(request.Path.ToString());
        builder.Append(request.QueryString.ToString());
        return builder.ToString();
    }

    private static string ResolveQueryParam(HttpContext context, IReadOnlyDictionary<string, object>? parameters)
    {
        if (parameters is null || !parameters.TryGetValue("name", out var value) || value is not string name)
        {
            throw new MessageSignatureException("@query-param requires a 'name' parameter");
        }

        var queryValues = context.Request.Query[name];
        if (queryValues.Count == 0)
        {
            throw new MessageSignatureException($"Missing query parameter '{name}' for @query-param component");
        }

        return string.Join(',', queryValues.ToArray());
    }

    private string ResolveHeaderComponent(HttpContext context, string headerName, IReadOnlyDictionary<string, object>? parameters)
    {
        if (!context.Request.Headers.TryGetValue(headerName, out var values))
        {
            throw new MessageSignatureException($"Missing header '{headerName}' referenced in signature");
        }

        if (parameters is null || parameters.Count == 0)
        {
            return CombineHeaderValues(values);
        }

        if (parameters.TryGetValue("sf", out var sfValue) && sfValue is bool sf && sf)
        {
            return SerializeStructuredFieldHeader(headerName, values);
        }

        if (parameters.TryGetValue("key", out var keyValue) && keyValue is string key)
        {
            var raw = CombineHeaderValues(values);
            var parseError = SfvParser.ParseDictionary(raw, out var dictionary);
            if (parseError.HasValue || dictionary is null)
            {
                throw new MessageSignatureException($"Failed to parse header '{headerName}' as dictionary: {parseError?.Message ?? "unknown error"}");
            }

            if (!dictionary.TryGetValue(key, out var item))
            {
                throw new MessageSignatureException($"Header '{headerName}' dictionary missing key '{key}'");
            }

            return StructuredFieldFormatter.SerializeItem(item);
        }

        return CombineHeaderValues(values);
    }

    private static string SerializeStructuredFieldHeader(string headerName, IReadOnlyList<string> values)
    {
        var raw = CombineHeaderValues(values);
        var dictionaryError = SfvParser.ParseDictionary(raw, out var dictionary);
        if (!dictionaryError.HasValue && dictionary is not null)
        {
            return StructuredFieldFormatter.SerializeDictionary(dictionary);
        }

        var listError = SfvParser.ParseList(raw, out var list);
        if (!listError.HasValue && list is not null)
        {
            return StructuredFieldFormatter.SerializeList(list);
        }

        var itemError = SfvParser.ParseItem(raw, out var item);
        if (!itemError.HasValue)
        {
            return StructuredFieldFormatter.SerializeItem(item);
        }

        var errorMessage = dictionaryError?.Message ?? listError?.Message ?? itemError?.Message ?? "unknown error";
        throw new MessageSignatureException($"Failed to parse header '{headerName}' as structured field value: {errorMessage}");
    }
}

public sealed record MessageSignatureResult(bool Success, string? Error, string? CanonicalMessage)
{
    public static MessageSignatureResult Failure(string error) => new(false, error, null);
    public static MessageSignatureResult Succeeded(string canonical) => new(true, null, canonical);
}

public sealed class MessageSignatureException : Exception
{
    public MessageSignatureException(string message) : base(message)
    {
    }
}
