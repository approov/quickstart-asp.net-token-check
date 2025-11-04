namespace Hello.Helpers;

using System.Collections.Generic;
using System.Text;

public readonly record struct HttpSignatureEntry(string Label, string Signature);

public record HttpSignatureInput(
    string Label,
    IReadOnlyList<string> Components,
    long? Created,
    long? Expires,
    string? Nonce);

public static class HttpSignatureParser
{
    public static bool TryParseSignature(string headerValue, out HttpSignatureEntry entry, out string? error)
    {
        entry = default;
        error = null;

        if (string.IsNullOrWhiteSpace(headerValue))
        {
            error = "Signature header is empty.";
            return false;
        }

        foreach (var segment in SplitTopLevel(headerValue))
        {
            var trimmed = segment.Trim();
            if (string.IsNullOrEmpty(trimmed))
            {
                continue;
            }

            var equalsIndex = trimmed.IndexOf('=');
            if (equalsIndex < 0)
            {
                continue;
            }

            var label = trimmed[..equalsIndex].Trim();
            var remainder = trimmed[(equalsIndex + 1)..].Trim();

            if (string.IsNullOrEmpty(label))
            {
                continue;
            }

            string signatureValue;

            if (remainder.StartsWith(":", StringComparison.Ordinal))
            {
                var closingColonIndex = remainder.IndexOf(':', 1);
                if (closingColonIndex < 0)
                {
                    error = "Signature header value missing closing colon.";
                    return false;
                }

                signatureValue = remainder.Substring(1, closingColonIndex - 1);
            }
            else
            {
                var semicolonIndex = remainder.IndexOf(';');
                if (semicolonIndex >= 0)
                {
                    remainder = remainder[..semicolonIndex];
                }

                signatureValue = remainder.Trim().Trim('"');
            }

            if (string.IsNullOrEmpty(signatureValue))
            {
                error = "Signature header missing encoded signature.";
                return false;
            }

            entry = new HttpSignatureEntry(label, signatureValue);
            return true;
        }

        error = "Signature header missing expected entry.";
        return false;
    }

    public static bool TryParseSignatureInput(string headerValue, string expectedLabel, out HttpSignatureInput? signatureInput, out string? error)
    {
        signatureInput = null;
        error = null;

        if (string.IsNullOrWhiteSpace(headerValue))
        {
            error = "Signature-Input header is empty.";
            return false;
        }

        foreach (var segment in SplitTopLevel(headerValue))
        {
            var trimmed = segment.Trim();
            if (string.IsNullOrEmpty(trimmed))
            {
                continue;
            }

            var equalsIndex = trimmed.IndexOf('=');
            if (equalsIndex < 0)
            {
                continue;
            }

            var label = trimmed[..equalsIndex].Trim();
            if (!string.IsNullOrEmpty(expectedLabel) && !string.Equals(label, expectedLabel, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var remainder = trimmed[(equalsIndex + 1)..].Trim();
            var openParenIndex = remainder.IndexOf('(');
            var closeParenIndex = remainder.IndexOf(')', openParenIndex + 1);

            if (openParenIndex < 0 || closeParenIndex < 0 || closeParenIndex <= openParenIndex)
            {
                error = "Signature-Input header missing component list.";
                return false;
            }

            var componentsSegment = remainder.Substring(openParenIndex + 1, closeParenIndex - openParenIndex - 1);
            var components = ParseComponents(componentsSegment);

            var parametersSegment = remainder[(closeParenIndex + 1)..];
            long? created = null;
            long? expires = null;
            string? nonce = null;

            if (!string.IsNullOrWhiteSpace(parametersSegment))
            {
                var parameterParts = parametersSegment.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (var parameter in parameterParts)
                {
                    var separatorIndex = parameter.IndexOf('=');
                    var key = separatorIndex >= 0 ? parameter[..separatorIndex].Trim() : parameter.Trim();
                    var value = separatorIndex >= 0 ? parameter[(separatorIndex + 1)..].Trim() : string.Empty;
                    value = TrimQuotes(value);

                    switch (key)
                    {
                        case "created":
                            if (long.TryParse(value, out var createdValue))
                            {
                                created = createdValue;
                            }
                            break;
                        case "expires":
                            if (long.TryParse(value, out var expiresValue))
                            {
                                expires = expiresValue;
                            }
                            break;
                        case "nonce":
                            nonce = value;
                            break;
                    }
                }
            }

            signatureInput = new HttpSignatureInput(label, components, created, expires, nonce);
            return true;
        }

        error = string.IsNullOrEmpty(expectedLabel)
            ? "Signature-Input header missing required entry."
            : $"Signature-Input header missing entry for label '{expectedLabel}'.";
        return false;
    }

    private static IReadOnlyList<string> ParseComponents(string segment)
    {
        var components = new List<string>();
        var builder = new StringBuilder();
        var insideQuotes = false;
        var escaping = false;

        foreach (var ch in segment)
        {
            if (escaping)
            {
                builder.Append(ch);
                escaping = false;
                continue;
            }

            if (ch == '\\' && insideQuotes)
            {
                escaping = true;
                continue;
            }

            if (ch == '"')
            {
                if (insideQuotes)
                {
                    components.Add(builder.ToString());
                    builder.Clear();
                }

                insideQuotes = !insideQuotes;
                continue;
            }

            if (insideQuotes)
            {
                builder.Append(ch);
            }
        }

        return components;
    }

    private static IEnumerable<string> SplitTopLevel(string headerValue)
    {
        var segments = new List<string>();
        var builder = new StringBuilder();
        var insideQuotes = false;
        var escaping = false;
        var parenDepth = 0;

        foreach (var ch in headerValue)
        {
            if (escaping)
            {
                builder.Append(ch);
                escaping = false;
                continue;
            }

            switch (ch)
            {
                case '\\':
                    if (insideQuotes)
                    {
                        escaping = true;
                        continue;
                    }
                    break;
                case '"':
                    insideQuotes = !insideQuotes;
                    break;
                case '(':
                    if (!insideQuotes)
                    {
                        parenDepth++;
                    }
                    break;
                case ')':
                    if (!insideQuotes && parenDepth > 0)
                    {
                        parenDepth--;
                    }
                    break;
                case ',':
                    if (!insideQuotes && parenDepth == 0)
                    {
                        segments.Add(builder.ToString());
                        builder.Clear();
                        continue;
                    }
                    break;
            }

            builder.Append(ch);
        }

        if (builder.Length > 0)
        {
            segments.Add(builder.ToString());
        }

        return segments;
    }

    private static string TrimQuotes(string value)
    {
        if (value.Length >= 2 && value.StartsWith('"') && value.EndsWith('"'))
        {
            return value[1..^1];
        }

        return value;
    }
}
