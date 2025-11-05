namespace Hello.Helpers;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using StructuredFieldValues;

public static class StructuredFieldFormatter
{
    public static string SerializeItem(ParsedItem item)
    {
        var builder = new StringBuilder();
        builder.Append(SerializeBareItem(item.Value));

        if (item.Parameters is { Count: > 0 })
        {
            foreach (var parameter in item.Parameters)
            {
                builder.Append(';');
                builder.Append(parameter.Key);
                if (parameter.Value is bool boolean && boolean)
                {
                    continue;
                }

                builder.Append('=');
                builder.Append(SerializeBareItem(parameter.Value));
            }
        }

        return builder.ToString();
    }

    public static string SerializeInnerList(IReadOnlyList<ParsedItem> items, IReadOnlyDictionary<string, object>? parameters)
    {
        var builder = new StringBuilder();
        builder.Append('(');
        for (var i = 0; i < items.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(' ');
            }

            builder.Append(SerializeItem(items[i]));
        }

        builder.Append(')');
        if (parameters is { Count: > 0 })
        {
            foreach (var parameter in parameters)
            {
                builder.Append(';');
                builder.Append(parameter.Key);
                if (parameter.Value is bool boolean && boolean)
                {
                    continue;
                }

                builder.Append('=');
                builder.Append(SerializeBareItem(parameter.Value));
            }
        }

        return builder.ToString();
    }

    public static string SerializeList(IReadOnlyList<ParsedItem> items)
    {
        var builder = new StringBuilder();
        for (var i = 0; i < items.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(", ");
            }

            builder.Append(SerializeItem(items[i]));
        }

        return builder.ToString();
    }

    public static string SerializeDictionary(IReadOnlyDictionary<string, ParsedItem> dictionary)
    {
        var builder = new StringBuilder();
        var first = true;
        foreach (var entry in dictionary)
        {
            if (!first)
            {
                builder.Append(", ");
            }

            builder.Append(entry.Key);

            // Bare item with boolean true is encoded without explicit value.
            if (entry.Value.Value is bool boolean && boolean && (entry.Value.Parameters == null || entry.Value.Parameters.Count == 0))
            {
                first = false;
                continue;
            }

            builder.Append('=');
            builder.Append(SerializeItem(entry.Value));
            first = false;
        }

        return builder.ToString();
    }

    private static string SerializeBareItem(object? value)
    {
        switch (value)
        {
            case null:
                return string.Empty;
            case bool boolean:
                return boolean ? "?1" : "?0";
            case long integer:
                return integer.ToString(CultureInfo.InvariantCulture);
            case int smallInteger:
                return smallInteger.ToString(CultureInfo.InvariantCulture);
            case double number:
                return number.ToString("G", CultureInfo.InvariantCulture);
            case string text:
                return SerializeString(text);
            case Token token:
                return token.ToString();
            case DisplayString display:
                return SerializeDisplayString(display);
            case ReadOnlyMemory<byte> bytes:
                return ":" + Convert.ToBase64String(bytes.ToArray()) + ":";
            case IReadOnlyList<ParsedItem> innerList:
                return SerializeInnerList(innerList, null);
            default:
                throw new NotSupportedException($"Unsupported structured field value type '{value.GetType()}'.");
        }
    }

    private static string SerializeString(string value)
    {
        var builder = new StringBuilder();
        builder.Append('"');
        foreach (var ch in value)
        {
            if (ch == '"' || ch == '\\')
            {
                builder.Append('\\');
            }

            builder.Append(ch);
        }
        builder.Append('"');
        return builder.ToString();
    }

    private static string SerializeDisplayString(DisplayString displayString)
    {
        var text = displayString.ToString();
        var bytes = Encoding.UTF8.GetBytes(text);
        var builder = new StringBuilder();
        builder.Append('%');

        foreach (var b in bytes)
        {
            var ch = (char)b;
            if (ch >= 0x20 && ch <= 0x7E && ch != '%' && ch != '"')
            {
                builder.Append(ch);
            }
            else
            {
                builder.Append('%');
                builder.Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }
}
