using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace UploadFileBlazor.Services;

internal static partial class EmailHtmlSanitizer
{
    private const int MaxDecodePasses = 8;

    private static readonly HashSet<string> AllowedElements = new(StringComparer.OrdinalIgnoreCase)
    {
        "a",
        "abbr",
        "b",
        "blockquote",
        "body",
        "br",
        "caption",
        "center",
        "cite",
        "code",
        "col",
        "colgroup",
        "dd",
        "del",
        "div",
        "dl",
        "dt",
        "em",
        "font",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "html",
        "i",
        "img",
        "li",
        "ol",
        "p",
        "pre",
        "q",
        "s",
        "small",
        "span",
        "strong",
        "sub",
        "sup",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "u",
        "ul"
    };

    private static readonly HashSet<string> VoidElements = new(StringComparer.OrdinalIgnoreCase)
    {
        "br",
        "col",
        "hr",
        "img"
    };

    private static readonly HashSet<string> DangerousContentElements = new(StringComparer.OrdinalIgnoreCase)
    {
        "applet",
        "audio",
        "base",
        "button",
        "canvas",
        "embed",
        "fieldset",
        "form",
        "frame",
        "frameset",
        "head",
        "iframe",
        "input",
        "link",
        "math",
        "meta",
        "noscript",
        "object",
        "option",
        "plaintext",
        "script",
        "select",
        "source",
        "style",
        "svg",
        "template",
        "textarea",
        "title",
        "track",
        "video",
        "xmp"
    };

    private static readonly HashSet<string> GlobalTextAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "class",
        "dir",
        "id",
        "lang",
        "role",
        "title"
    };

    private static readonly HashSet<string> AnchorSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "https",
        "mailto",
        "tel"
    };

    private static readonly HashSet<string> ImageSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "https",
        "cid"
    };

    private static readonly HashSet<string> AlignmentValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "baseline",
        "bottom",
        "center",
        "justify",
        "left",
        "middle",
        "right",
        "top"
    };

    public static string Sanitize(string html)
    {
        var canonicalHtml = NormalizeLineEndings(RemoveUnsafeControlCharacters(DecodeHtmlEntitiesRepeatedly(html)));
        var sanitized = new StringBuilder(canonicalHtml.Length);

        for (var index = 0; index < canonicalHtml.Length; index++)
        {
            if (canonicalHtml[index] != '<')
            {
                AppendEncodedCharacter(sanitized, canonicalHtml[index]);
                continue;
            }

            if (!TryReadTag(canonicalHtml, index, out var tag, out var nextIndex))
            {
                sanitized.Append("&lt;");
                continue;
            }

            index = nextIndex - 1;

            if (tag.Kind is HtmlTagKind.Comment or HtmlTagKind.Declaration)
            {
                continue;
            }

            if (DangerousContentElements.Contains(tag.Name))
            {
                if (!tag.IsClosing)
                {
                    index = FindDangerousElementEnd(canonicalHtml, tag.Name, nextIndex) - 1;
                }

                continue;
            }

            if (!AllowedElements.Contains(tag.Name))
            {
                continue;
            }

            if (tag.IsClosing)
            {
                if (!VoidElements.Contains(tag.Name))
                {
                    sanitized.Append("</").Append(tag.Name).Append('>');
                }

                continue;
            }

            sanitized.Append('<').Append(tag.Name);
            AppendSanitizedAttributes(sanitized, tag.Name, tag.RawAttributes);
            sanitized.Append('>');
        }

        return sanitized.ToString().Trim();
    }

    private static bool TryReadTag(string html, int startIndex, out HtmlTag tag, out int nextIndex)
    {
        tag = default;
        nextIndex = startIndex + 1;

        if (startIndex + 1 >= html.Length || html[startIndex] != '<')
        {
            return false;
        }

        if (html.AsSpan(startIndex + 1).StartsWith("!--", StringComparison.Ordinal))
        {
            var commentEnd = html.IndexOf("-->", startIndex + 4, StringComparison.Ordinal);
            nextIndex = commentEnd >= 0 ? commentEnd + 3 : html.Length;
            tag = new HtmlTag(HtmlTagKind.Comment, string.Empty, false, string.Empty);
            return true;
        }

        var index = startIndex + 1;
        if (html[index] is '!' or '?')
        {
            nextIndex = FindTagEnd(html, index + 1);
            if (nextIndex < 0)
            {
                nextIndex = html.Length;
            }

            tag = new HtmlTag(HtmlTagKind.Declaration, string.Empty, false, string.Empty);
            return true;
        }

        var isClosing = false;
        if (html[index] == '/')
        {
            isClosing = true;
            index++;
        }

        while (index < html.Length && char.IsWhiteSpace(html[index]))
        {
            index++;
        }

        if (index >= html.Length || !IsTagNameStart(html[index]))
        {
            return false;
        }

        var nameStart = index;
        index++;
        while (index < html.Length && IsTagNameCharacter(html[index]))
        {
            index++;
        }

        var tagName = html[nameStart..index].ToLowerInvariant();
        nextIndex = FindTagEnd(html, index);
        if (nextIndex <= index)
        {
            return false;
        }

        var rawAttributes = isClosing ? string.Empty : html[index..(nextIndex - 1)];
        tag = new HtmlTag(HtmlTagKind.Element, tagName, isClosing, rawAttributes);
        return true;
    }

    private static int FindTagEnd(string html, int startIndex)
    {
        char? quote = null;

        for (var index = startIndex; index < html.Length; index++)
        {
            var character = html[index];
            if (quote is not null)
            {
                if (character == quote)
                {
                    quote = null;
                }

                continue;
            }

            if (character is '"' or '\'')
            {
                quote = character;
                continue;
            }

            if (character == '>')
            {
                return index + 1;
            }
        }

        return -1;
    }

    private static int FindDangerousElementEnd(string html, string tagName, int startIndex)
    {
        var pattern = "</" + tagName;
        var closingStart = html.IndexOf(pattern, startIndex, StringComparison.OrdinalIgnoreCase);
        if (closingStart < 0)
        {
            return html.Length;
        }

        var closingEnd = FindTagEnd(html, closingStart + 2 + tagName.Length);
        return closingEnd > closingStart ? closingEnd : html.Length;
    }

    private static void AppendSanitizedAttributes(StringBuilder sanitized, string tagName, string rawAttributes)
    {
        var attributes = ParseAttributes(rawAttributes);
        var emittedAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var opensInNewWindow = false;

        foreach (var attribute in attributes)
        {
            if (!TrySanitizeAttribute(tagName, attribute.Name, attribute.Value, out var sanitizedName, out var sanitizedValue))
            {
                continue;
            }

            if (!emittedAttributes.Add(sanitizedName))
            {
                continue;
            }

            if (sanitizedName.Equals("target", StringComparison.OrdinalIgnoreCase) &&
                sanitizedValue.Equals("_blank", StringComparison.OrdinalIgnoreCase))
            {
                opensInNewWindow = true;
            }

            sanitized.Append(' ')
                .Append(sanitizedName)
                .Append("=\"")
                .Append(HtmlEncodeAttribute(sanitizedValue))
                .Append('"');
        }

        if (tagName.Equals("a", StringComparison.OrdinalIgnoreCase) &&
            opensInNewWindow &&
            !emittedAttributes.Contains("rel"))
        {
            sanitized.Append(" rel=\"noopener noreferrer\"");
        }
    }

    private static List<HtmlAttribute> ParseAttributes(string rawAttributes)
    {
        var attributes = new List<HtmlAttribute>();
        var index = 0;

        while (index < rawAttributes.Length)
        {
            while (index < rawAttributes.Length && (char.IsWhiteSpace(rawAttributes[index]) || rawAttributes[index] == '/'))
            {
                index++;
            }

            if (index >= rawAttributes.Length)
            {
                break;
            }

            if (!IsAttributeNameStart(rawAttributes[index]))
            {
                index++;
                continue;
            }

            var nameStart = index;
            index++;
            while (index < rawAttributes.Length && IsAttributeNameCharacter(rawAttributes[index]))
            {
                index++;
            }

            var attributeName = rawAttributes[nameStart..index].ToLowerInvariant();

            while (index < rawAttributes.Length && char.IsWhiteSpace(rawAttributes[index]))
            {
                index++;
            }

            var attributeValue = string.Empty;
            if (index < rawAttributes.Length && rawAttributes[index] == '=')
            {
                index++;
                while (index < rawAttributes.Length && char.IsWhiteSpace(rawAttributes[index]))
                {
                    index++;
                }

                if (index < rawAttributes.Length && rawAttributes[index] is '"' or '\'')
                {
                    var quote = rawAttributes[index++];
                    var valueStart = index;
                    while (index < rawAttributes.Length && rawAttributes[index] != quote)
                    {
                        index++;
                    }

                    attributeValue = rawAttributes[valueStart..index];
                    if (index < rawAttributes.Length)
                    {
                        index++;
                    }
                }
                else
                {
                    var valueStart = index;
                    while (index < rawAttributes.Length &&
                           !char.IsWhiteSpace(rawAttributes[index]) &&
                           rawAttributes[index] is not '/' and not '>')
                    {
                        index++;
                    }

                    attributeValue = rawAttributes[valueStart..index];
                }
            }

            attributes.Add(new HtmlAttribute(attributeName, attributeValue));
        }

        return attributes;
    }

    private static bool TrySanitizeAttribute(
        string tagName,
        string attributeName,
        string attributeValue,
        out string sanitizedName,
        out string sanitizedValue)
    {
        sanitizedName = attributeName.ToLowerInvariant();
        sanitizedValue = DecodeHtmlEntitiesRepeatedly(attributeValue).Trim();

        if (sanitizedName.Length == 0 ||
            sanitizedName.StartsWith("on", StringComparison.OrdinalIgnoreCase) ||
            sanitizedName.StartsWith("xmlns", StringComparison.OrdinalIgnoreCase) ||
            sanitizedName is "style" or "srcdoc" or "formaction" or "action" or "background" or "dynsrc" or "lowsrc" or "srcset")
        {
            return false;
        }

        sanitizedValue = RemoveUnsafeControlCharacters(sanitizedValue);
        if (sanitizedValue.Length > 2048)
        {
            return false;
        }

        if (sanitizedName.StartsWith("aria-", StringComparison.OrdinalIgnoreCase))
        {
            return IsSafeTextAttributeValue(sanitizedValue);
        }

        if (GlobalTextAttributes.Contains(sanitizedName))
        {
            return sanitizedName switch
            {
                "dir" => IsOneOf(sanitizedValue, "ltr", "rtl", "auto"),
                "id" or "class" => IsSafeTokenList(sanitizedValue),
                _ => IsSafeTextAttributeValue(sanitizedValue)
            };
        }

        if (tagName.Equals("a", StringComparison.OrdinalIgnoreCase))
        {
            return sanitizedName switch
            {
                "href" => TrySanitizeUrl(sanitizedValue, AnchorSchemes, allowFragment: true, out sanitizedValue),
                "target" => TrySanitizeTarget(sanitizedValue, out sanitizedValue),
                "rel" => TrySanitizeRel(sanitizedValue, out sanitizedValue),
                "name" => IsSafeTokenList(sanitizedValue),
                _ => false
            };
        }

        if (tagName.Equals("img", StringComparison.OrdinalIgnoreCase))
        {
            return sanitizedName switch
            {
                "src" => TrySanitizeUrl(sanitizedValue, ImageSchemes, allowFragment: false, out sanitizedValue),
                "alt" => IsSafeTextAttributeValue(sanitizedValue),
                "height" or "width" => IsSafeDimension(sanitizedValue),
                "title" => IsSafeTextAttributeValue(sanitizedValue),
                _ => false
            };
        }

        if (tagName.Equals("table", StringComparison.OrdinalIgnoreCase))
        {
            return sanitizedName switch
            {
                "align" => AlignmentValues.Contains(sanitizedValue),
                "bgcolor" => IsSafeColor(sanitizedValue),
                "border" or "cellpadding" or "cellspacing" or "height" or "width" => IsSafeDimension(sanitizedValue),
                "summary" => IsSafeTextAttributeValue(sanitizedValue),
                _ => false
            };
        }

        if (tagName is "td" or "th")
        {
            return sanitizedName switch
            {
                "align" or "valign" => AlignmentValues.Contains(sanitizedValue),
                "bgcolor" => IsSafeColor(sanitizedValue),
                "colspan" or "rowspan" or "height" or "width" => IsSafeDimension(sanitizedValue),
                "scope" => IsOneOf(sanitizedValue, "col", "colgroup", "row", "rowgroup"),
                _ => false
            };
        }

        if (tagName.Equals("tr", StringComparison.OrdinalIgnoreCase))
        {
            return sanitizedName switch
            {
                "align" or "valign" => AlignmentValues.Contains(sanitizedValue),
                "bgcolor" => IsSafeColor(sanitizedValue),
                _ => false
            };
        }

        if (tagName is "col" or "colgroup")
        {
            return sanitizedName switch
            {
                "span" or "width" => IsSafeDimension(sanitizedValue),
                _ => false
            };
        }

        if (tagName.Equals("font", StringComparison.OrdinalIgnoreCase))
        {
            return sanitizedName switch
            {
                "color" => IsSafeColor(sanitizedValue),
                "face" => IsSafeTextAttributeValue(sanitizedValue),
                "size" => FontSizeRegex().IsMatch(sanitizedValue),
                _ => false
            };
        }

        if (tagName.Equals("body", StringComparison.OrdinalIgnoreCase))
        {
            return sanitizedName switch
            {
                "alink" or "bgcolor" or "link" or "text" or "vlink" => IsSafeColor(sanitizedValue),
                _ => false
            };
        }

        return false;
    }

    private static bool TrySanitizeUrl(
        string value,
        HashSet<string> allowedSchemes,
        bool allowFragment,
        out string sanitizedValue)
    {
        sanitizedValue = value.Trim();

        if (sanitizedValue.Length == 0 ||
            sanitizedValue.StartsWith("//", StringComparison.Ordinal) ||
            sanitizedValue.StartsWith("/", StringComparison.Ordinal))
        {
            return false;
        }

        if (allowFragment && sanitizedValue.StartsWith("#", StringComparison.Ordinal))
        {
            return FragmentRegex().IsMatch(sanitizedValue);
        }

        var decodedUrl = DecodePercentEscapesRepeatedly(DecodeHtmlEntitiesRepeatedly(sanitizedValue));
        if (decodedUrl.Any(IsUnsafeUrlCharacter))
        {
            return false;
        }

        var rawSchemeMatch = RawSchemeRegex().Match(sanitizedValue);
        var canonicalSchemeMatch = RawSchemeRegex().Match(CanonicalizeUrlForSchemeCheck(decodedUrl));

        if (!rawSchemeMatch.Success || !canonicalSchemeMatch.Success)
        {
            return false;
        }

        var rawScheme = rawSchemeMatch.Groups["scheme"].Value;
        var canonicalScheme = canonicalSchemeMatch.Groups["scheme"].Value;
        return rawScheme.Equals(canonicalScheme, StringComparison.OrdinalIgnoreCase) &&
               allowedSchemes.Contains(canonicalScheme);
    }

    private static string CanonicalizeUrlForSchemeCheck(string value)
    {
        var canonical = new StringBuilder(value.Length);

        foreach (var character in value)
        {
            if (!char.IsWhiteSpace(character) && character is not '\u0000' and not '\u200B' and not '\uFEFF')
            {
                canonical.Append(character);
            }
        }

        return canonical.ToString();
    }

    private static string DecodePercentEscapesRepeatedly(string value)
    {
        var current = value;
        for (var pass = 0; pass < MaxDecodePasses; pass++)
        {
            var decoded = PercentEncodingRegex().Replace(current, match =>
                ((char)Convert.ToByte(match.Groups["hex"].Value, 16)).ToString());

            if (decoded == current)
            {
                return current;
            }

            current = decoded;
        }

        return current;
    }

    private static bool TrySanitizeTarget(string value, out string sanitizedValue)
    {
        sanitizedValue = value.ToLowerInvariant();
        return IsOneOf(sanitizedValue, "_blank", "_self", "_parent", "_top");
    }

    private static bool TrySanitizeRel(string value, out string sanitizedValue)
    {
        var safeTokens = value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(token => IsOneOf(token, "noopener", "noreferrer", "nofollow", "ugc", "sponsored"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        sanitizedValue = string.Join(' ', safeTokens).ToLowerInvariant();
        return sanitizedValue.Length > 0;
    }

    private static bool IsOneOf(string value, params string[] allowedValues) =>
        allowedValues.Any(allowedValue => value.Equals(allowedValue, StringComparison.OrdinalIgnoreCase));

    private static bool IsSafeTextAttributeValue(string value) =>
        value.Length <= 512 &&
        value.IndexOf('<') < 0 &&
        value.IndexOf('>') < 0 &&
        value.IndexOf('\u0000') < 0;

    private static bool IsSafeTokenList(string value) =>
        value.Length <= 256 && TokenListRegex().IsMatch(value);

    private static bool IsSafeDimension(string value) =>
        DimensionRegex().IsMatch(value);

    private static bool IsSafeColor(string value) =>
        ColorRegex().IsMatch(value);

    private static bool IsUnsafeUrlCharacter(char character) =>
        char.IsControl(character) ||
        char.IsWhiteSpace(character) ||
        character is '<' or '>' or '"' or '\'';

    private static string DecodeHtmlEntitiesRepeatedly(string value)
    {
        var current = value;
        for (var pass = 0; pass < MaxDecodePasses; pass++)
        {
            var decoded = WebUtility.HtmlDecode(current);
            if (decoded == current)
            {
                return current;
            }

            current = decoded;
        }

        return current;
    }

    private static string RemoveUnsafeControlCharacters(string value)
    {
        var sanitized = new StringBuilder(value.Length);

        foreach (var character in value)
        {
            if (character is '\t' or '\n' or '\r' || character >= ' ')
            {
                sanitized.Append(character);
            }
        }

        return sanitized.ToString();
    }

    private static string NormalizeLineEndings(string value) =>
        value.Replace("\r\n", "\n").Replace('\r', '\n');

    private static bool IsTagNameStart(char character) =>
        character is >= 'A' and <= 'Z' or >= 'a' and <= 'z';

    private static bool IsTagNameCharacter(char character) =>
        IsTagNameStart(character) || character is >= '0' and <= '9';

    private static bool IsAttributeNameStart(char character) =>
        IsTagNameStart(character) || character == ':';

    private static bool IsAttributeNameCharacter(char character) =>
        IsTagNameStart(character) || character is >= '0' and <= '9' or '-' or '_' or ':';

    private static void AppendEncodedCharacter(StringBuilder builder, char character)
    {
        switch (character)
        {
            case '<':
                builder.Append("&lt;");
                break;
            case '>':
                builder.Append("&gt;");
                break;
            case '&':
                builder.Append("&amp;");
                break;
            case '"':
                builder.Append("&quot;");
                break;
            case '\'':
                builder.Append("&#39;");
                break;
            default:
                builder.Append(character);
                break;
        }
    }

    private static string HtmlEncodeAttribute(string value) =>
        WebUtility.HtmlEncode(value).Replace("'", "&#39;", StringComparison.Ordinal);

    [GeneratedRegex(@"^(?<scheme>[a-z][a-z0-9+.-]*):", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RawSchemeRegex();

    [GeneratedRegex(@"%u?0*(?<hex>[0-9a-f]{2})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PercentEncodingRegex();

    [GeneratedRegex(@"^#[A-Za-z][A-Za-z0-9_-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex FragmentRegex();

    [GeneratedRegex(@"^[A-Za-z0-9 _.,-]{1,256}$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenListRegex();

    [GeneratedRegex(@"^\d{1,4}%?$", RegexOptions.CultureInvariant)]
    private static partial Regex DimensionRegex();

    [GeneratedRegex(@"^(#[0-9a-f]{3}(?:[0-9a-f]{3})?|[a-z]{3,20})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ColorRegex();

    [GeneratedRegex(@"^[+-]?\d{1,2}$", RegexOptions.CultureInvariant)]
    private static partial Regex FontSizeRegex();

    private readonly record struct HtmlTag(HtmlTagKind Kind, string Name, bool IsClosing, string RawAttributes);

    private readonly record struct HtmlAttribute(string Name, string Value);

    private enum HtmlTagKind
    {
        Element,
        Comment,
        Declaration
    }
}
