using System.Text.RegularExpressions;
using AngleSharp.Css.Dom;
using AngleSharp.Dom;
using Ganss.Xss;

namespace UploadFileBlazor.Services;

internal static partial class EmailHtmlSanitizer
{
    private const string AdditionalUnsafeCssValuePattern =
        @"(?:expression\s*\(|javascript\s*:|vbscript\s*:|data\s*:|-\s*moz\s*-\s*binding|behavior\s*:)";

    private static readonly Regex DisallowedCssPropertyValueRegex = new(
        $"{HtmlSanitizer.DefaultDisallowedCssPropertyValue}|{AdditionalUnsafeCssValuePattern}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly string[] HttpsSchemes =
    [
        "https"
    ];

    private static readonly string[] AllowedTags =
    [
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
        "head",
        "hr",
        "html",
        "i",
        "img",
        "li",
        "link",
        "meta",
        "ol",
        "p",
        "pre",
        "q",
        "s",
        "small",
        "span",
        "strong",
        "style",
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
    ];

    private static readonly string[] AllowedAttributes =
    [
        "align",
        "alink",
        "alt",
        "aria-describedby",
        "aria-hidden",
        "aria-label",
        "aria-labelledby",
        "aria-live",
        "bgcolor",
        "border",
        "cellpadding",
        "cellspacing",
        "charset",
        "class",
        "color",
        "colspan",
        "content",
        "crossorigin",
        "dir",
        "face",
        "height",
        "http-equiv",
        "href",
        "id",
        "lang",
        "link",
        "media",
        "name",
        "rel",
        "role",
        "rowspan",
        "scope",
        "size",
        "span",
        "src",
        "style",
        "summary",
        "target",
        "text",
        "title",
        "type",
        "valign",
        "vlink",
        "width"
    ];

    private static readonly string[] UriAttributes =
    [
        "href",
        "src"
    ];

    private static readonly string[] AllowedSchemes =
    [
        "cid",
        "https",
        "mailto",
        "tel"
    ];

    private static readonly HashSet<string> AnchorSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "https",
        "mailto",
        "tel"
    };

    private static readonly HashSet<string> ImageSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "cid",
        "https"
    };

    private static readonly HashSet<string> AllowedTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "_blank",
        "_parent",
        "_self",
        "_top"
    };

    private static readonly string[] AllowedRelTokens =
    [
        "noopener",
        "noreferrer",
        "nofollow",
        "ugc",
        "sponsored"
    ];

    private static readonly string[] AllowedLinkRelTokenOrder =
    [
        "stylesheet",
        "preconnect",
        "dns-prefetch"
    ];

    private static readonly HashSet<string> AllowedLinkRelTokens = new(AllowedLinkRelTokenOrder, StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> AllowedFontStylesheetHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "fonts.googleapis.com"
    };

    private static readonly HashSet<string> AllowedFontPreconnectHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "fonts.googleapis.com",
        "fonts.gstatic.com"
    };

    private static readonly HashSet<string> AllowedMetaNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "color-scheme",
        "format-detection",
        "supported-color-schemes",
        "viewport",
        "x-apple-disable-message-reformatting"
    };

    private static readonly HashSet<string> AllowedHttpEquivValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "content-type",
        "x-ua-compatible"
    };

    private static readonly CssRuleType[] AllowedAtRules =
    [
        CssRuleType.Style,
        CssRuleType.Media
    ];

    private static readonly string[] AdditionalEmailCssProperties =
    [
        "-ms-text-size-adjust",
        "-webkit-text-size-adjust",
        "font-size",
        "mso-hide",
        "mso-line-height-rule",
        "mso-padding-alt",
        "mso-table-lspace",
        "mso-table-rspace",
        "text-size-adjust"
    ];

    public static string Sanitize(string html)
    {
        var sanitizer = CreateSanitizer();
        var sanitized = FullDocumentHintRegex().IsMatch(html)
            ? sanitizer.SanitizeDocument(html)
            : sanitizer.Sanitize(html);

        return sanitized.Trim();
    }

    private static HtmlSanitizer CreateSanitizer()
    {
        var sanitizer = new HtmlSanitizer
        {
            AllowCssCustomProperties = false,
            AllowDataAttributes = false,
            DisallowCssPropertyValue = DisallowedCssPropertyValueRegex,
            KeepChildNodes = false
        };

        ReplaceAllowedValues(sanitizer.AllowedTags, AllowedTags);
        ReplaceAllowedValues(sanitizer.AllowedAttributes, AllowedAttributes);
        ReplaceAllowedValues(sanitizer.AllowedSchemes, AllowedSchemes);
        ReplaceAllowedValues(sanitizer.UriAttributes, UriAttributes);
        ReplaceAllowedValues(sanitizer.AllowedAtRules, AllowedAtRules);

        foreach (var property in AdditionalEmailCssProperties)
        {
            sanitizer.AllowedCssProperties.Add(property);
        }

        sanitizer.FilterUrl += (_, args) =>
        {
            if (!IsSafeUrl(args.SanitizedUrl, AllowedSchemes, allowFragment: true))
            {
                args.SanitizedUrl = null;
            }
        };

        sanitizer.PostProcessNode += (_, args) =>
        {
            if (args.Node is not IElement element)
            {
                return;
            }

            RemoveUnexpectedUriAttributes(element);
            SanitizeMetaElement(element);
            SanitizeLinkElement(element);
            RemoveContextualAttributes(element);
            HardenAnchor(element);
        };

        return sanitizer;
    }

    private static void ReplaceAllowedValues<T>(ISet<T> values, IEnumerable<T> allowedValues)
    {
        values.Clear();
        foreach (var allowedValue in allowedValues)
        {
            values.Add(allowedValue);
        }
    }

    private static void RemoveUnexpectedUriAttributes(IElement element)
    {
        var tagName = element.LocalName;

        if (element.GetAttribute("href") is { } href &&
            !IsExpectedHrefAttribute(tagName, href))
        {
            element.RemoveAttribute("href");
        }

        if (element.GetAttribute("src") is { } src &&
            (!tagName.Equals("img", StringComparison.OrdinalIgnoreCase) ||
             !IsSafeUrl(src, ImageSchemes, allowFragment: false)))
        {
            element.RemoveAttribute("src");
        }
    }

    private static bool IsExpectedHrefAttribute(string tagName, string href) =>
        tagName.Equals("a", StringComparison.OrdinalIgnoreCase)
            ? IsSafeUrl(href, AnchorSchemes, allowFragment: true)
            : tagName.Equals("link", StringComparison.OrdinalIgnoreCase) && IsSafeFontLinkHref(href, out _);

    private static void SanitizeMetaElement(IElement element)
    {
        if (!element.LocalName.Equals("meta", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (!TrySanitizeMetaElement(element))
        {
            RemoveElement(element);
        }
    }

    private static bool TrySanitizeMetaElement(IElement element)
    {
        var charset = element.GetAttribute("charset");
        var name = element.GetAttribute("name");
        var httpEquiv = element.GetAttribute("http-equiv");
        var content = element.GetAttribute("content");

        if (charset is not null)
        {
            if (name is not null ||
                httpEquiv is not null ||
                !charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            RemoveAttributesExcept(element, "charset");
            element.SetAttribute("charset", "utf-8");
            return true;
        }

        if (name is not null)
        {
            if (httpEquiv is not null)
            {
                return false;
            }

            name = name.Trim().ToLowerInvariant();
            if (!AllowedMetaNames.Contains(name) || !IsSafeMetaNameContent(name, content))
            {
                return false;
            }

            RemoveAttributesExcept(element, "name", "content");
            element.SetAttribute("name", name);
            return true;
        }

        if (httpEquiv is not null)
        {
            httpEquiv = httpEquiv.Trim().ToLowerInvariant();
            if (!AllowedHttpEquivValues.Contains(httpEquiv) || !IsSafeHttpEquivContent(httpEquiv, content))
            {
                return false;
            }

            RemoveAttributesExcept(element, "http-equiv", "content");
            element.SetAttribute("http-equiv", httpEquiv);
            return true;
        }

        return false;
    }

    private static bool IsSafeMetaNameContent(string name, string? content) =>
        name switch
        {
            "color-scheme" or "supported-color-schemes" =>
                content is not null && ColorSchemeMetaContentRegex().IsMatch(content),
            "format-detection" =>
                content is not null && FormatDetectionMetaContentRegex().IsMatch(content),
            "viewport" =>
                content is not null && ViewportMetaContentRegex().IsMatch(content),
            "x-apple-disable-message-reformatting" =>
                content is null || SafeShortMetaContentRegex().IsMatch(content),
            _ => false
        };

    private static bool IsSafeHttpEquivContent(string httpEquiv, string? content) =>
        httpEquiv switch
        {
            "content-type" => content is not null && ContentTypeMetaContentRegex().IsMatch(content),
            "x-ua-compatible" => content is not null && XUaCompatibleMetaContentRegex().IsMatch(content),
            _ => false
        };

    private static void SanitizeLinkElement(IElement element)
    {
        if (!element.LocalName.Equals("link", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (!TrySanitizeLinkElement(element))
        {
            RemoveElement(element);
        }
    }

    private static bool TrySanitizeLinkElement(IElement element)
    {
        if (!IsSafeFontLinkHref(element.GetAttribute("href"), out var hrefUri))
        {
            return false;
        }

        var relTokens = GetAllowedLinkRelTokens(element.GetAttribute("rel"));
        if (relTokens.Count == 0)
        {
            return false;
        }

        var isStylesheet = relTokens.Contains("stylesheet");
        var allowedHosts = isStylesheet ? AllowedFontStylesheetHosts : AllowedFontPreconnectHosts;
        if (!allowedHosts.Contains(hrefUri.Host))
        {
            return false;
        }

        if (element.GetAttribute("type") is { } type &&
            !type.Equals("text/css", StringComparison.OrdinalIgnoreCase))
        {
            element.RemoveAttribute("type");
        }

        if (element.GetAttribute("media") is { } media &&
            !MediaAttributeRegex().IsMatch(media))
        {
            element.RemoveAttribute("media");
        }

        if (element.GetAttribute("crossorigin") is { } crossorigin)
        {
            if (crossorigin.Length == 0 ||
                crossorigin.Equals("anonymous", StringComparison.OrdinalIgnoreCase))
            {
                element.SetAttribute("crossorigin", "anonymous");
            }
            else
            {
                element.RemoveAttribute("crossorigin");
            }
        }

        RemoveAttributesExcept(element, "href", "rel", "media", "type", "crossorigin");
        element.SetAttribute("rel", string.Join(' ', AllowedLinkRelTokenOrder.Where(relTokens.Contains)));
        return true;
    }

    private static HashSet<string> GetAllowedLinkRelTokens(string? rel)
    {
        var relTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var token in (rel ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!AllowedLinkRelTokens.Contains(token))
            {
                relTokens.Clear();
                return relTokens;
            }

            relTokens.Add(token);
        }

        return relTokens;
    }

    private static bool IsSafeFontLinkHref(string? href, out Uri hrefUri)
    {
        hrefUri = null!;
        if (!IsSafeUrl(href, HttpsSchemes, allowFragment: false) ||
            !Uri.TryCreate(href!.Trim(), UriKind.Absolute, out var parsedUri) ||
            parsedUri is null)
        {
            return false;
        }

        hrefUri = parsedUri;
        return true;
    }

    private static void RemoveAttributesExcept(IElement element, params string[] allowedAttributes)
    {
        var allowed = new HashSet<string>(allowedAttributes, StringComparer.OrdinalIgnoreCase);
        foreach (var attribute in element.Attributes.ToArray())
        {
            if (!allowed.Contains(attribute.Name))
            {
                element.RemoveAttribute(attribute.Name);
            }
        }
    }

    private static void RemoveContextualAttributes(IElement element)
    {
        var tagName = element.LocalName;

        if (!tagName.Equals("meta", StringComparison.OrdinalIgnoreCase))
        {
            element.RemoveAttribute("charset");
            element.RemoveAttribute("content");
            element.RemoveAttribute("http-equiv");
        }

        if (!tagName.Equals("link", StringComparison.OrdinalIgnoreCase))
        {
            element.RemoveAttribute("crossorigin");
        }

        if (!tagName.Equals("a", StringComparison.OrdinalIgnoreCase) &&
            !tagName.Equals("link", StringComparison.OrdinalIgnoreCase))
        {
            element.RemoveAttribute("rel");
        }
    }

    private static void RemoveElement(IElement element)
    {
        element.Parent?.RemoveChild(element);
    }

    private static void HardenAnchor(IElement element)
    {
        if (!element.LocalName.Equals("a", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var target = element.GetAttribute("target");
        if (target is not null && !AllowedTargets.Contains(target))
        {
            element.RemoveAttribute("target");
            target = null;
        }

        if (target is not null)
        {
            target = target.ToLowerInvariant();
            element.SetAttribute("target", target);
        }

        var relTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var token in (element.GetAttribute("rel") ?? string.Empty)
                     .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (AllowedRelTokens.Contains(token, StringComparer.OrdinalIgnoreCase))
            {
                relTokens.Add(token);
            }
        }

        if (target is "_blank")
        {
            relTokens.Add("noopener");
            relTokens.Add("noreferrer");
        }

        if (relTokens.Count == 0)
        {
            element.RemoveAttribute("rel");
            return;
        }

        element.SetAttribute("rel", string.Join(' ', AllowedRelTokens.Where(relTokens.Contains)));
    }

    private static bool IsSafeUrl(string? value, IEnumerable<string> allowedSchemes, bool allowFragment)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var sanitizedValue = value.Trim();
        if (sanitizedValue.StartsWith("//", StringComparison.Ordinal) ||
            sanitizedValue.StartsWith("/", StringComparison.Ordinal) ||
            UnsafeUrlCharacterRegex().IsMatch(sanitizedValue) ||
            UnsafePercentEncodingRegex().IsMatch(sanitizedValue))
        {
            return false;
        }

        if (allowFragment && FragmentRegex().IsMatch(sanitizedValue))
        {
            return true;
        }

        return Uri.TryCreate(sanitizedValue, UriKind.Absolute, out var uri) &&
               allowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"<(?:!doctype|html|head|body)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FullDocumentHintRegex();

    [GeneratedRegex(@"[\u0000-\u001F\u007F\s<>""']")]
    private static partial Regex UnsafeUrlCharacterRegex();

    [GeneratedRegex(@"%(?:0[0-9a-f]|1[0-9a-f]|20|22|27|3c|3e|7f)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafePercentEncodingRegex();

    [GeneratedRegex(@"^#[A-Za-z][A-Za-z0-9_-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex FragmentRegex();

    [GeneratedRegex(@"^(?:light|dark|only light)(?:\s+(?:light|dark))*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ColorSchemeMetaContentRegex();

    [GeneratedRegex(@"^[A-Za-z-]+=(?:yes|no)(?:\s*,\s*[A-Za-z-]+=(?:yes|no))*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FormatDetectionMetaContentRegex();

    [GeneratedRegex(@"^[A-Za-z0-9\s,=._:%+-]{1,256}$", RegexOptions.CultureInvariant)]
    private static partial Regex ViewportMetaContentRegex();

    [GeneratedRegex(@"^[A-Za-z0-9\s,=._:%+-]{0,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeShortMetaContentRegex();

    [GeneratedRegex(@"^text/html\s*;\s*charset\s*=\s*utf-8$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ContentTypeMetaContentRegex();

    [GeneratedRegex(@"^ie=edge$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex XUaCompatibleMetaContentRegex();

    [GeneratedRegex(@"^[A-Za-z0-9\s,=._:%()+-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex MediaAttributeRegex();
}
