using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components.Forms;
using UploadFileBlazor.Services;
using Xunit;

namespace UploadFileBlazor.Tests;

public sealed class UploadedFileProcessorTests
{
    [Fact]
    public async Task SanitizesCommonEmailMarkup()
    {
        const string html =
            "<h1 id=\"hero\" class=\"primary-title\" onclick=\"evil()\">Hi &amp; welcome</h1>" +
            "<p style=\"color:red\">Hello <strong>{{FirstName}}</strong><br>" +
            "<a href=\"https://example.com/welcome?x=1&amp;y=2\" target=\"_blank\" rel=\"noopener external\">Start</a></p>" +
            "<table width=\"100%\" onclick=\"evil()\"><tr><td align=\"center\">Body</td></tr></table>";

        var processed = await ProcessHtmlAsync(html);

        Assert.True(processed.WasHtml, "HTML extension should mark the upload as HTML.");
        AssertContains("<h1", processed.Text);
        AssertContains("id=\"hero\"", processed.Text);
        AssertContains("class=\"primary-title\"", processed.Text);
        AssertContains("Hi &amp; welcome", processed.Text);
        AssertContains("style=", processed.Text);
        AssertContains("color:", processed.Text);
        AssertContains("Hello <strong>{{FirstName}}</strong>", processed.Text);
        AssertContains("href=\"https://example.com/welcome?x=1&amp;y=2\"", processed.Text);
        AssertContains("target=\"_blank\"", processed.Text);
        AssertContains("rel=\"noopener noreferrer\"", processed.Text);
        AssertContains("width=\"100%\"", processed.Text);
        AssertContains("align=\"center\"", processed.Text);
        AssertDoesNotContain("onclick", processed.Text);
        AssertNoExecutableHtml(processed.Text);
    }

    [Fact]
    public async Task LeavesPlainTextUploadsAsText()
    {
        const string text = "<script>alert(1)</script>\nHello {{FirstName}}";
        var processed = await ProcessTextAsync(text);

        Assert.False(processed.WasHtml, "txt extension should remain plain text.");
        Assert.Equal(text, processed.Text);
    }

    [Fact]
    public async Task RemovesUnsafeControlCharactersFromTextUploads()
    {
        var processed = await ProcessTextAsync("Hello\u007F \u0085World");

        Assert.Equal("Hello World", processed.Text);
    }

    [Fact]
    public async Task StripsScriptAndActiveContentAttackCorpus()
    {
        var attacks = new[]
        {
            "<p>Before</p><script>alert(1)</script><p>After</p>",
            "&#60;script&#62;alert(1)&#60;/script&#62;<p>Safe</p>",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;<p>Safe</p>",
            "&amp;#x3C;script&amp;#x3E;alert(1)&amp;#x3C;/script&amp;#x3E;<p>Safe</p>",
            "<scr\u0000ipt>alert(1)</scr\u0000ipt><p>Safe</p>",
            "<script>alert(1)<p>Unclosed script loses the rest",
            "<iframe srcdoc=\"<script>alert(1)</script>\">Fallback</iframe><p>Safe</p>",
            "<object data=\"https://example.com/payload.swf\">Fallback</object><p>Safe</p>",
            "<embed src=\"https://example.com/payload.swf\"><p>Safe</p>",
            "<svg><a xlink:href=\"javascript:alert(1)\">x</a></svg><p>Safe</p>",
            "<math href=\"javascript:alert(1)\">x</math><p>Safe</p>",
            "<template><img src=x onerror=alert(1)></template><p>Safe</p>",
            "<form action=\"https://example.com\"><button formaction=\"javascript:alert(1)\">Send</button></form><p>Safe</p>",
            "<base href=\"javascript:alert(1)\"><link rel=\"stylesheet\" href=\"javascript:alert(1)\"><meta http-equiv=\"refresh\" content=\"0;javascript:alert(1)\"><p>Safe</p>",
            "<!--[if mso]><script>alert(1)</script><![endif]--><p>Safe</p>"
        };

        foreach (var attack in attacks)
        {
            var processed = await ProcessHtmlAsync(attack);
            AssertNoExecutableHtml(processed.Text);
        }
    }

    [Fact]
    public async Task StripsDangerousUrlAttackCorpus()
    {
        var attacks = new[]
        {
            "<a href=\"javascript:alert(1)\">Click</a>",
            "<a href=\"JaVaScRiPt:alert(1)\">Click</a>",
            "<a href=\"&#106;&#97;vascript:alert(1)\">Click</a>",
            "<a href=\"jav&#x61;script:alert(1)\">Click</a>",
            "<a href=\"jav&#x0A;ascript:alert(1)\">Click</a>",
            "<a href=\"java%0ascript:alert(1)\">Click</a>",
            "<a href=\"jav%61script:alert(1)\">Click</a>",
            "<a href=\"%6a%61%76%61%73%63%72%69%70%74:alert(1)\">Click</a>",
            "<a href=\"vbscript:msgbox(1)\">Click</a>",
            "<a href=\"data:text/html,<script>alert(1)</script>\">Click</a>",
            "<a href=\"file:///etc/passwd\">Click</a>",
            "<a href=\"http://example.com\">Click</a>",
            "<a href=\"//example.com/path\">Click</a>",
            "<a href=\"/relative/path\">Click</a>",
            "<a href=\"https://example.com/%0d%0aSet-Cookie:bad=true\">Click</a>",
            "<a href=\"mailto:support@example.com?subject=Hi%0ABcc:attacker@example.com\">Click</a>",
            "<a href=\"https://example.com/%3Cscript%3Ealert(1)%3C/script%3E\">Click</a>",
            "<img src=\"javascript:alert(1)\" alt=\"Logo\">",
            "<img src=\"data:image/svg+xml,<svg onload=alert(1)>\" alt=\"Logo\">",
            "<img src=\"http://example.com/logo.png\" alt=\"Logo\">"
        };

        foreach (var attack in attacks)
        {
            var processed = await ProcessHtmlAsync(attack);
            AssertNoExecutableHtml(processed.Text);
            AssertDoesNotMatch("\\s(?:href|src)=\"(?:javascript|vbscript|data|file|http):", processed.Text);
        }
    }

    [Fact]
    public async Task SanitizesCssAndStyleAttackCorpus()
    {
        var attacks = new[]
        {
            "<style>body{background:url(javascript:alert(1))}</style><p>Safe</p>",
            "<p style=\"background:url(javascript:alert(1))\">Safe</p>",
            "<p style=\"width:expression(alert(1))\">Safe</p>",
            "<div style=\"-moz-binding:url(https://example.com/xss.xml#xss)\">Safe</div>",
            "<table style=\"background-image:url(data:text/html,<script>alert(1)</script>)\"><tr><td>Safe</td></tr></table>"
        };

        foreach (var attack in attacks)
        {
            var processed = await ProcessHtmlAsync(attack);
            AssertNoExecutableHtml(processed.Text);
            AssertDoesNotContain("javascript:", processed.Text);
            AssertDoesNotContain("vbscript:", processed.Text);
            AssertDoesNotContain("data:text/html", processed.Text);
            AssertDoesNotContain("expression(", processed.Text);
            AssertDoesNotContain("-moz-binding", processed.Text);
        }
    }

    [Fact]
    public async Task PreservesSafeStyleTagsAndInlineStyleAttributes()
    {
        const string html =
            "<!doctype html><html><head>" +
            "<style>p{color:#123456;margin:0}@media screen and (max-width:600px){.hero{font-size:20px}}</style>" +
            "</head><body>" +
            "<p class=\"hero\" style=\"color:red;margin:0;mso-line-height-rule:exactly\">Safe</p>" +
            "</body></html>";

        var processed = await ProcessHtmlAsync(html);

        AssertContains("<style", processed.Text);
        AssertContains("</style>", processed.Text);
        AssertContains("color:", processed.Text);
        AssertContains("margin:", processed.Text);
        AssertContains("@media", processed.Text);
        AssertContains("font-size:", processed.Text);
        AssertContains("style=", processed.Text);
        AssertContains("mso-line-height-rule", processed.Text);
        AssertNoExecutableHtml(processed.Text);
    }

    [Fact]
    public async Task PreservesSafeEmailFontLinkAndMetaTags()
    {
        const string html =
            "<!doctype html><html><head>" +
            "<meta charset=\"UTF-8\">" +
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" +
            "<meta name=\"x-apple-disable-message-reformatting\">" +
            "<meta name=\"format-detection\" content=\"telephone=no, date=no, address=no, email=no\">" +
            "<meta name=\"color-scheme\" content=\"light dark\">" +
            "<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>" +
            "<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;700&amp;display=swap\" media=\"screen\">" +
            "</head><body><p style=\"font-family:Inter, Arial\">Safe</p></body></html>";

        var processed = await ProcessHtmlAsync(html);

        AssertContains("<meta", processed.Text);
        AssertContains("charset=\"utf-8\"", processed.Text);
        AssertContains("name=\"viewport\"", processed.Text);
        AssertContains("width=device-width", processed.Text);
        AssertContains("name=\"x-apple-disable-message-reformatting\"", processed.Text);
        AssertContains("name=\"format-detection\"", processed.Text);
        AssertContains("name=\"color-scheme\"", processed.Text);
        AssertContains("<link", processed.Text);
        AssertContains("rel=\"preconnect\"", processed.Text);
        AssertContains("href=\"https://fonts.gstatic.com\"", processed.Text);
        AssertContains("crossorigin=\"anonymous\"", processed.Text);
        AssertContains("rel=\"stylesheet\"", processed.Text);
        AssertContains("href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;700&amp;display=swap\"", processed.Text);
        AssertContains("media=\"screen\"", processed.Text);
        AssertNoExecutableHtml(processed.Text);
    }

    [Fact]
    public async Task StripsDangerousMetaAndExternalLinkTags()
    {
        const string html =
            "<!doctype html><html><head>" +
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">" +
            "<meta name=\"viewport\" content=\"width=device-width;javascript:alert(1)\">" +
            "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">" +
            "<link rel=\"stylesheet\" href=\"http://fonts.googleapis.com/css2?family=Inter\">" +
            "<link rel=\"stylesheet\" href=\"https://evil.example/email.css\">" +
            "<link rel=\"preload\" href=\"https://fonts.googleapis.com/css2?family=Inter\">" +
            "</head><body><p>Safe</p></body></html>";

        var processed = await ProcessHtmlAsync(html);

        AssertDoesNotContain("<meta", processed.Text);
        AssertDoesNotContain("<link", processed.Text);
        AssertDoesNotContain("http-equiv", processed.Text);
        AssertDoesNotContain("refresh", processed.Text);
        AssertDoesNotContain("evil.example", processed.Text);
        AssertDoesNotContain("fonts.googleapis.com", processed.Text);
        AssertNoExecutableHtml(processed.Text);
    }

    [Fact]
    public async Task StripsDangerousAttributeAttackCorpus()
    {
        var attacks = new[]
        {
            "<img src=\"https://example.com/logo.png\" onerror=\"alert(1)\" alt=\"Logo\">",
            "<img src=\"https://example.com/logo.png\" o&#110;error=\"alert(1)\" alt=\"Logo\">",
            "<img src=\"https://example.com/logo.png\" onload=alert(1) alt=\"Logo\">",
            "<body onload=\"alert(1)\" bgcolor=\"#fff\">Hello</body>",
            "<p formaction=\"javascript:alert(1)\" action=\"javascript:alert(1)\" srcdoc=\"<script>alert(1)</script>\">Safe</p>",
            "<a xlink:href=\"javascript:alert(1)\" href=\"https://example.com\">Safe</a>",
            "<img dynsrc=\"javascript:alert(1)\" lowsrc=\"javascript:alert(1)\" srcset=\"javascript:alert(1) 1x\" alt=\"Logo\">",
            "<p data-danger=\"javascript:alert(1)\" aria-label=\"Safe label\">Safe</p>",
            "<p id=\"safe\" id=\"javascript:alert(1)\" class=\"email body\">Safe</p>"
        };

        foreach (var attack in attacks)
        {
            var processed = await ProcessHtmlAsync(attack);
            AssertNoExecutableHtml(processed.Text);
        }
    }

    [Fact]
    public async Task KeepsOnlyConservativeSafeEmailUrls()
    {
        var processed = await ProcessHtmlAsync(
            "<a href=\"https://example.com?a=1&amp;b=2\" target=\"_blank\">Web</a>" +
            "<a href=\"mailto:support@example.com\">Mail</a>" +
            "<a href=\"tel:+48123456789\">Phone</a>" +
            "<a href=\"#intro\">Fragment</a>" +
            "<img src=\"https://example.com/logo.png\" width=\"200\" height=\"100\" alt=\"Logo\">" +
            "<img src=\"cid:logo-image\" alt=\"Inline logo\">");

        AssertContains("href=\"https://example.com?a=1&amp;b=2\"", processed.Text);
        AssertContains("target=\"_blank\" rel=\"noopener noreferrer\"", processed.Text);
        AssertContains("href=\"mailto:support@example.com\"", processed.Text);
        AssertContains("href=\"tel:+48123456789\"", processed.Text);
        AssertContains("href=\"#intro\"", processed.Text);
        AssertContains("src=\"https://example.com/logo.png\"", processed.Text);
        AssertContains("width=\"200\"", processed.Text);
        AssertContains("height=\"100\"", processed.Text);
        AssertContains("alt=\"Logo\"", processed.Text);
        AssertContains("src=\"cid:logo-image\"", processed.Text);
        AssertContains("alt=\"Inline logo\"", processed.Text);
        AssertNoExecutableHtml(processed.Text);
    }

    [Fact]
    public async Task ForcesNoopenerAndNoreferrerForBlankTargets()
    {
        var processed = await ProcessHtmlAsync(
            "<a href=\"https://example.com\" target=\"_blank\" rel=\"nofollow opener\">Open</a>");

        AssertContains("target=\"_blank\"", processed.Text);
        AssertContains("rel=\"noopener noreferrer nofollow\"", processed.Text);
        AssertNoExecutableHtml(processed.Text);
    }

    [Fact]
    public async Task RejectsInvalidUtf8()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ProcessBytesAsync("template.html", "text/html", [0xC0, 0xAF]));
    }

    [Fact]
    public async Task RejectsUnsupportedExtensions()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new UploadedFileProcessor().ProcessAsync(new TestBrowserFile("template.svg", "image/svg+xml", Encoding.UTF8.GetBytes("<svg></svg>"))));
    }

    [Fact]
    public async Task NormalizesUntrustedFileNameAndContentTypeMetadata()
    {
        var processed = await ProcessBytesAsync(@"C:\fakepath\<template>.HTML", "image/svg+xml", Encoding.UTF8.GetBytes("<p>Safe</p>"));

        Assert.Equal("_template_.HTML", processed.FileName);
        Assert.Equal("text/html", processed.ContentType);
        Assert.True(processed.WasHtml);
    }

    [Fact]
    public async Task RejectsEmptyFiles()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new UploadedFileProcessor().ProcessAsync(new TestBrowserFile("empty.html", "text/html", [])));
    }

    [Fact]
    public async Task RejectsOversizedFilesBeforeReading()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new UploadedFileProcessor().ProcessAsync(new TestBrowserFile("huge.html", "text/html", Encoding.UTF8.GetBytes("x"), UploadedFileProcessor.MaxFileSize + 1)));
    }

    [Fact]
    public async Task RejectsStreamsThatExceedLimitEvenWhenReportedSizeIsSmaller()
    {
        var bytes = new byte[(int)UploadedFileProcessor.MaxFileSize + 1];

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new UploadedFileProcessor().ProcessAsync(new TestBrowserFile("huge.html", "text/html", bytes, reportedSize: 1)));
    }

    private static async Task<ProcessedUpload> ProcessHtmlAsync(string html) =>
        await ProcessBytesAsync("template.html", "text/html", Encoding.UTF8.GetBytes(html));

    private static async Task<ProcessedUpload> ProcessTextAsync(string text) =>
        await ProcessBytesAsync("template.txt", "text/plain", Encoding.UTF8.GetBytes(text));

    private static async Task<ProcessedUpload> ProcessBytesAsync(string name, string contentType, byte[] bytes)
    {
        var file = new TestBrowserFile(name, contentType, bytes);
        return await new UploadedFileProcessor().ProcessAsync(file);
    }

    private static void AssertNoExecutableHtml(string html)
    {
        var forbiddenFragments = new[]
        {
            "<script",
            "</script",
            "<iframe",
            "<object",
            "<embed",
            "<svg",
            "<math",
            "<form",
            "<input",
            "<button",
            "<textarea",
            "<base",
            "srcdoc",
            "formaction",
            "xlink:href",
            "http-equiv=\"refresh",
            "@import",
            "javascript:",
            "vbscript:",
            "data:",
            "expression(",
            "-moz-binding",
            "behavior:",
            "url(javascript:"
        };

        foreach (var fragment in forbiddenFragments)
        {
            AssertDoesNotContain(fragment, html);
        }

        AssertDoesNotMatch("<[^>]+\\son[a-z0-9_:-]*\\s*=", html);
    }

    private static void AssertContains(string expectedFragment, string actual) =>
        Assert.Contains(expectedFragment, actual, StringComparison.Ordinal);

    private static void AssertDoesNotContain(string forbiddenFragment, string actual) =>
        Assert.DoesNotContain(forbiddenFragment, actual, StringComparison.OrdinalIgnoreCase);

    private static void AssertDoesNotMatch(string pattern, string actual)
    {
        Assert.False(
            Regex.IsMatch(actual, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant),
            $"Expected output not to match '{pattern}', got '{actual}'.");
    }

    private sealed class TestBrowserFile : IBrowserFile
    {
        private readonly byte[] bytes;
        private readonly long reportedSize;

        public TestBrowserFile(string name, string contentType, byte[] bytes, long? reportedSize = null)
        {
            Name = name;
            ContentType = contentType;
            this.bytes = bytes;
            this.reportedSize = reportedSize ?? bytes.Length;
        }

        public string Name { get; }

        public DateTimeOffset LastModified { get; } = DateTimeOffset.UtcNow;

        public long Size => reportedSize;

        public string ContentType { get; }

        public Stream OpenReadStream(long maxAllowedSize = 512000, CancellationToken cancellationToken = default)
        {
            if (Size > maxAllowedSize)
            {
                throw new IOException("The fake file is larger than the allowed size.");
            }

            return new MemoryStream(bytes, writable: false);
        }
    }
}
