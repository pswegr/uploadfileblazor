using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components.Forms;
using UploadFileBlazor.Services;

var tests = new (string Name, Func<Task> Run)[]
{
    ("sanitizes common email markup while keeping safe structure", SanitizesCommonEmailMarkup),
    ("leaves txt uploads as untrusted plain text", LeavesPlainTextUploadsAsText),
    ("strips script and active content attack corpus", StripsScriptAndActiveContentAttackCorpus),
    ("strips dangerous url attack corpus", StripsDangerousUrlAttackCorpus),
    ("strips css and style attack corpus", StripsCssAndStyleAttackCorpus),
    ("strips dangerous attribute attack corpus", StripsDangerousAttributeAttackCorpus),
    ("keeps only conservative safe email urls", KeepsOnlyConservativeSafeEmailUrls),
    ("rejects invalid utf8", RejectsInvalidUtf8),
    ("rejects unsupported extensions", RejectsUnsupportedExtensions),
    ("rejects empty files", RejectsEmptyFiles),
    ("rejects oversized files before reading", RejectsOversizedFilesBeforeReading)
};

var failures = new List<string>();

foreach (var test in tests)
{
    try
    {
        await test.Run();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception exception)
    {
        failures.Add($"{test.Name}: {exception.Message}");
        Console.WriteLine($"FAIL {test.Name}");
        Console.WriteLine(exception);
    }
}

if (failures.Count > 0)
{
    Console.WriteLine();
    Console.WriteLine("Failed tests:");
    foreach (var failure in failures)
    {
        Console.WriteLine($"- {failure}");
    }

    Environment.Exit(1);
}

Console.WriteLine();
Console.WriteLine($"All {tests.Length} tests passed.");

static async Task SanitizesCommonEmailMarkup()
{
    const string html =
        "<h1 id=\"hero\" class=\"primary-title\" onclick=\"evil()\">Hi &amp; welcome</h1>" +
        "<p style=\"color:red\">Hello <strong>{{FirstName}}</strong><br>" +
        "<a href=\"https://example.com/welcome?x=1&amp;y=2\" target=\"_blank\" rel=\"noopener external\">Start</a></p>" +
        "<table width=\"100%\" onclick=\"evil()\"><tr><td align=\"center\">Body</td></tr></table>";

    var processed = await ProcessHtmlAsync(html);

    AssertTrue(processed.WasHtml, "HTML extension should mark the upload as HTML.");
    AssertContains("<h1 id=\"hero\" class=\"primary-title\">Hi &amp; welcome</h1>", processed.Text);
    AssertContains("<p>Hello <strong>{{FirstName}}</strong><br><a href=\"https://example.com/welcome?x=1&amp;y=2\" target=\"_blank\" rel=\"noopener\">Start</a></p>", processed.Text);
    AssertContains("<table width=\"100%\"><tr><td align=\"center\">Body</td></tr></table>", processed.Text);
    AssertNoExecutableHtml(processed.Text);
}

static async Task LeavesPlainTextUploadsAsText()
{
    const string text = "<script>alert(1)</script>\nHello {{FirstName}}";
    var processed = await ProcessTextAsync(text);

    AssertFalse(processed.WasHtml, "txt extension should remain plain text.");
    AssertEqual(text, processed.Text);
}

static async Task StripsScriptAndActiveContentAttackCorpus()
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

static async Task StripsDangerousUrlAttackCorpus()
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

static async Task StripsCssAndStyleAttackCorpus()
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
        AssertDoesNotContain("style=", processed.Text);
    }
}

static async Task StripsDangerousAttributeAttackCorpus()
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

static async Task KeepsOnlyConservativeSafeEmailUrls()
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
    AssertContains("<img src=\"https://example.com/logo.png\" width=\"200\" height=\"100\" alt=\"Logo\">", processed.Text);
    AssertContains("<img src=\"cid:logo-image\" alt=\"Inline logo\">", processed.Text);
    AssertNoExecutableHtml(processed.Text);
}

static async Task RejectsInvalidUtf8()
{
    await AssertThrowsAsync<InvalidDataException>(() =>
        ProcessBytesAsync("template.html", "text/html", [0xC0, 0xAF]));
}

static async Task RejectsUnsupportedExtensions()
{
    await AssertThrowsAsync<InvalidDataException>(() =>
        new UploadedFileProcessor().ProcessAsync(new TestBrowserFile("template.svg", "image/svg+xml", Encoding.UTF8.GetBytes("<svg></svg>"))));
}

static async Task RejectsEmptyFiles()
{
    await AssertThrowsAsync<InvalidDataException>(() =>
        new UploadedFileProcessor().ProcessAsync(new TestBrowserFile("empty.html", "text/html", [])));
}

static async Task RejectsOversizedFilesBeforeReading()
{
    await AssertThrowsAsync<InvalidDataException>(() =>
        new UploadedFileProcessor().ProcessAsync(new TestBrowserFile("huge.html", "text/html", Encoding.UTF8.GetBytes("x"), UploadedFileProcessor.MaxFileSize + 1)));
}

static async Task<ProcessedUpload> ProcessHtmlAsync(string html) =>
    await ProcessBytesAsync("template.html", "text/html", Encoding.UTF8.GetBytes(html));

static async Task<ProcessedUpload> ProcessTextAsync(string text) =>
    await ProcessBytesAsync("template.txt", "text/plain", Encoding.UTF8.GetBytes(text));

static async Task<ProcessedUpload> ProcessBytesAsync(string name, string contentType, byte[] bytes)
{
    var file = new TestBrowserFile(name, contentType, bytes);
    return await new UploadedFileProcessor().ProcessAsync(file);
}

static void AssertNoExecutableHtml(string html)
{
    var forbiddenFragments = new[]
    {
        "<script",
        "</script",
        "<style",
        "</style",
        "<iframe",
        "<object",
        "<embed",
        "<svg",
        "<math",
        "<form",
        "<input",
        "<button",
        "<textarea",
        "<meta",
        "<link",
        "<base",
        "srcdoc",
        "formaction",
        "xlink:href",
        "javascript:",
        "vbscript:",
        "data:",
        "expression(",
        "url(javascript:"
    };

    foreach (var fragment in forbiddenFragments)
    {
        AssertDoesNotContain(fragment, html);
    }

    AssertDoesNotMatch("<[^>]+\\son[a-z0-9_:-]*\\s*=", html);
    AssertDoesNotMatch("<[^>]+\\sstyle\\s*=", html);
}

static async Task AssertThrowsAsync<TException>(Func<Task> action)
    where TException : Exception
{
    try
    {
        await action();
    }
    catch (TException)
    {
        return;
    }
    catch (Exception exception)
    {
        throw new TestFailureException($"Expected {typeof(TException).Name}, got {exception.GetType().Name}.");
    }

    throw new TestFailureException($"Expected {typeof(TException).Name}, but no exception was thrown.");
}

static void AssertTrue(bool condition, string message)
{
    if (!condition)
    {
        throw new TestFailureException(message);
    }
}

static void AssertFalse(bool condition, string message) =>
    AssertTrue(!condition, message);

static void AssertEqual(string expected, string actual)
{
    if (!string.Equals(expected, actual, StringComparison.Ordinal))
    {
        throw new TestFailureException($"Expected '{expected}', got '{actual}'.");
    }
}

static void AssertContains(string expectedFragment, string actual)
{
    if (!actual.Contains(expectedFragment, StringComparison.Ordinal))
    {
        throw new TestFailureException($"Expected output to contain '{expectedFragment}', got '{actual}'.");
    }
}

static void AssertDoesNotContain(string forbiddenFragment, string actual)
{
    if (actual.Contains(forbiddenFragment, StringComparison.OrdinalIgnoreCase))
    {
        throw new TestFailureException($"Expected output not to contain '{forbiddenFragment}', got '{actual}'.");
    }
}

static void AssertDoesNotMatch(string pattern, string actual)
{
    if (Regex.IsMatch(actual, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
    {
        throw new TestFailureException($"Expected output not to match '{pattern}', got '{actual}'.");
    }
}

internal sealed class TestBrowserFile : IBrowserFile
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

internal sealed class TestFailureException : Exception
{
    public TestFailureException(string message)
        : base(message)
    {
    }
}
