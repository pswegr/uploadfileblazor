using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components.Forms;

namespace UploadFileBlazor.Services;

public sealed class UploadedFileProcessor
{
    public const long MaxFileSize = 5 * 1_048_576;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt",
        ".htm",
        ".html"
    };

    private static readonly (Regex Pattern, string Message)[] DangerousPatterns =
    [
        (new Regex(@"<\s*/?\s*script\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled),
            "Script tags are not allowed."),
        (new Regex(@"<[^>]+\s+on[a-z0-9_:-]+\s*=", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled),
            "Inline event handler attributes are not allowed."),
        (new Regex(@"\b(?:href|src|xlink:href|action|formaction|srcdoc)\s*=\s*(['""]?)\s*(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t|d\s*a\s*t\s*a)\s*:",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled),
            "Scriptable URL values are not allowed."),
        (new Regex(@"expression\s*\(|url\s*\(\s*(['""]?)\s*j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled),
            "Scriptable CSS expressions are not allowed.")
    ];

    public async Task<ProcessedUpload> ProcessAsync(IBrowserFile file, CancellationToken cancellationToken = default)
    {
        var extension = Path.GetExtension(file.Name);
        if (!AllowedExtensions.Contains(extension))
        {
            throw new InvalidDataException("Only .txt, .htm, and .html files are supported.");
        }

        if (file.Size is <= 0)
        {
            throw new InvalidDataException("The selected file is empty.");
        }

        if (file.Size > MaxFileSize)
        {
            throw new InvalidDataException($"The selected file is too large. Maximum size is {FormatBytes(MaxFileSize)}.");
        }

        var fileText = await ReadUtf8TextAsync(file, cancellationToken);
        fileText = NormalizeLineEndings(RemoveUnsafeControlCharacters(fileText));

        ValidateNoScripts(fileText);

        var isHtml = IsHtmlExtension(extension);
        var sanitizedText = isHtml ? SanitizeHtmlMarkup(fileText) : fileText;

        ValidateNoScripts(sanitizedText);

        return new ProcessedUpload(
            file.Name,
            file.ContentType,
            file.Size,
            sanitizedText,
            isHtml);
    }

    private static async Task<string> ReadUtf8TextAsync(IBrowserFile file, CancellationToken cancellationToken)
    {
        await using var stream = file.OpenReadStream(MaxFileSize, cancellationToken);
        using var memoryStream = new MemoryStream((int)file.Size);

        await stream.CopyToAsync(memoryStream, cancellationToken);

        try
        {
            return StrictUtf8.GetString(memoryStream.ToArray()).TrimStart('\uFEFF');
        }
        catch (DecoderFallbackException)
        {
            throw new InvalidDataException("The selected file must be valid UTF-8 text.");
        }
    }

    private static void ValidateNoScripts(string value)
    {
        var decodedValue = WebUtility.HtmlDecode(value);

        foreach (var (pattern, message) in DangerousPatterns)
        {
            if (pattern.IsMatch(value) || pattern.IsMatch(decodedValue))
            {
                throw new InvalidDataException(message);
            }
        }
    }

    private static string SanitizeHtmlMarkup(string html)
    {
        return NormalizeLineEndings(RemoveUnsafeControlCharacters(html)).Trim();
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

    private static bool IsHtmlExtension(string extension) =>
        extension.Equals(".html", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".htm", StringComparison.OrdinalIgnoreCase);

    private static string FormatBytes(long bytes) =>
        bytes >= 1_048_576 ? $"{bytes / 1_048_576d:0.#} MB" : $"{bytes / 1024d:0.#} KB";
}

public sealed record ProcessedUpload(
    string FileName,
    string ContentType,
    long Size,
    string Text,
    bool WasHtml);
