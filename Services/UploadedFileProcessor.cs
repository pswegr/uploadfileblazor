using System.Text;
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

        var isHtml = IsHtmlExtension(extension);
        var sanitizedText = isHtml ? SanitizeHtmlMarkup(fileText) : fileText;

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

    private static string SanitizeHtmlMarkup(string html)
    {
        return EmailHtmlSanitizer.Sanitize(html);
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
