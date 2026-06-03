using System.Text;
using Ganss.Xss;
using Microsoft.AspNetCore.Components.Forms;

namespace UploadFileBlazor.Services;

public sealed class UploadedFileProcessor
{
    public const long MaxFileSize = 5 * 1_048_576;
    public const int MaxTextCharacters = (int)MaxFileSize;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt",
        ".htm",
        ".html"
    };
    private static readonly Dictionary<string, string> CanonicalContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".txt"] = "text/plain",
        [".htm"] = "text/html",
        [".html"] = "text/html"
    };
    private static readonly HashSet<char> UnsafeFileNameCharacters = new(Path.GetInvalidFileNameChars())
    {
        '<',
        '>',
        ':',
        '"',
        '/',
        '\\',
        '|',
        '?',
        '*'
    };

    private const int MaxFileNameLength = 120;

    public async Task<ProcessedUpload> ProcessAsync(IBrowserFile file, CancellationToken cancellationToken = default)
    {
        var safeFileName = SanitizeFileName(file.Name);
        var extension = Path.GetExtension(safeFileName);
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
            safeFileName,
            CanonicalContentTypes[extension],
            file.Size,
            sanitizedText,
            isHtml);
    }

    private static async Task<string> ReadUtf8TextAsync(IBrowserFile file, CancellationToken cancellationToken)
    {
        await using var stream = file.OpenReadStream(MaxFileSize, cancellationToken);
        using var memoryStream = new MemoryStream((int)Math.Min(file.Size, MaxFileSize));
        var buffer = new byte[81920];
        long bytesReadTotal = 0;

        while (true)
        {
            var bytesRead = await stream.ReadAsync(buffer, cancellationToken);
            if (bytesRead == 0)
            {
                break;
            }

            bytesReadTotal += bytesRead;
            if (bytesReadTotal > MaxFileSize)
            {
                throw new InvalidDataException($"The selected file is too large. Maximum size is {FormatBytes(MaxFileSize)}.");
            }

            await memoryStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
        }

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
        return new HtmlSanitizer().Sanitize(html).Trim();
    }

    private static string RemoveUnsafeControlCharacters(string value)
    {
        var sanitized = new StringBuilder(value.Length);

        foreach (var character in value)
        {
            if (IsSafeContentCharacter(character))
            {
                sanitized.Append(character);
            }
        }

        return sanitized.ToString();
    }

    private static string SanitizeFileName(string fileName)
    {
        var lastSegment = fileName
            .Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries)
            .LastOrDefault() ?? string.Empty;
        var sanitized = new StringBuilder(lastSegment.Length);

        foreach (var character in lastSegment)
        {
            sanitized.Append(IsSafeContentCharacter(character) && !UnsafeFileNameCharacters.Contains(character)
                ? character
                : '_');
        }

        var safeFileName = sanitized.ToString().Trim();
        if (safeFileName.Length == 0)
        {
            throw new InvalidDataException("The selected file name is invalid.");
        }

        if (safeFileName.Length <= MaxFileNameLength)
        {
            return safeFileName;
        }

        var extension = Path.GetExtension(safeFileName);
        var nameWithoutExtension = Path.GetFileNameWithoutExtension(safeFileName);
        var maxNameLength = Math.Max(1, MaxFileNameLength - extension.Length);

        return nameWithoutExtension[..Math.Min(nameWithoutExtension.Length, maxNameLength)] + extension;
    }

    private static bool IsSafeContentCharacter(char character) =>
        character is '\t' or '\n' or '\r' || !char.IsControl(character);

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
