using MailPhishingDetector.Models;
using MimeKit;
using System.Text.RegularExpressions;

namespace MailPhishingDetector.Services;

/// <summary>
/// Parses a raw .eml file (or an in-memory <see cref="MimeMessage"/>) into a
/// <see cref="ParsedEmail"/> ready for phishing analysis.
/// </summary>
public class EmlParserService
{
    // Matches href="..." and src="..." as well as plain http(s) URLs in text.
    private static readonly Regex UrlRegex = new(
        @"https?://[^\s""'<>\)\]]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Parses a .eml file from disk.</summary>
    public ParsedEmail Parse(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var message = MimeMessage.Load(stream);
        return ParseMimeMessage(message, filePath);
    }

    /// <summary>
    /// Parses an already-loaded <see cref="MimeMessage"/> — used by the IMAP fetch path
    /// where there is no file on disk.
    /// </summary>
    public ParsedEmail ParseMessage(MimeMessage message, string filePath = "")
        => ParseMimeMessage(message, filePath);

    // ---------------------------------------------------------------
    //  Core extraction — shared by both public methods
    // ---------------------------------------------------------------

    private static ParsedEmail ParseMimeMessage(MimeMessage message, string filePath)
    {
        var toAddresses = message.To
            .Mailboxes
            .Select(m => m.Address)
            .ToList();

        var replyTo    = message.ReplyTo.Mailboxes.FirstOrDefault()?.Address ?? string.Empty;
        var returnPath = message.Headers[HeaderId.ReturnPath] ?? string.Empty;

        var plainText = message.GetTextBody(MimeKit.Text.TextFormat.Plain) ?? string.Empty;
        var htmlBody  = message.GetTextBody(MimeKit.Text.TextFormat.Html)  ?? string.Empty;

        // Collect URLs from both HTML and plain-text bodies
        var urls = UrlRegex
            .Matches(htmlBody + " " + plainText)
            .Select(m => m.Value.TrimEnd('.', ',', ';'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Attachment file names (binary parts only — MessageParts are handled separately)
        var attachments = message.Attachments
            .OfType<MimePart>()
            .Select(a => a.FileName ?? string.Empty)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .ToList();

        // All Received: headers (for hop analysis)
        var received = message.Headers
            .Where(h => h.Id == HeaderId.Received)
            .Select(h => h.Value)
            .ToList();

        var from = message.From.Mailboxes.FirstOrDefault();

        return new ParsedEmail
        {
            FilePath           = filePath,
            MessageId          = message.MessageId ?? string.Empty,
            Subject            = message.Subject   ?? string.Empty,
            FromAddress        = from?.Address      ?? string.Empty,
            FromDisplayName    = from?.Name         ?? string.Empty,
            ReplyToAddress     = replyTo,
            ReturnPath         = returnPath,
            ToAddresses        = toAddresses,
            ReceivedSpf        = message.Headers["Received-SPF"]          ?? string.Empty,
            AuthResults        = message.Headers["Authentication-Results"] ?? string.Empty,
            DkimSignature      = message.Headers["DKIM-Signature"]         ?? string.Empty,
            PlainTextBody      = plainText,
            HtmlBody           = htmlBody,
            BodyUrls           = urls,
            AttachmentNames    = attachments,
            AllReceivedHeaders = received,
            SentDate           = message.Date,
        };
    }
}
