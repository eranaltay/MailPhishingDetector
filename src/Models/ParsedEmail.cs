namespace MailPhishingDetector.Models;

/// <summary>
/// Represents a fully parsed EML file, ready for phishing analysis.
/// </summary>
public record ParsedEmail
{
    public string FilePath       { get; init; } = string.Empty;
    public string MessageId      { get; init; } = string.Empty;
    public string Subject        { get; init; } = string.Empty;

    // Envelope fields
    public string FromAddress    { get; init; } = string.Empty;
    public string FromDisplayName{ get; init; } = string.Empty;
    public string ReplyToAddress { get; init; } = string.Empty;
    public string ReturnPath     { get; init; } = string.Empty;

    /// <summary>All To: recipients (we will send the report to these addresses).</summary>
    public IReadOnlyList<string> ToAddresses  { get; init; } = Array.Empty<string>();

    // Authentication headers
    public string ReceivedSpf    { get; init; } = string.Empty;
    public string AuthResults    { get; init; } = string.Empty;
    public string DkimSignature  { get; init; } = string.Empty;

    // Body
    public string PlainTextBody  { get; init; } = string.Empty;
    public string HtmlBody       { get; init; } = string.Empty;

    // Extracted artifacts
    public IReadOnlyList<string> BodyUrls          { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> AttachmentNames   { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> AllReceivedHeaders{ get; init; } = Array.Empty<string>();

    public DateTimeOffset SentDate { get; init; }
}
