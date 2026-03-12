using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using MailPhishingDetector.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace MailPhishingDetector.Services;

public class ImapSettings
{
    public bool   Enabled             { get; set; } = false;
    public string Host                { get; set; } = "imap.gmail.com";
    public int    Port                { get; set; } = 993;
    public bool   UseSsl              { get; set; } = true;
    public string Username            { get; set; } = string.Empty;
    public string Password            { get; set; } = string.Empty;
    /// <summary>Mailbox folder to watch for forwarded emails.</summary>
    public string InboxFolder         { get; set; } = "INBOX";
    /// <summary>Successfully processed messages are moved here.</summary>
    public string ProcessedFolder     { get; set; } = "Processed";
    /// <summary>Messages that could not be processed are moved here.</summary>
    public string ErrorFolder         { get; set; } = "Error";
    public int    PollIntervalSeconds { get; set; } = 30;
}

/// <summary>
/// Background service that polls a dedicated IMAP inbox for emails forwarded
/// by users.  Each forwarded message must contain the original email as a
/// <c>message/rfc822</c> attachment ("Forward as Attachment").
///
/// Flow per message:
///   1. Identify the forwarder (outer From address).
///   2. Locate the message/rfc822 attachment (the original suspicious email).
///   3. Parse → Analyse → Send report to forwarder.
///   4. Move message to ProcessedFolder (or ErrorFolder on failure).
/// </summary>
public class ImapFetchService : BackgroundService
{
    private readonly ImapSettings           _cfg;
    private readonly EmlParserService       _parser;
    private readonly PhishingDetectorService _detector;
    private readonly ReportSenderService    _sender;
    private readonly ILogger<ImapFetchService> _log;

    public ImapFetchService(
        IOptions<ImapSettings>         settings,
        EmlParserService               parser,
        PhishingDetectorService        detector,
        ReportSenderService            sender,
        ILogger<ImapFetchService>      logger)
    {
        _cfg      = settings.Value;
        _parser   = parser;
        _detector = detector;
        _sender   = sender;
        _log      = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation(
            "IMAP fetch service started — polling '{Inbox}' on {Host}:{Port} every {Interval}s.",
            _cfg.InboxFolder, _cfg.Host, _cfg.Port, _cfg.PollIntervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "IMAP poll cycle failed — will retry after {Interval}s.", _cfg.PollIntervalSeconds);
            }

            await Task.Delay(TimeSpan.FromSeconds(_cfg.PollIntervalSeconds), stoppingToken);
        }

        _log.LogInformation("IMAP fetch service stopped.");
    }

    // ---------------------------------------------------------------
    //  Poll cycle
    // ---------------------------------------------------------------

    private async Task PollOnceAsync(CancellationToken ct)
    {
        using var client = new ImapClient();

        var ssl = _cfg.UseSsl ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.None;
        await client.ConnectAsync(_cfg.Host, _cfg.Port, ssl, ct);
        await client.AuthenticateAsync(_cfg.Username, _cfg.Password, ct);

        // Open inbox
        var inbox = client.GetFolder(_cfg.InboxFolder);
        await inbox.OpenAsync(FolderAccess.ReadWrite, ct);

        // Find all unseen messages
        var uids = await inbox.SearchAsync(SearchQuery.NotSeen, ct);

        if (uids.Count == 0)
        {
            _log.LogDebug("No unseen messages in '{Inbox}'.", _cfg.InboxFolder);
            await client.DisconnectAsync(quit: true, ct);
            return;
        }

        _log.LogInformation("Found {Count} unseen message(s) to process.", uids.Count);

        // Ensure target folders exist
        var processedFolder = await EnsureFolderAsync(client, _cfg.ProcessedFolder, ct);
        var errorFolder     = await EnsureFolderAsync(client, _cfg.ErrorFolder, ct);

        foreach (var uid in uids)
        {
            if (ct.IsCancellationRequested) break;

            // Re-open inbox if needed (MailKit may close it after folder operations)
            if (inbox.IsOpen is false)
                await inbox.OpenAsync(FolderAccess.ReadWrite, ct);

            await ProcessMessageAsync(inbox, uid, processedFolder, errorFolder, ct);
        }

        await client.DisconnectAsync(quit: true, ct);
    }

    // ---------------------------------------------------------------
    //  Per-message processing
    // ---------------------------------------------------------------

    private async Task ProcessMessageAsync(
        IMailFolder inbox,
        UniqueId    uid,
        IMailFolder processedFolder,
        IMailFolder errorFolder,
        CancellationToken ct)
    {
        MimeMessage outer;
        try
        {
            outer = await inbox.GetMessageAsync(uid, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to fetch message UID {Uid} — skipping.", uid);
            return;
        }

        var forwarderAddress = outer.From.Mailboxes.FirstOrDefault()?.Address;
        if (string.IsNullOrWhiteSpace(forwarderAddress))
        {
            _log.LogWarning("UID {Uid}: No From address on outer message — moving to error folder.", uid);
            await MoveAsync(inbox, uid, errorFolder, ct);
            return;
        }

        _log.LogInformation("Processing UID {Uid} forwarded by '{Forwarder}'…", uid, forwarderAddress);

        // Locate the original email attached as message/rfc822
        var rfc822Part = outer.Attachments
            .OfType<MessagePart>()
            .FirstOrDefault();

        if (rfc822Part is null)
        {
            _log.LogWarning(
                "UID {Uid}: No message/rfc822 attachment found. " +
                "Please ask users to use \"Forward as Attachment\" instead of inline forward. " +
                "Moving to error folder.",
                uid);
            await MoveAsync(inbox, uid, errorFolder, ct);
            return;
        }

        try
        {
            var originalEmail = rfc822Part.Message;
            _log.LogDebug("UID {Uid}: Attached email subject: '{Subject}'", uid, originalEmail.Subject);

            var parsed = _parser.ParseMessage(originalEmail);
            var report = _detector.Analyse(parsed);

            _log.LogInformation(
                "UID {Uid}: Analysis done — Score {Score}/100, Risk: {Risk}, Findings: {Count}.",
                uid, report.Score, report.RiskLevel, report.Findings.Count);

            foreach (var finding in report.Findings)
                _log.LogDebug("  {Finding}", finding);

            // Send report back to the forwarder
            await _sender.SendReportAsync(report, new[] { forwarderAddress }, ct);

            // Mark as seen and move to Processed
            await inbox.AddFlagsAsync(uid, MessageFlags.Seen, silent: true, ct);
            await MoveAsync(inbox, uid, processedFolder, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "UID {Uid}: Failed to analyse or send report — moving to error folder.", uid);
            await MoveAsync(inbox, uid, errorFolder, ct);
        }
    }

    // ---------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------

    private static async Task<IMailFolder> EnsureFolderAsync(
        ImapClient client, string folderName, CancellationToken ct)
    {
        try
        {
            var folder = client.GetFolder(folderName);
            return folder;
        }
        catch
        {
            // Folder doesn't exist — create it under the personal namespace
            var personal = client.PersonalNamespaces.FirstOrDefault();
            var root     = await client.GetFolderAsync(personal?.Path ?? string.Empty, ct);
            return await root.CreateAsync(folderName, isMessageFolder: true, ct);
        }
    }

    private static async Task MoveAsync(
        IMailFolder source, UniqueId uid, IMailFolder destination, CancellationToken ct)
    {
        try
        {
            await source.MoveToAsync(uid, destination, ct);
        }
        catch (Exception ex)
        {
            // Non-fatal — worst case the message stays in the inbox
            Console.Error.WriteLine($"[WARN] Could not move UID {uid} to '{destination.Name}': {ex.Message}");
        }
    }
}
