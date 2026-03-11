using MailPhishingDetector.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailPhishingDetector.Services;

public class WatcherSettings
{
    /// <summary>Folder that is monitored for incoming .eml files.</summary>
    public string DropFolder   { get; set; } = "./drop";

    /// <summary>Successfully processed files are moved here.</summary>
    public string DoneFolder   { get; set; } = "./done";

    /// <summary>Files that failed processing are moved here.</summary>
    public string ErrorFolder  { get; set; } = "./error";

    /// <summary>
    /// How long (ms) to wait before processing a file that just appeared,
    /// giving the writer time to finish flushing.
    /// </summary>
    public int FileSettleDelayMs { get; set; } = 500;
}

/// <summary>
/// Background service that watches a drop folder for .eml files,
/// analyses each one, sends the report, and then moves the file.
/// </summary>
public class EmlWatcherService : BackgroundService
{
    private readonly WatcherSettings           _settings;
    private readonly EmlParserService          _parser;
    private readonly PhishingDetectorService   _detector;
    private readonly ReportSenderService       _sender;
    private readonly ILogger<EmlWatcherService> _log;

    // Files currently being processed — prevents double-processing
    private readonly HashSet<string> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim   _lock      = new(1, 1);

    public EmlWatcherService(
        IOptions<WatcherSettings>     settings,
        EmlParserService              parser,
        PhishingDetectorService       detector,
        ReportSenderService           sender,
        ILogger<EmlWatcherService>    logger)
    {
        _settings = settings.Value;
        _parser   = parser;
        _detector = detector;
        _sender   = sender;
        _log      = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        EnsureFoldersExist();

        // Process any files that were already sitting in the drop folder
        // before the service started.
        await ProcessExistingFilesAsync(stoppingToken);

        // Set up FileSystemWatcher for live arrivals.
        using var watcher = CreateWatcher();

        _log.LogInformation("Watching '{DropFolder}' for .eml files…", _settings.DropFolder);

        await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
    }

    // ---------------------------------------------------------------
    //  Watcher setup
    // ---------------------------------------------------------------

    private FileSystemWatcher CreateWatcher()
    {
        var watcher = new FileSystemWatcher(_settings.DropFolder, "*.eml")
        {
            NotifyFilter           = NotifyFilters.FileName | NotifyFilters.LastWrite,
            IncludeSubdirectories  = false,
            EnableRaisingEvents    = true,
        };

        watcher.Created += OnFileEvent;
        watcher.Renamed += OnFileEvent;
        watcher.Error   += (_, e) =>
            _log.LogError(e.GetException(), "FileSystemWatcher error.");

        return watcher;
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        // Fire-and-forget on a thread-pool thread
        _ = Task.Run(async () =>
        {
            await Task.Delay(_settings.FileSettleDelayMs); // let the writer finish
            await HandleFileAsync(e.FullPath, CancellationToken.None);
        });
    }

    // ---------------------------------------------------------------
    //  Processing
    // ---------------------------------------------------------------

    private async Task ProcessExistingFilesAsync(CancellationToken ct)
    {
        var existing = Directory.GetFiles(_settings.DropFolder, "*.eml");
        _log.LogInformation("Found {Count} pre-existing EML file(s) to process.", existing.Length);

        foreach (var file in existing)
            await HandleFileAsync(file, ct);
    }

    private async Task HandleFileAsync(string filePath, CancellationToken ct)
    {
        // Deduplication — ignore if already in flight
        await _lock.WaitAsync(ct);
        bool added = _inFlight.Add(filePath);
        _lock.Release();

        if (!added) return;

        try
        {
            _log.LogInformation("Processing '{File}'…", Path.GetFileName(filePath));

            var email  = _parser.Parse(filePath);
            var report = _detector.Analyse(email);

            _log.LogInformation(
                "Analysis complete — Score: {Score}/100, Risk: {Risk}, Findings: {Count}",
                report.Score, report.RiskLevel, report.Findings.Count);

            // Log each finding at debug level
            foreach (var finding in report.Findings)
                _log.LogDebug("  {Finding}", finding);

            await _sender.SendReportAsync(report, email.ToAddresses, ct);

            MoveFile(filePath, _settings.DoneFolder);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to process '{File}'.", Path.GetFileName(filePath));
            MoveFile(filePath, _settings.ErrorFolder);
        }
        finally
        {
            await _lock.WaitAsync(ct);
            _inFlight.Remove(filePath);
            _lock.Release();
        }
    }

    // ---------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------

    private void EnsureFoldersExist()
    {
        foreach (var folder in new[] { _settings.DropFolder, _settings.DoneFolder, _settings.ErrorFolder })
        {
            if (!Directory.Exists(folder))
            {
                Directory.CreateDirectory(folder);
                _log.LogInformation("Created folder '{Folder}'.", folder);
            }
        }
    }

    private void MoveFile(string sourcePath, string targetFolder)
    {
        try
        {
            var dest = Path.Combine(targetFolder, Path.GetFileName(sourcePath));

            // Avoid collisions — append a timestamp suffix if needed
            if (File.Exists(dest))
                dest = Path.Combine(targetFolder,
                    $"{Path.GetFileNameWithoutExtension(sourcePath)}_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}.eml");

            File.Move(sourcePath, dest);
            _log.LogInformation("Moved '{File}' → '{Dest}'.", Path.GetFileName(sourcePath), dest);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not move '{File}' after processing.", sourcePath);
        }
    }
}
