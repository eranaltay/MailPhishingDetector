using MailPhishingDetector.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureLogging(logging =>
    {
        logging.ClearProviders();
        logging.AddConsole(opts =>
        {
            opts.TimestampFormat = "[yyyy-MM-dd HH:mm:ss] ";
        });
    })
    .ConfigureServices((ctx, services) =>
    {
        // Bind configuration sections to strongly-typed settings
        services.Configure<WatcherSettings>(ctx.Configuration.GetSection("Watcher"));
        services.Configure<SmtpSettings>   (ctx.Configuration.GetSection("Smtp"));
        services.Configure<ImapSettings>   (ctx.Configuration.GetSection("Imap"));

        // Register services
        services.AddSingleton<EmlParserService>();
        services.AddSingleton<PhishingDetectorService>();
        services.AddSingleton<ReportSenderService>();

        // Local drop-folder watcher (always active — useful for testing)
        services.AddHostedService<EmlWatcherService>();

        // IMAP inbox poller — only started when Imap:Enabled = true
        if (ctx.Configuration.GetValue<bool>("Imap:Enabled"))
            services.AddHostedService<ImapFetchService>();
    })
    .Build();

await host.RunAsync();
