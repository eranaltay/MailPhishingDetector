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

        // Register services
        services.AddSingleton<EmlParserService>();
        services.AddSingleton<PhishingDetectorService>();
        services.AddSingleton<ReportSenderService>();

        // The watcher is a long-running background service
        services.AddHostedService<EmlWatcherService>();
    })
    .Build();

await host.RunAsync();
