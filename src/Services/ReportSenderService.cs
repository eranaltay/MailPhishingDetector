using MailKit.Net.Smtp;
using MailKit.Security;
using MailPhishingDetector.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace MailPhishingDetector.Services;

public class SmtpSettings
{
    public string Host        { get; set; } = "localhost";
    public int    Port        { get; set; } = 587;
    public bool   UseTls      { get; set; } = true;
    public string Username    { get; set; } = string.Empty;
    public string Password    { get; set; } = string.Empty;
    public string FromAddress { get; set; } = string.Empty;
    public string FromName    { get; set; } = "Mail Phishing Detector";
}

/// <summary>
/// Sends a phishing analysis report back to the original recipients via SMTP.
/// </summary>
public class ReportSenderService
{
    private readonly SmtpSettings _smtp;
    private readonly ILogger<ReportSenderService> _log;

    public ReportSenderService(IOptions<SmtpSettings> smtpOptions,
                               ILogger<ReportSenderService> logger)
    {
        _smtp = smtpOptions.Value;
        _log  = logger;
    }

    public async Task SendReportAsync(PhishingReport report,
                                      IEnumerable<string> recipients,
                                      CancellationToken ct = default)
    {
        var recipientList = recipients.ToList();
        if (recipientList.Count == 0)
        {
            _log.LogWarning("No recipients for report on message '{MessageId}' — skipping send.", report.MessageId);
            return;
        }

        var body = BuildTextReport(report);
        var html = BuildHtmlReport(report);

        var mimeMessage = new MimeMessage();
        mimeMessage.From.Add(new MailboxAddress(_smtp.FromName, _smtp.FromAddress));
        mimeMessage.Subject = $"[Phishing Analysis] {report.RiskLevel} risk — {report.Subject}";

        foreach (var addr in recipientList)
        {
            if (MailboxAddress.TryParse(addr, out var mb))
                mimeMessage.To.Add(mb);
        }

        var bodyBuilder = new BodyBuilder
        {
            TextBody = body,
            HtmlBody = html,
        };
        mimeMessage.Body = bodyBuilder.ToMessageBody();

        using var client = new SmtpClient();

        var secureOption = _smtp.UseTls
            ? SecureSocketOptions.StartTls
            : SecureSocketOptions.None;

        await client.ConnectAsync(_smtp.Host, _smtp.Port, secureOption, ct);

        if (!string.IsNullOrWhiteSpace(_smtp.Username))
            await client.AuthenticateAsync(_smtp.Username, _smtp.Password, ct);

        await client.SendAsync(mimeMessage, ct);
        await client.DisconnectAsync(quit: true, ct);

        _log.LogInformation("Report sent to {Recipients} for message '{MessageId}'.",
            string.Join(", ", recipientList), report.MessageId);
    }

    // ---------------------------------------------------------------
    //  Report formatting
    // ---------------------------------------------------------------

    private static string BuildTextReport(PhishingReport r)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== MAIL PHISHING ANALYSIS REPORT ===");
        sb.AppendLine();
        sb.AppendLine($"Original Subject : {r.Subject}");
        sb.AppendLine($"From             : {r.FromAddress}");
        sb.AppendLine($"Message-ID       : {r.MessageId}");
        sb.AppendLine($"Analysed at      : {r.AnalysedAt:u}");
        sb.AppendLine();
        sb.AppendLine($"RISK LEVEL  : {r.RiskLevel}");
        sb.AppendLine($"SCORE       : {r.Score} / 100");
        sb.AppendLine();
        sb.AppendLine("--- FINDINGS ---");

        if (r.Findings.Count == 0)
        {
            sb.AppendLine("No suspicious indicators detected.");
        }
        else
        {
            foreach (var f in r.Findings)
                sb.AppendLine($"  • {f}");
        }

        sb.AppendLine();
        sb.AppendLine("--- RECOMMENDATION ---");
        sb.AppendLine(r.RiskLevel switch
        {
            RiskLevel.Safe     => "This email appears legitimate. No action required.",
            RiskLevel.Low      => "This email shows minor anomalies. Exercise normal caution.",
            RiskLevel.Medium   => "This email has several suspicious traits. Do not click links or open attachments without verification.",
            RiskLevel.High     => "This email is likely malicious. Do NOT interact with it. Report to your IT/security team.",
            RiskLevel.Critical => "This email is almost certainly a phishing/malware attempt. Delete it immediately and report to your IT/security team.",
            _                  => string.Empty
        });

        sb.AppendLine();
        sb.AppendLine("This report was generated automatically by MailPhishingDetector.");
        return sb.ToString();
    }

    private static string BuildHtmlReport(PhishingReport r)
    {
        var riskColor = r.RiskLevel switch
        {
            RiskLevel.Safe     => "#28a745",
            RiskLevel.Low      => "#6c757d",
            RiskLevel.Medium   => "#fd7e14",
            RiskLevel.High     => "#dc3545",
            RiskLevel.Critical => "#7b0000",
            _                  => "#333333"
        };

        var recommendation = r.RiskLevel switch
        {
            RiskLevel.Safe     => "This email appears legitimate. No action required.",
            RiskLevel.Low      => "This email shows minor anomalies. Exercise normal caution.",
            RiskLevel.Medium   => "This email has several suspicious traits. Do not click links or open attachments without verification.",
            RiskLevel.High     => "This email is likely malicious. Do NOT interact with it. Report to your IT/security team.",
            RiskLevel.Critical => "This email is almost certainly a phishing/malware attempt. Delete it immediately and report to your IT/security team.",
            _                  => string.Empty
        };

        var findingsHtml = r.Findings.Count > 0
            ? "<ul>" + string.Join("", r.Findings.Select(f =>
                $"<li style='margin:4px 0'>{System.Net.WebUtility.HtmlEncode(f)}</li>")) + "</ul>"
            : "<p>No suspicious indicators detected.</p>";

        return $"""
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><title>Phishing Analysis Report</title></head>
            <body style="font-family:Arial,sans-serif;max-width:680px;margin:auto;padding:20px">

              <h1 style="border-bottom:2px solid {riskColor};padding-bottom:8px;color:{riskColor}">
                Mail Phishing Analysis Report
              </h1>

              <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
                <tr><td style="padding:4px 8px;font-weight:bold;width:160px">Original Subject</td><td>{System.Net.WebUtility.HtmlEncode(r.Subject)}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">From</td><td>{System.Net.WebUtility.HtmlEncode(r.FromAddress)}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">Message-ID</td><td style="font-size:0.85em">{System.Net.WebUtility.HtmlEncode(r.MessageId)}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">Analysed at</td><td>{r.AnalysedAt:u}</td></tr>
              </table>

              <div style="background:{riskColor};color:#fff;border-radius:6px;padding:12px 20px;margin-bottom:20px">
                <span style="font-size:1.4em;font-weight:bold">{r.RiskLevel} Risk</span>
                &nbsp;&nbsp;|&nbsp;&nbsp;
                Score: <strong>{r.Score} / 100</strong>
              </div>

              <h2 style="color:#333">Findings</h2>
              {findingsHtml}

              <h2 style="color:#333">Recommendation</h2>
              <p style="background:#f8f9fa;border-left:4px solid {riskColor};padding:10px 16px">
                {System.Net.WebUtility.HtmlEncode(recommendation)}
              </p>

              <p style="font-size:0.8em;color:#999;margin-top:40px">
                This report was generated automatically by MailPhishingDetector.
              </p>
            </body>
            </html>
            """;
    }
}
