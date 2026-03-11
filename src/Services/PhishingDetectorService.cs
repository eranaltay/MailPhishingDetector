using MailPhishingDetector.Models;
using System.Text.RegularExpressions;

namespace MailPhishingDetector.Services;

/// <summary>
/// Heuristic phishing / spam detector.
///
/// Each rule adds points to a 0-100 score.  Rules are intentionally
/// documented so they can be tuned or extended independently.
/// </summary>
public class PhishingDetectorService
{
    // ---------------------------------------------------------------
    //  Pre-compiled patterns
    // ---------------------------------------------------------------

    // URL shorteners commonly abused in phishing
    private static readonly HashSet<string> UrlShorteners = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
        "adf.ly","rebrand.ly","cutt.ly","shorturl.at","tiny.cc","clck.ru"
    };

    // Dangerous attachment extensions
    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe",".bat",".cmd",".com",".scr",".vbs",".js",".jar",
        ".ps1",".hta",".iso",".img",".lnk",".wsf",".msi",".dll"
    };

    // Urgency / social-engineering keywords (plain text / subject)
    private static readonly string[] UrgencyKeywords =
    {
        "urgent","immediately","your account","verify now","suspended",
        "click here","act now","limited time","confirm your","bank account",
        "credit card","password","login","sign in","won","prize","lottery",
        "free","congratulations","invoice","payment due","overdue",
        "unpaid","refund","claim","expire","update required","action required"
    };

    // IP-address based URL  e.g.  http://192.168.1.1/login
    private static readonly Regex IpUrlRegex = new(
        @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Subdomain that looks like a brand in the path e.g. paypal.attacker.com
    private static readonly Regex BrandImpersonation = new(
        @"(paypal|apple|microsoft|google|amazon|netflix|facebook|instagram|" +
        @"linkedin|dropbox|wellsfargo|chase|citibank|hsbc|barclays|dhl|fedex|ups)" +
        @"\.[a-z]{2,}\.[a-z]{2,}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Detects data-URI or javascript: pseudo-URLs
    private static readonly Regex ObfuscatedUrlPattern = new(
        @"(javascript:|data:text/html)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // ---------------------------------------------------------------
    //  Public API
    // ---------------------------------------------------------------

    public PhishingReport Analyse(ParsedEmail email)
    {
        var findings = new List<string>();
        int score = 0;

        // ── 1. Sender / envelope checks ────────────────────────────

        score += CheckSenderMismatch(email, findings);
        score += CheckAuthHeaders(email, findings);
        score += CheckReturnPathMismatch(email, findings);

        // ── 2. Subject & body keyword analysis ─────────────────────

        score += CheckUrgencyKeywords(email, findings);

        // ── 3. URL analysis ─────────────────────────────────────────

        score += CheckUrlCount(email, findings);
        score += CheckUrlShorteners(email, findings);
        score += CheckIpBasedUrls(email, findings);
        score += CheckBrandImpersonation(email, findings);
        score += CheckObfuscatedUrls(email, findings);
        score += CheckHtmlVsTextRatio(email, findings);

        // ── 4. Attachment analysis ──────────────────────────────────

        score += CheckDangerousAttachments(email, findings);

        // ── 5. Header anomalies ─────────────────────────────────────

        score += CheckExcessiveReceivedHops(email, findings);
        score += CheckFutureOrVeryOldDate(email, findings);

        // Cap at 100
        score = Math.Min(score, 100);

        var risk = score switch
        {
            <= 10 => RiskLevel.Safe,
            <= 30 => RiskLevel.Low,
            <= 55 => RiskLevel.Medium,
            <= 75 => RiskLevel.High,
            _     => RiskLevel.Critical
        };

        return new PhishingReport
        {
            MessageId   = email.MessageId,
            Subject     = email.Subject,
            FromAddress = email.FromAddress,
            Score       = score,
            RiskLevel   = risk,
            Findings    = findings,
            AnalysedAt  = DateTimeOffset.UtcNow,
        };
    }

    // ---------------------------------------------------------------
    //  Individual rule implementations
    // ---------------------------------------------------------------

    // Rule 1 — From display name doesn't match the actual e-mail domain
    private static int CheckSenderMismatch(ParsedEmail email, List<string> findings)
    {
        if (string.IsNullOrWhiteSpace(email.FromDisplayName) ||
            string.IsNullOrWhiteSpace(email.FromAddress)) return 0;

        // Extract domain from display name (if it looks like an email)
        var dnDomain = ExtractDomain(email.FromDisplayName);
        var addrDomain = ExtractDomain(email.FromAddress);

        if (dnDomain is not null && addrDomain is not null &&
            !string.Equals(dnDomain, addrDomain, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add($"[SENDER MISMATCH] Display name domain '{dnDomain}' differs from sender domain '{addrDomain}'.");
            return 25;
        }

        // Reply-To domain mismatch with From domain
        if (!string.IsNullOrWhiteSpace(email.ReplyToAddress))
        {
            var replyDomain = ExtractDomain(email.ReplyToAddress);
            if (replyDomain is not null && addrDomain is not null &&
                !string.Equals(replyDomain, addrDomain, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add($"[REPLY-TO MISMATCH] Reply-To domain '{replyDomain}' differs from sender domain '{addrDomain}'.");
                return 20;
            }
        }

        return 0;
    }

    // Rule 2 — SPF / DKIM / DMARC failures
    private static int CheckAuthHeaders(ParsedEmail email, List<string> findings)
    {
        int points = 0;

        if (!string.IsNullOrWhiteSpace(email.ReceivedSpf))
        {
            if (email.ReceivedSpf.Contains("fail", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add("[SPF FAIL] The sending server is not authorised to send for this domain.");
                points += 20;
            }
            else if (email.ReceivedSpf.Contains("softfail", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add("[SPF SOFTFAIL] SPF softfail — sender may not be authorised.");
                points += 10;
            }
            else if (email.ReceivedSpf.Contains("none", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add("[SPF NONE] No SPF record found for the sender domain.");
                points += 5;
            }
        }
        else
        {
            findings.Add("[SPF MISSING] No Received-SPF header found.");
            points += 5;
        }

        if (string.IsNullOrWhiteSpace(email.DkimSignature))
        {
            findings.Add("[DKIM MISSING] No DKIM-Signature header — message authenticity cannot be verified.");
            points += 10;
        }
        else if (email.AuthResults.Contains("dkim=fail", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("[DKIM FAIL] DKIM signature verification failed.");
            points += 15;
        }

        if (email.AuthResults.Contains("dmarc=fail", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("[DMARC FAIL] DMARC policy check failed.");
            points += 15;
        }

        return points;
    }

    // Rule 3 — Return-Path domain differs from From domain
    private static int CheckReturnPathMismatch(ParsedEmail email, List<string> findings)
    {
        if (string.IsNullOrWhiteSpace(email.ReturnPath)) return 0;

        var returnDomain = ExtractDomain(email.ReturnPath);
        var fromDomain   = ExtractDomain(email.FromAddress);

        if (returnDomain is not null && fromDomain is not null &&
            !string.Equals(returnDomain, fromDomain, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add($"[RETURN-PATH MISMATCH] Return-Path domain '{returnDomain}' differs from From domain '{fromDomain}'.");
            return 10;
        }

        return 0;
    }

    // Rule 4 — Urgency / social-engineering keywords
    private static int CheckUrgencyKeywords(ParsedEmail email, List<string> findings)
    {
        var combined = (email.Subject + " " + email.PlainTextBody).ToLowerInvariant();
        var matched  = UrgencyKeywords.Where(k => combined.Contains(k)).ToList();

        if (matched.Count == 0) return 0;

        int points = Math.Min(matched.Count * 3, 20); // cap at +20
        findings.Add($"[URGENCY KEYWORDS] {matched.Count} social-engineering keyword(s) detected: {string.Join(", ", matched)}.");
        return points;
    }

    // Rule 5 — Suspicious number of external URLs
    private static int CheckUrlCount(ParsedEmail email, List<string> findings)
    {
        int count = email.BodyUrls.Count;
        if (count > 15)
        {
            findings.Add($"[EXCESSIVE URLS] {count} external URLs found — typical of spray-and-pray phishing.");
            return 15;
        }
        if (count > 7)
        {
            findings.Add($"[MANY URLS] {count} external URLs found.");
            return 5;
        }
        return 0;
    }

    // Rule 6 — URL shorteners
    private static int CheckUrlShorteners(ParsedEmail email, List<string> findings)
    {
        var shortened = email.BodyUrls
            .Where(u => Uri.TryCreate(u, UriKind.Absolute, out var uri) &&
                        UrlShorteners.Contains(uri.Host))
            .ToList();

        if (shortened.Count > 0)
        {
            findings.Add($"[URL SHORTENERS] {shortened.Count} URL-shortener link(s) detected — destination is hidden: {string.Join(", ", shortened)}.");
            return Math.Min(shortened.Count * 10, 25);
        }
        return 0;
    }

    // Rule 7 — IP-based URLs
    private static int CheckIpBasedUrls(ParsedEmail email, List<string> findings)
    {
        var ipUrls = email.BodyUrls.Where(u => IpUrlRegex.IsMatch(u)).ToList();
        if (ipUrls.Count > 0)
        {
            findings.Add($"[IP-BASED URLs] Links use raw IP addresses instead of domain names: {string.Join(", ", ipUrls)}.");
            return Math.Min(ipUrls.Count * 15, 30);
        }
        return 0;
    }

    // Rule 8 — Brand name in subdomain (typosquatting)
    private static int CheckBrandImpersonation(ParsedEmail email, List<string> findings)
    {
        var impersonated = email.BodyUrls
            .Where(u => BrandImpersonation.IsMatch(u))
            .ToList();

        if (impersonated.Count > 0)
        {
            findings.Add($"[BRAND IMPERSONATION] URL(s) appear to impersonate well-known brands: {string.Join(", ", impersonated)}.");
            return Math.Min(impersonated.Count * 20, 35);
        }
        return 0;
    }

    // Rule 9 — javascript: / data: pseudo-URLs
    private static int CheckObfuscatedUrls(ParsedEmail email, List<string> findings)
    {
        var obfuscated = email.BodyUrls
            .Concat(new[] { email.HtmlBody })
            .Where(u => ObfuscatedUrlPattern.IsMatch(u))
            .ToList();

        if (obfuscated.Count > 0)
        {
            findings.Add("[OBFUSCATED URLS] javascript: or data: URI scheme detected — commonly used to bypass link scanners.");
            return 30;
        }
        return 0;
    }

    // Rule 10 — HTML body but no plain-text alternative (common in phishing)
    private static int CheckHtmlVsTextRatio(ParsedEmail email, List<string> findings)
    {
        if (!string.IsNullOrWhiteSpace(email.HtmlBody) &&
             string.IsNullOrWhiteSpace(email.PlainTextBody))
        {
            findings.Add("[HTML ONLY] Email has an HTML body but no plain-text alternative — common in phishing templates.");
            return 8;
        }
        return 0;
    }

    // Rule 11 — Dangerous attachment types
    private static int CheckDangerousAttachments(ParsedEmail email, List<string> findings)
    {
        var dangerous = email.AttachmentNames
            .Where(n => DangerousExtensions.Contains(Path.GetExtension(n)))
            .ToList();

        if (dangerous.Count > 0)
        {
            findings.Add($"[DANGEROUS ATTACHMENTS] Executable/script attachment(s) detected: {string.Join(", ", dangerous)}.");
            return Math.Min(dangerous.Count * 20, 40);
        }
        return 0;
    }

    // Rule 12 — Unusually long Received: chain (> 7 hops)
    private static int CheckExcessiveReceivedHops(ParsedEmail email, List<string> findings)
    {
        if (email.AllReceivedHeaders.Count > 7)
        {
            findings.Add($"[EXCESSIVE HOPS] {email.AllReceivedHeaders.Count} Received: headers — email may have been relayed through many servers.");
            return 8;
        }
        return 0;
    }

    // Rule 13 — Sent date is in the far future or very old past
    private static int CheckFutureOrVeryOldDate(ParsedEmail email, List<string> findings)
    {
        var now = DateTimeOffset.UtcNow;
        var diff = email.SentDate - now;

        if (diff > TimeSpan.FromDays(1))
        {
            findings.Add($"[DATE ANOMALY] Email claims to have been sent {diff.TotalDays:F1} day(s) in the future.");
            return 10;
        }
        if (now - email.SentDate > TimeSpan.FromDays(365))
        {
            findings.Add($"[DATE ANOMALY] Email date is more than one year old ({email.SentDate:yyyy-MM-dd}).");
            return 5;
        }
        return 0;
    }

    // ---------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------

    private static string? ExtractDomain(string value)
    {
        // Try it as an email address first
        var atIdx = value.LastIndexOf('@');
        if (atIdx >= 0)
            return value[(atIdx + 1)..].Trim().ToLowerInvariant();

        // Try it as a URL
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return uri.Host.ToLowerInvariant();

        return null;
    }
}
