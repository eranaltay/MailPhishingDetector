# MailPhishingDetector

A slim, server-side C# 10 / .NET 6 application with **two independent input modes**:

1. **Local drop folder** — drop `.eml` files into `./drop/` for instant analysis (great for development)
2. **IMAP inbox mode** — users forward suspicious emails to a dedicated mailbox; the app polls it and sends the report back automatically

No paid services required.

---

## How it works

### Mode 1 — Local file drop

```
.eml file saved to  ./drop/
        │
        ▼
EmlWatcherService detects the file (FileSystemWatcher)
        │
        ▼
EmlParserService  – extracts headers, body, URLs, attachments
        │
        ▼
PhishingDetectorService – scores 0–100 against 15 heuristic rules
        │
        ▼
ReportSenderService – emails the result back to the To: recipients
        │
        ▼
File moved to  ./done/  (or  ./error/  on failure)
```

### Mode 2 — IMAP inbox (real-world flow)

```
User receives a suspicious email
        │
        ▼
User selects "Forward as Attachment" → sends to scan@gmail.com
        │
        ▼  (IMAP poll every N seconds — default 30s)
ImapFetchService connects, searches for unseen messages
        │
        ├─ Finds message/rfc822 attachment  →  parse the ORIGINAL attached email
        └─ No attachment found  →  warn user, move to Error folder, skip
        │
        ▼
EmlParserService.ParseMessage(MimeMessage)
        │
        ▼
PhishingDetectorService.Analyse(ParsedEmail)
        │
        ▼
ReportSenderService.SendReportAsync(report, forwarderAddress)
  (report goes back to the person who forwarded — not the original sender)
        │
        ▼
IMAP: mark Seen, move message to "Processed" folder
      (or "Error" folder on failure)
```

---

## Project layout

```
src/
├── MailPhishingDetector.csproj
├── Program.cs
├── appsettings.json
├── Models/
│   ├── ParsedEmail.cs      – immutable record for a parsed email
│   └── PhishingReport.cs   – analysis result (score, risk level, findings)
└── Services/
    ├── EmlParserService.cs         – MimeKit wrapper; Parse(filePath) + ParseMessage(MimeMessage)
    ├── PhishingDetectorService.cs  – 15-rule heuristic engine
    ├── ReportSenderService.cs      – formats HTML + plain-text report, sends via SMTP
    ├── EmlWatcherService.cs        – FileSystemWatcher drop-folder mode
    └── ImapFetchService.cs         – IMAP polling mode
```

---

## Detection rules

| # | Rule | Max points |
|---|------|-----------|
| 1 | Sender display-name / Reply-To domain mismatch | 25 |
| 2 | SPF fail / softfail / missing | 20 |
| 3 | DKIM missing or failed | 15 |
| 4 | DMARC fail | 15 |
| 5 | Return-Path domain mismatch | 10 |
| 6 | Urgency / social-engineering keywords in subject or body | 20 |
| 7 | Excessive external URLs (> 15) | 15 |
| 8 | URL-shortener links (bit.ly, tinyurl, etc.) | 25 |
| 9 | IP-address-based URLs | 30 |
| 10 | Brand impersonation in subdomain (paypal.attacker.com style) | 35 |
| 11 | javascript: / data: obfuscated URLs | 30 |
| 12 | HTML body with no plain-text alternative | 8 |
| 13 | Dangerous attachment extensions (.exe, .ps1, .js, …) | 40 |
| 14 | Excessive Received: hops (> 7) | 8 |
| 15 | Date anomaly (future or > 1 year old) | 10 |

**Score thresholds**

| Score | Risk level |
|-------|-----------|
| 0–10  | Safe |
| 11–30 | Low |
| 31–55 | Medium |
| 56–75 | High |
| 76–100| Critical |

---

## Prerequisites

- [.NET 6 SDK](https://dotnet.microsoft.com/download/dotnet/6.0)
- An SMTP server for sending reports (see options below)
- *(IMAP mode only)* A free email inbox with IMAP access

---

## Getting started

### 1. Configure SMTP (for sending reports)

Edit `src/appsettings.json`:

```json
"Smtp": {
  "Host":        "smtp.gmail.com",
  "Port":        587,
  "UseTls":      true,
  "Username":    "your-sender@gmail.com",
  "Password":    "YOUR_GMAIL_APP_PASSWORD",
  "FromAddress": "your-sender@gmail.com",
  "FromName":    "Mail Phishing Detector"
}
```

> **Tip for local testing** — use [Papercut](https://github.com/ChangemakerStudios/Papercut-SMTP) or [MailHog](https://github.com/mailhog/MailHog) as a local SMTP sink:
> ```json
> "Smtp": { "Host": "localhost", "Port": 25, "UseTls": false, "Username": "", "Password": "" }
> ```

Sensitive values can also be supplied via environment variables:

```bash
Smtp__Password=secret dotnet run
```

### 2. Build and run

```bash
cd src
dotnet restore
dotnet build
dotnet run
```

---

## Mode 1 — Local drop folder

Drop any `.eml` file into the `drop/` folder. The service detects it within half a second, analyses it, sends the report to the email's `To:` recipients, and moves the file to `done/`.

---

## Mode 2 — IMAP inbox (recommended for production)

### Step A: Set up a free dedicated Gmail inbox

1. Create (or reuse) a Gmail account — e.g. `scan@gmail.com`
2. Enable IMAP:
   - Gmail → Settings → See all settings → Forwarding and POP/IMAP → **Enable IMAP** → Save
3. Create a Google App Password (required since Google disabled plain-password IMAP):
   - Google Account → Security → 2-Step Verification → App passwords
   - App: **Mail**, Device: **Other** (name it "MailPhishingDetector") → Generate
   - Copy the 16-character password

> **Alternative free providers**
> | Provider | IMAP host | Port | Notes |
> |----------|-----------|------|-------|
> | Gmail | `imap.gmail.com` | 993 | Needs App Password |
> | Outlook / Hotmail | `outlook.office365.com` | 993 | Needs App Password |
> | Zoho Mail | `imap.zoho.com` | 993 | Free 1-user plan, standard IMAP |

### Step B: Configure the app

In `src/appsettings.json`, set `"Enabled": true` and fill in your credentials:

```json
"Imap": {
  "Enabled":             true,
  "Host":                "imap.gmail.com",
  "Port":                993,
  "UseSsl":              true,
  "Username":            "scan@gmail.com",
  "Password":            "abcd efgh ijkl mnop",
  "InboxFolder":         "INBOX",
  "ProcessedFolder":     "Processed",
  "ErrorFolder":         "Error",
  "PollIntervalSeconds": 30
}
```

### Step C: Tell users how to forward

Users should use **"Forward as Attachment"** (not regular forward):

| Mail client | How |
|-------------|-----|
| **Gmail** | Open email → More (⋮) → **Forward as attachment** |
| **Outlook** | Open email → More actions → **Forward as attachment** |
| **Thunderbird** | Message menu → **Forward as** → **Attachment** |
| **Apple Mail** | Message menu → **Forward as Attachment** |

> This is critical. Regular inline forwarding discards the original email headers
> (SPF, DKIM, sender domain), which disables most detection rules. Only "Forward as
> Attachment" preserves the full original email as an embedded `message/rfc822` part.

### Step D: Run and observe

```bash
dotnet run
# [2026-03-12 10:00:00] IMAP fetch service started — polling 'INBOX' on imap.gmail.com:993 every 30s.
# [2026-03-12 10:00:30] Found 1 unseen message(s) to process.
# [2026-03-12 10:00:30] Processing UID 42 forwarded by 'alice@company.com'…
# [2026-03-12 10:00:31] Analysis done — Score 65/100, Risk: High, Findings: 4.
# [2026-03-12 10:00:31] Report sent to alice@company.com for message '<...>'.
```

The forwarded message is moved to the `Processed` folder in the inbox. Alice receives a formatted HTML + plain-text analysis report in her inbox.

---

## Extending the app

| Goal | Where to edit |
|------|--------------|
| Add a new detection rule | `PhishingDetectorService.cs` — add a private method, call it from `Analyse()` |
| Persist reports to a database | Inject `DbContext` after `_detector.Analyse()` in `ImapFetchService` and `EmlWatcherService` |
| Expose a REST API | Switch to `Microsoft.NET.Sdk.Web` and add controllers |
| Run as a systemd service | Add a `.service` unit file pointing to `dotnet run` |

---

## License

MIT
