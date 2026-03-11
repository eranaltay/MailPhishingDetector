# MailPhishingDetector

A slim, server-side C# 10 / .NET 6 application that monitors a local drop folder
for `.eml` files, analyses each one for phishing and spam indicators, and sends
an automated analysis report back to the original recipients via SMTP.

---

## How it works

```
User receives suspicious mail
          │
          ▼
  Forwards it to a designated inbox
          │
          ▼  (manually, or via an IMAP-fetch step added later)
  .eml file saved to  ./drop/
          │
          ▼
  EmlWatcherService detects the file
          │
          ▼
  EmlParserService  – extracts headers, body, URLs, attachments
          │
          ▼
  PhishingDetectorService – scores the email (0-100) against 13 heuristic rules
          │
          ▼
  ReportSenderService – emails the result back to the To: recipients
          │
          ▼
  File moved to  ./done/  (or  ./error/  on failure)
```

---

## Project layout

```
src/
├── MailPhishingDetector.csproj
├── Program.cs
├── appsettings.json
├── Models/
│   ├── ParsedEmail.cs      – data record for a parsed EML
│   └── PhishingReport.cs   – analysis result (score, risk level, findings)
└── Services/
    ├── EmlParserService.cs         – wraps MimeKit to parse .eml files
    ├── PhishingDetectorService.cs  – 13-rule heuristic engine
    ├── ReportSenderService.cs      – formats and sends the report via SMTP
    └── EmlWatcherService.cs        – FileSystemWatcher + orchestration
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
- An SMTP server (or local relay such as [Papercut](https://github.com/ChangemakerStudios/Papercut-SMTP) / MailHog for testing)

---

## Getting started

### 1. Configure

Edit `src/appsettings.json`:

```json
{
  "Watcher": {
    "DropFolder":  "./drop",   // place .eml files here
    "DoneFolder":  "./done",   // processed files land here
    "ErrorFolder": "./error"   // failed files land here
  },
  "Smtp": {
    "Host":        "smtp.example.com",
    "Port":        587,
    "UseTls":      true,
    "Username":    "user@example.com",
    "Password":    "secret",
    "FromAddress": "phishing-detector@example.com",
    "FromName":    "Mail Phishing Detector"
  }
}
```

Sensitive values can also be supplied through environment variables
(the standard .NET configuration override):

```
Smtp__Password=secret dotnet run
```

### 2. Build and run

```bash
cd src
dotnet restore
dotnet build
dotnet run
```

### 3. Drop an EML file

Save any `.eml` file into the `drop/` folder.  The service detects it within
half a second, analyses it, sends the report, and moves the file to `done/`.

### 4. Test locally without an SMTP server

Point `Smtp.Host` to a local SMTP sink such as **Papercut** or **MailHog**:

```json
"Smtp": {
  "Host":   "localhost",
  "Port":   25,
  "UseTls": false,
  "Username": "",
  "Password": ""
}
```

---

## Extending the app

| Goal | Where to edit |
|------|--------------|
| Add a new detection rule | `PhishingDetectorService.cs` — add a private method, call it from `Analyse()` |
| Fetch EMLs from an IMAP inbox | Add a new `ImapFetchService : BackgroundService` alongside `EmlWatcherService` |
| Persist reports to a database | Inject `DbContext` into `EmlWatcherService.HandleFileAsync` after analysis |
| Expose a REST API | Switch to `Microsoft.NET.Sdk.Web` and add controllers |

---

## License

MIT
