namespace MailPhishingDetector.Models;

public enum RiskLevel { Safe, Low, Medium, High, Critical }

/// <summary>
/// Result of the phishing analysis for one email.
/// </summary>
public record PhishingReport
{
    public string MessageId    { get; init; } = string.Empty;
    public string Subject      { get; init; } = string.Empty;
    public string FromAddress  { get; init; } = string.Empty;

    /// <summary>0–100 composite score. Higher = more suspicious.</summary>
    public int Score           { get; init; }

    public RiskLevel RiskLevel { get; init; }

    /// <summary>Human-readable explanations for every triggered rule.</summary>
    public IReadOnlyList<string> Findings { get; init; } = Array.Empty<string>();

    public DateTimeOffset AnalysedAt { get; init; } = DateTimeOffset.UtcNow;
}
