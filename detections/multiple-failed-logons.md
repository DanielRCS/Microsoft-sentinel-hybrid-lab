# Multiple Failed Logons Detection

## Purpose

This detection identifies repeated Windows failed logon attempts against the same account within a short time period.

The goal is to surface activity that could indicate password guessing or repeated failed authentication attempts.

## Data Source

- Microsoft Sentinel
- Windows Security Events
- Event ID 4625

## Detection Logic

```kusto
SecurityEvent
| where EventID == 4625
| extend HostName = extract(@"^([^.]+)", 1, Computer)
| extend DnsDomain = extract(@"^[^.]+\.(.+)$", 1, Computer)
| extend AccountDomain = extract(@"^([^\\]+)\\", 1, Account)
| extend AccountName = extract(@"\\(.+)$", 1, Account)
| summarize
    FailedLogons = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Account, Computer, HostName, DnsDomain, AccountName, AccountDomain
| where FailedLogons >= 5
