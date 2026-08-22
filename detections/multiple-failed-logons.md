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
```

## Rule Configuration

- Severity: Medium
- Frequency: Every 5 minutes
- Lookback: 5 minutes
- Threshold: 5 or more failed logons
- MITRE ATT&CK: T1110.001 - Password Guessing

## Entity Mapping

**Device**

- HostName
- DNS Domain

This allows the alert to associate the activity with the affected Windows endpoint.

## Alert Details

The alert includes:

- Affected account
- Affected computer
- Number of failed logons
- First failed attempt
- Last failed attempt

## Testing

The rule was tested by generating five failed RDP authentication attempts against the COFFEE endpoint.

The detection successfully triggered and generated a Medium-severity Credential Access incident in Microsoft Sentinel.
