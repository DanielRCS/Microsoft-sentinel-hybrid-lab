# New Account Added to Domain Admins

## Purpose

This detection identifies newly created domain accounts that are added to the `Domain Admins` group shortly after creation.

The goal is to detect potentially suspicious privilege escalation where a newly created account receives high-level administrative privileges within a short period of time.

## Data Source

- Microsoft Sentinel
- Windows Security Events
- Domain Controller telemetry
- Event ID 4720 - User account created
- Event ID 4728 - Member added to a security-enabled global group

## Detection Logic

The detection correlates account creation events with Domain Admin membership changes using the account SID.

Using the SID ensures the same account is matched across both events instead of correlating unrelated activity from the same domain controller.

```kusto
SecurityEvent
| where EventID == 4720
| project
    CreatedTime = TimeGenerated,
    CreatedAccount = TargetAccount,
    CreatedBy = SubjectAccount,
    AccountSid = TargetSid,
    Computer
| join kind=inner (
    SecurityEvent
    | where EventID == 4728
    | where TargetAccount has "Domain Admins"
    | project
        AddedTime = TimeGenerated,
        MemberName,
        AccountSid = MemberSid,
        TargetGroup = TargetAccount,
        AddedBy = SubjectAccount,
        Computer
) on AccountSid
| where AddedTime >= CreatedTime
| where AddedTime <= CreatedTime + 10m
| extend HostName = extract(@"^([^.]+)", 1, Computer)
| extend DnsDomain = extract(@"^[^.]+\.(.+)$", 1, Computer)
```

## Rule Configuration

- Severity: High
- Frequency: Every 5 minutes
- Lookback: 10 minutes
- MITRE ATT&CK Tactic: Privilege Escalation
- MITRE ATT&CK Technique: T1098 - Account Manipulation

## Entity Mapping

**Device**

- HostName
- DNS Domain

The device entity is mapped from the domain controller that generated the security events.

## Alert Details

The alert includes:

- Newly created account
- Account that created the user
- Time the account was created
- Domain Admin membership time
- Account that performed the group membership change
- Target privileged group

## Testing

The detection was tested by creating a temporary domain account and adding it to the `Domain Admins` group shortly after creation.

The initial version of the query correlated events using only the domain controller name, which produced duplicate matches.

The query was then improved to correlate Event ID 4720 `TargetSid` with Event ID 4728 `MemberSid`, ensuring the detection matches the exact same account across both events.

After updating the correlation logic, the duplicate matches were eliminated and the detection generated the expected High-severity incident.

## Result

The final detection successfully identified a newly created domain account receiving Domain Admin privileges shortly after account creation.

This detection demonstrates multi-event correlation using Windows Active Directory telemetry rather than relying on a single security event.
