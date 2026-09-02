# Suspicious Registry Run Key Persistence

## Purpose

This detection identifies suspicious modifications to Windows `Run` and `RunOnce` registry keys that may be used for persistence.

The goal is to detect cases where a process adds or changes a startup entry that could automatically execute when a user logs in.

---

## Data Source

- Microsoft Sentinel
- Sysmon
- Sysmon Event ID 13 - Registry Value Set
- Windows endpoint: COFFEE

---

## Detection Logic

The rule monitors Sysmon registry events for changes to common Windows startup locations:

```text
\Software\Microsoft\Windows\CurrentVersion\Run\
\Software\Microsoft\Windows\CurrentVersion\RunOnce\
```

The detection then looks for suspicious command interpreters, script hosts, temporary paths, or modifications made through `reg.exe`.

```kusto
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 13
| extend
    Image = extract(@"<Data Name=""Image"">([^<]+)</Data>", 1, EventData),
    TargetObject = extract(@"<Data Name=""TargetObject"">([^<]+)</Data>", 1, EventData),
    Details = extract(@"<Data Name=""Details"">([^<]+)</Data>", 1, EventData),
    User = extract(@"<Data Name=""User"">([^<]+)</Data>", 1, EventData)
| where TargetObject has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run\",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce\"
)
| where Details has_any (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    @"C:\Users\Public\",
    @"\AppData\Local\Temp\",
    @"\Temp\"
)
    or Image endswith @"\reg.exe"
| extend HostName = extract(@"^([^.]+)", 1, Computer)
| extend DnsDomain = extract(@"^[^.]+\.(.+)$", 1, Computer)
| project
    TimeGenerated,
    Computer,
    HostName,
    DnsDomain,
    User,
    Image,
    TargetObject,
    Details
| summarize
    MatchCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetObjects = make_set(TargetObject, 10),
    DetailsSet = make_set(Details, 10),
    Images = make_set(Image, 10)
    by Computer, HostName, DnsDomain, User
| order by LastSeen desc
```

---

## Rule Configuration

- Name: `Suspicious Registry Run Key Persistence`
- Severity: High
- Run Frequency: Every 5 minutes
- Lookback: 5 minutes
- MITRE ATT&CK Tactic: Persistence
- MITRE ATT&CK Technique: T1547.001 - Registry Run Keys / Startup Folder

---

## Alert Details

### Alert Title

```text
Suspicious Run key persistence on {{Computer}}
```

### Alert Description

```text
{{User}} generated {{MatchCount}} suspicious Run/RunOnce registry modifications on {{Computer}}.
```

---

## Custom Details

The alert includes:

- `MatchCount`
- `FirstSeen`
- `LastSeen`
- `TargetObjects`
- `DetailsSet`
- `Images`

These fields make it easier to review the registry paths, values, and processes involved without opening every individual event.

---

## Entity Mapping

### Impacted Asset

**Device**

- HostName → `HostName`
- DNS Domain → `DnsDomain`

---

## Testing

The rule was tested using Atomic Red Team technique:

```text
T1547.001 - Registry Run Keys / Startup Folder
```

The test created a registry value under:

```text
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

The observed Sysmon event showed:

```text
Process: C:\Windows\system32\reg.exe
Target:  ...\CurrentVersion\Run\Atomic Red Team
Value:   C:\Path\AtomicRedTeam.exe
User:    KINGDOM\it.admin
```

---

## Detection Tuning

The first version of the rule generated multiple incidents from a single Atomic Red Team test because several matching registry events were returned individually.

The query was updated to use `summarize`, grouping the matching events by:

- Computer
- Host
- Domain
- User

This reduced multiple matching registry events into a single detection result for the same user and device within the rule window.

After the update, the Atomic Red Team test generated one High-severity incident instead of several duplicate incidents.

---

## Recommended Investigation

When this detection triggers:

1. Review the registry path and value data.
2. Identify the process that created or modified the startup entry.
3. Verify whether the user and software are expected.
4. Review surrounding process and authentication activity.
5. Check for additional persistence mechanisms.
6. Remove the registry entry if unauthorized.
7. Investigate the endpoint and user account for related suspicious activity.

---

## Result

The final detection successfully identified Atomic Red Team registry persistence activity and generated a single High-severity incident.

This rule also demonstrated how detection logic can be tuned to reduce duplicate alerts while keeping the important persistence activity visible.
