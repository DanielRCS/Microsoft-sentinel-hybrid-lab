# Investigation - Repeated Failed RDP Logons

## Incident Summary

Microsoft Sentinel generated a Medium-severity incident after detecting five failed logon attempts against the same account within a five-minute period.

The affected account was:

`KINGDOM\test.user`

The affected endpoint was:

`Coffee.kingdom.hearts`

## Alert Details

The custom detection identified:

- 5 failed logon attempts
- Same account
- Same endpoint
- Attempts occurred within approximately 13 seconds
- MITRE ATT&CK: T1110.001 - Password Guessing

## Investigation

I reviewed Windows Security Event ID 4625 events associated with the account and endpoint.

The authentication attempts originated from the system I normally use to RDP into the COFFEE VM.

### Authentication Details

- Source IP: Known RDP client
- Logon Type: 10
- Logon Type Description: RemoteInteractive / RDP
- Failure Reason: Incorrect password
- Status: `0xC000006D`
- SubStatus: `0xC000006A`

The events showed that the attempts were remote interactive logons and failed because an incorrect password was entered.

## Successful Authentication Check

I searched for Windows Security Event ID 4624 events for the same account after the failed attempts.

No successful authentication was identified after the failed logons.

## Findings

The investigation confirmed:

- Five failed RDP authentication attempts occurred
- All attempts targeted the same account
- The attempts originated from a known source
- The failures were caused by an incorrect password
- No successful authentication followed the failed attempts
- No additional suspicious activity was identified

## Final Disposition

The source and activity were verified as part of controlled lab testing.

The incident was classified as:

**Benign / Expected Activity**

Although the activity was intentionally generated, the detection worked as expected and demonstrated the full workflow from Windows security telemetry to custom detection, alert generation, incident creation, and investigation.
