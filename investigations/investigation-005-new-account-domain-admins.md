# Investigation 005 - New Account Added to Domain Admins

## Incident Summary

A High-severity alert was generated after a newly created domain account was added to the `Domain Admins` group shortly after creation.

The activity was generated as part of a controlled lab simulation to test account lifecycle monitoring and privileged group detection.

## Alert Details

- Detection: New Account Added to Domain Admins Shortly After Creation
- Severity: High
- Data Source: Windows Security Events
- Domain Controller: ROSE
- Account: `temp.service`
- Privileged Group: `Domain Admins`
- Actor: `KINGDOM\Administrator`

## Investigation

The investigation focused on reviewing the full lifecycle of the `temp.service` account and determining how quickly the account received privileged access.

Windows Security Events showed the following activity:

- Event ID 4720 - Account created
- Event ID 4738 - Account modified
- Event ID 4724 - Password reset
- Event ID 4722 - Account enabled
- Event ID 4728 - Added to Domain Admins
- Event ID 4729 - Removed from Domain Admins
- Event ID 4725 - Account disabled
- Event ID 4726 - Account deleted

## Timeline

The account was created on August 22, 2026 at approximately 2:36:23 PM by `KINGDOM\Administrator`.

At approximately 2:37:55 PM, the account was added to the `Domain Admins` group.

The account received Domain Admin privileges approximately 1 minute and 32 seconds after being created.

At approximately 2:38:30 PM, the account was removed from `Domain Admins`, meaning the account retained privileged access for roughly 30-35 seconds.

The account was then disabled at approximately 2:38:36 PM and deleted at approximately 2:38:43 PM.

## Correlation

The investigation correlated Event ID 4720 and Event ID 4728 using the account SID.

This confirmed that the account created in the first event was the same account later added to the `Domain Admins` group.

Using the SID avoided false correlations between unrelated account creation and group membership events occurring on the same domain controller.

## Findings

The investigation confirmed that:

- A new domain account was created.
- The account received Domain Admin privileges shortly after creation.
- The privileged access was later removed.
- The account was disabled and deleted.
- The actions were performed by `KINGDOM\Administrator`.
- The activity was part of a controlled lab simulation.

If the same activity occurred unexpectedly in a production environment, it would require immediate validation because rapid privilege assignment to a newly created account could indicate unauthorized account creation or privilege escalation.

## Final Disposition

**Classification:** True Positive / Expected Lab Activity

The detection correctly identified the simulated privilege escalation activity.

Although the activity was intentionally generated for testing, the alert accurately represented behavior that would be considered high-risk if it occurred without authorization in a production Active Directory environment.
