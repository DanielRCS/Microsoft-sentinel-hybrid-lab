# Microsoft-sentinel-hybrid-lab
Hybrid Microsoft Sentinel security lab for SIEM KQL, detection engineering, and incident response practice.

# Project Overview
This project is my hands-on lab for learning Microsoft Sentinel and getting more experience with security monitoring and incident investigation.

I already have a home lab running on a Dell PowerEdge T630 with XCP-ng, Active Directory, Windows endpoints, Sysmon, and several security tools. Instead of creating a completely separate environment in Azure, I'm connecting my existing lab to Microsoft Sentinel and using it as a simulated business and security testing environment.

I'll be using the lab to practice collecting and analyzing security logs, writing KQL queries, creating detections, investigating alerts, and working through different security scenarios.

The rest of my XCP-ng lab includes Kali Linux, Security Onion, Splunk, a file server, and a Terraform controller. I plan to use some of these systems later as I expand the Sentinel lab and work through different security monitoring and attack simulation scenarios.

As I build out the environment, I'll document what I configure, problems I run into, KQL queries I create, and the investigations I complete.

## Lab Architecture

### On-Premises Environment
The local lab is hosted on a Dell PowerEdge T630 running XCP-ng with Xen Orchestra (XOA) for virtualization.

Current systems being used for this project:

- **Rose - Windows Server 2019**
  - Active Directory Domain Services
  - DNS
  - Sysmon

- **Coffee - Windows 10 Victim**
  - Domain joined
  - Sysmon
  
### Azure Environment
The Azure side of the lab currently includes:

- Resource Group: `RG-SecurityLab`
- Log Analytics Workspace: `law-securitygroup`
- Microsoft Sentinel
- Windows Security Events solution

### Phase 1 - Windows Security Event Collection

I onboarded my COFFEE Windows 10 VM to Azure Arc so I could connect my local home lab to Azure and start sending logs to Microsoft Sentinel.

I installed the Azure Monitor Agent (AMA) and created a Data Collection Rule (DCR) to collect Windows Security Events from COFFEE. I then used KQL in Sentinel to make sure the logs were actually coming in.

I ran into a few problems while setting everything up. One of the main issues was that my lab network is blocked from accessing the internet by default. I had to create firewall rules to allow the Azure traffic I needed.

I also ran into DNS and time sync issues. My domain controller wasn't able to reach an external NTP server, which caused the system time to be wrong and Azure authentication to fail. After fixing the firewall rules, DNS, and NTP, I was able to get COFFEE connected to Azure Arc and start receiving Windows Security Events in Sentinel.

### Investigation #001 - Failed Logins

For my first investigation, I purposely entered the wrong password several times on COFFEE so I could generate failed login events and then find them in Sentinel.

Using KQL, I found five Event ID 4625 events for the `KINGDOM\IT.Admin` account. I looked through the events to find where the attempts came from, the logon type, and why the login failed.

The attempts came from my main PC that I use to RDP into COFFEE. The events showed Logon Type 7 (Unlock), status `0xC000006D`, and substatus `0xC000006A`, which showed that the password entered was incorrect.

I then searched for a successful login and found an Event ID 4624 for the same account and source IP.

Since I knew the source PC and I purposely generated the failed logins, I was able to confirm that this was normal activity and not an actual attack.

This investigation helped me get more familiar with using KQL to search Windows Security Events and also showed me why it's important to look at more than just the failed login event before deciding if something is suspicious.

## Detection & Incident Response

### Multiple Failed Logons

Created a custom Microsoft Sentinel detection for repeated failed logon attempts against the same account.

The rule monitors Windows Security Event ID 4625 and triggers when an account has five or more failed logons within a five-minute window. The alert includes the affected account, device, failed logon count, and attempt timestamps.

I tested the rule using repeated failed RDP authentication attempts against the COFFEE endpoint. Sentinel generated a Medium-severity Credential Access incident, which I investigated using Event IDs 4625 and 4624.

The investigation identified:
- Source IP of the authentication attempts
- Logon Type 10 (RemoteInteractive/RDP)
- Incorrect password failures
- No successful authentication after the attempts

The source was verified as known lab activity, and the incident was closed as benign.

[View detection logic](detections/multiple-failed-logons.md)

[View full incident investigation](investigations/investigation-004-failed-rdp-detection.md)

## Current Progress

- [x] Built XCP-ng home lab environment
- [x] Configured Active Directory domain environment
- [x] Installed Sysmon on Windows lab systems
- [x] Created Azure resource group
- [x] Created Log Analytics Workspace
- [x] Enabled Microsoft Sentinel
- [x] Installed Windows Security Events solution
- [x] Onboarded COFFEE to Azure Arc
- [x] Configured Azure Monitor Agent
- [x] Send Windows Security Events to Sentinel
- [x] Send Sysmon telemetry to Sentinel
- [x] Verify telemetry using KQL
- [x] Create first custom detection
- [x] Investigate first Sentinel incident
