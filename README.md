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
- Log Analytics Workspace: `LAW-SecurityLab`
- Microsoft Sentinel
- Windows Security Events solution

The next step is onboarding the Coffee Windows 10 VM through Azure Arc so that I can begin sending Windows Security and Sysmon telemetry to Microsoft Sentinel.

## Current Progress

- [x] Built XCP-ng home lab environment
- [x] Configured Active Directory domain environment
- [x] Installed Sysmon on Windows lab systems
- [x] Created Azure resource group
- [x] Created Log Analytics Workspace
- [x] Enabled Microsoft Sentinel
- [x] Installed Windows Security Events solution
- [ ] Onboard Coffee to Azure Arc
- [ ] Configure Azure Monitor Agent
- [ ] Send Windows Security Events to Sentinel
- [ ] Send Sysmon telemetry to Sentinel
- [ ] Verify telemetry using KQL
- [ ] Create first custom detection
- [ ] Investigate first Sentinel incident
