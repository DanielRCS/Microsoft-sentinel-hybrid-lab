# Microsoft-sentinel-hybrid-lab
Hybris Microsoft Sentinel security lab for SIEM KQL, detection engineering, and incident response practice.

# Project Overview
This project is my hands-on lab for learning Microsoft Sentinel and getting more experience with security monitoring and incident investigation.

I already have a home lab running on a Dell PowerEdge t630 with XCP-ng, Active Directory, Windows 11 workstations, and Sysmon. Instead of creating a completely separate environment in Azure, I'm connecting my existing lab to Microsoft Sentinel and using it as a small simulated business network.

I'll be using the lab to practice collecting and analyzing security logs, writing KQL queries, creating detections, investigating alerts, and working through different security scenarios.

As I build out the environment, I'll document what I configure, problems I run into, KQL queries I create, and the investigations I complete.

# Lab Architecture
# On-Premises Environment
The local lab is hosted on a Dell PowerEdge T630 running XCP-ng with Xen Orchestra (XOA) for virtualization.

Current systems in the lab:
