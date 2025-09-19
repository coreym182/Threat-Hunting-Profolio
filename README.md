# Threat Hunting Profolio

# Description

In this profolio, we will look at the different threat hunting scenarios that I have created.

---

# Technology Utilized
- Microsoft Defender (to gather log data)
- KQL scripts (to create scripts to search within logs)
- Azure Virtual Machines (to use their machine to analyze)
- PowerShell (to create some of the attack scenarios)
---


# Table of Contents

- ## Table of Contents
- [Scenario 1: Devices Exposed to the Internet](#scenario-1-devices-exposed-to-the-internet)
- [Scenario 2: Sudden Network Slowdowns](#scenario-2-sudden-network-slowdowns)
  
---

# Scenario 1: Devices Exposed to the Internet (UPDATE)

windows-target-1 is a server that has been internet-facing for several days. By being exposed to the internet, it is at risk of serveral types of cyberattacks including DDos, malware, data exflitration and others. I will check the logs to see if this server was exposed to the internet and for how long.


KQL code used to conduct the search


DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc 

<img width="468" height="203" alt="Picture1" src="https://github.com/user-attachments/assets/c2195d3c-1917-44a4-b1a6-460ab5649121" />

 
Based on the findings, the last internet-facing time for windows-targert-1 server was Sep 16, 2025 9:50:45 AM

—

Several bad actors have been discovered to log into our machine

KQL code used to conduct the search

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts

<img width="468" height="200" alt="Picture2" src="https://github.com/user-attachments/assets/a7bdb580-1d4c-4724-95e2-e5c32aba57fb" />

—

The top five IP addresses with the most failed login attempts have not been able to break into the VM successfully.

KQL code used to conduct the search

let RemoteIPsInQuestion = dynamic(["147.93.150.115","178.22.24.78", "176.46.158.12", "57.129.140.32", "194.180.49.61"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)

Based on the results, there was no failed login attempts by this user. The only successful remote/network logon in the last 30 days was for the “labuser” account (0 total)

-

I checked to see if there was any failed logon from labuser's account

KQL code used to conduct the search

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| distinct AccountName == "labuser"
| summarize count()

<img width="468" height="100" alt="Picture3" src="https://github.com/user-attachments/assets/8b97f0f0-7259-4a7c-a8f8-0f3142927021" />

There was one failed logon for the labuser account, indicating that a brute force attempt for this account could have taken place and was not successful.

—

We checked all of the successful login IP addresses for the “labuser” account to see if any of them were unusual or from an unexpected location. No results were found. 

—

Although the device was internet-facing, there was no indication of any brute force used to access this user’s account. 

—

Relevant MITRE ATT&CK TTPs:

Scenario 1: Devices Exposed to the Internet (UPDATE)

- **Exposed internet-facing asset** → [T1595.002: Active Scanning - Vulnerability Scanning]  
- **Failed remote login attempts from multiple IPs** → [T1110: Brute Force]  
- **Monitoring for successful logins after failed attempts** → [T1078: Valid Accounts]  
- **Assessment of unusual login locations** → [T1078.003: Valid Accounts - Domain Accounts]  

Notes:  
- Attackers attempted brute force but were unsuccessful.  
- No evidence of valid account compromise or persistence established

---

# Scenario 2: Sudden Network Slowdowns

corey-machine-v was found to be failing connect with another host on the same network. 

KQL code used to conduct the search

DeviceNetworkEvents
| where DeviceName == "corey-machine-v"
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionsAttempts desc


<img width="468" height="210" alt="Picture4" src="https://github.com/user-attachments/assets/12c61ab3-bb14-4e75-975e-771af3c7bec1" />

-

I conducted another search based on the IP address in question and the ConnectionFailed

KQL code used to conduct the search


let IPInQuestion = "10.1.0.161";
DeviceNetworkEvents
| where DeviceName == "corey-machine-v"
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc


<img width="468" height="240" alt="Picture5" src="https://github.com/user-attachments/assets/0acaccb9-9f81-4b43-8f2f-15ca2b561dd5" />



After observing a Failed Connection Request from our suspicious host (Remote IP: 10.0.0.5), in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted. 


I inspected one of the records from the logs.

KQL code used to conduct the search

let VMName = "corey-machine-v";
let specificTime = datetime(2024-10-18T04:09:37.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine


<img width="263" height="368" alt="Picture6" src="https://github.com/user-attachments/assets/b199bb71-bff5-40c1-98c4-43fff0df53f8" />

--

I logged into the client’s computer and observed the PowerShell script that was used to conduct a port scan.

<img width="468" height="327" alt="Picture7" src="https://github.com/user-attachments/assets/e9e8ce98-f2a8-4fae-a6a0-3b94b1072651" />

--

We observed that this port scan script was launched by the “system” account. This is not expected behavior and is not something that the admins set up. So I isolated the device and ran a malware scan. 

--

The malware scan produced no results, so, out of caution, we kept the device isolated and submitted a ticket to have it reimaged/rebuilt.

--

MITRE ATT&CK Framework Related TTPs:

T1046 — Network Service Discovery (Port Scanning)
T1018 — Remote System Discovery
T1059.001 — Command and Scripting Interpreter: PowerShell
T1078 — Valid Accounts (SYSTEM account abuse)
T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC
T1036 — Masquerading (possible)
T1562 — Impair Defenses (possible/antivirus evasion)


Response

Goal: Mitigate any confirmed threats.

Activity:
	•	Containment
	•	Isolate the affected host (corey-machine-v) from the network (already performed).
	•	Block suspicious IP addresses (e.g., 10.0.0.5 if confirmed malicious).
	•	Eradication
	•	Remove the malicious script (portscan.ps1).
	•	Investigate how it was executed by the SYSTEM account (potential privilege escalation or misconfiguration).
	•	Patch and update the system to eliminate known vulnerabilities.
	•	Recovery
	•	Reimage/rebuild the device to ensure a clean state (already submitted a ticket).
	•	Rejoin the host to the domain/network after verifying it is clean.
	•	Monitor network traffic closely post-recovery for reoccurrence.

Can anything be done?
✅ Yes. The following can be done to strengthen defenses:
	•	Implement application whitelisting to prevent unauthorized PowerShell script execution.
	•	Enable PowerShell logging and forward logs to SIEM for real-time detection.
	•	Restrict SYSTEM account usage to legitimate processes only.
	•	Deploy network segmentation to limit lateral movement attempts.
	•	Conduct a threat hunt across other endpoints to ensure no further compromise exists.


