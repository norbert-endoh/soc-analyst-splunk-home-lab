# Lab Build & Telemetry Validation

**Objective:** Build a small, centralized SOC monitoring environment, collect Windows endpoint telemetry in Splunk, and **prove** the data pipeline works before writing any detection.

## Architecture

```text
Windows 11 physical host  -  VMware Workstation (bridged networking)
 |
 |-- Windows 10 Pro (DESKTOP-4AMTH10)  -  monitored endpoint
 |       Splunk Universal Forwarder --- TCP 9997 ---> Splunk Enterprise
 |
 |-- Ubuntu Server 24.04 LTS (10.0.0.85)  -  Splunk Enterprise 10.4.3 (SIEM)
 |
 |-- Kali Linux  -  SOC analyst workstation --- Splunk Web, TCP 8000 ---> Splunk Enterprise
```

**Design choice:** I put the SIEM on its own Ubuntu server instead of the monitored endpoint. That separates the endpoint, the SIEM infrastructure and the analyst workstation, the way an enterprise SOC is laid out.

## Build Steps

| # | Step | Detail |
|---|---|---|
| 1 | SIEM server | Created a dedicated Ubuntu Server 24.04 LTS VM (bridged), enabled OpenSSH, applied OS updates |
| 2 | Splunk Enterprise | Installed Splunk Enterprise 10.4.3, set ownership and permissions, started services, confirmed Splunk Web on TCP 8000 |
| 3 | Receiving port | Configured Splunk to receive forwarded data on **TCP 9997** |
| 4 | Endpoint agent | Installed **Splunk Universal Forwarder 10.4.3** (Windows x64) on Windows 10, pointed at 10.0.0.85:9997 |
| 5 | Analyst access | Used Kali Linux (Firefox) to work in Splunk Search & Reporting |

> Configuring port 9997 alone does not prove that logs are arriving, so every step was validated with SPL.

## Telemetry Validation

**1. Is the endpoint sending data?**
```spl
index=* host=* | stats count by host
```
Result: `DESKTOP-4AMTH10` with roughly **28,000 indexed events**, confirming end-to-end ingestion.

**2. What data types are arriving?**
```spl
index=* host="DESKTOP-4AMTH10" | stats count by sourcetype
```

| Sourcetype | Approx. events | Meaning |
|---|---|---|
| WinEventLog:Security | 21,814 | Authentication, account and privilege audit events |
| WinEventLog:Application | 2,842 | Application events |
| WinEventLog:System | 2,495 | OS and service events |
| Perfmon:Network Interface | 380 | Network performance |
| Perfmon:CPU Load | 365 | CPU performance |
| Perfmon:Available Memory | 194 | Memory performance |

**3. Which security events exist?**
```spl
index=* host="DESKTOP-4AMTH10" sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort - count
```
I profiled the Event IDs actually being collected before choosing a use case, letting the evidence guide the detection work rather than assuming the data existed.

## Event IDs Used in This Project

| Event ID | Meaning | Used for |
|---|---|---|
| 4624 | Successful logon | Authentication correlation, dashboard |
| 4625 | Failed logon | Brute-force detection (Use Case 01) |
| 4672 | Special privileges assigned | Privileged logon monitoring |
| 4688 | Process creation | Post-logon investigation, PowerShell detection |
| 4720–4726 | Account created, changed or deleted | Account-management monitoring, local account creation alert |
| 4732 / 4733 | Member added to or removed from a local group | Administrator group change alerts |

**Next:** [Detection engineering →](02_DETECTION_ENGINEERING.md)

[← Back to project overview](../README.md)
