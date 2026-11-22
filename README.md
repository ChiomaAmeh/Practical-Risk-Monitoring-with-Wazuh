# GRC103 Practical Laboratory: Practical Risk Monitoring with Wazuh (File Integrity Monitoring)

| | |
|---|---|
| **Student** | Chioma Ameh |
| **Registration number** | C11/26/CGRCE/17567 |
| **Course** | GRC103 - Risk Assessment and Management Techniques |
| **Date performed** | 19–20 Nov 2026 |

**Demonstration video:** 

> Lab note: only dummy files were used. Passwords, agent keys, and other secrets are concealed in all evidence.

---

## 1. Executive summary

A risk assessment rated **unauthorised modification or deletion of financial forecast documents** as a medium-to-high risk. The approved treatment was a **detective control**. I deployed **Wazuh File Integrity Monitoring (FIM)** with the manager on an Ubuntu VM and an agent on a Windows endpoint. I monitored a dedicated folder, generated controlled create/modify/delete events, and located the matching alerts in the central dashboard. The control **detected** all three events (rules 554, 550, and 553, each raised in real time and matching my test log to the second). It does **not prevent** them, so complementary preventive and corrective controls are recommended (Section 5).

## 2. Laboratory architecture

```
 Windows host (Control Agent)                 Ubuntu VM in VirtualBox (Risk Monitoring Platform)
 Wazuh agent  ──── TCP 1514 (events) ───────► Wazuh manager + indexer + dashboard
 Monitors: C:\Users\USER\SensitiveFiles      Browser (host) ──► https://192.168.100.17 (port 443)
              Both are on the same LAN via VirtualBox Bridged Adapter
```

![SSH login from the Windows host to the Ubuntu VM](evidence/00a-ssh-login.png)
![Windows host network configuration (192.168.100.3)](evidence/00b-windows-ipconfig-b.png)

### Software versions

| Component | Version |
|---|---|
| Host OS | Microsoft Windows 11 Pro, version 10.0.26300 (build 26300) |
| VirtualBox | 7.2.6 (r172322) |
| Ubuntu VM | Ubuntu 24.04.5 LTS (noble), kernel 6.8.0-149-generic; VirtualBox VM `ubuntu-server` (hostname `ubuntu`): 2 vCPU, 5.8 GiB RAM (6144 MB), 23 GB root volume on a 25 GB virtual disk, Bridged adapter on Wi-Fi |
| Wazuh manager | 4.12.0, all-in-one (manager, indexer, dashboard, Filebeat) installed with `wazuh-install.sh -a -i`; installation completed 19 Nov 2026, 17:32 UTC |
| Wazuh agent | 4.12.0 on Windows 11 Pro (agent name Finance-Dept-Workstation, ID 001) |
| Browser | Microsoft Edge 157.0.4341.60 |

| Item | Value |
|---|---|
| Ubuntu VM IP | 192.168.100.17/24 (Windows host 192.168.100.3, gateway 192.168.100.1) |
| Agent name / ID | Finance-Dept-Workstation / 001 |
| Monitored path | C:\Users\USER\SensitiveFiles |

## 3. Implementation and evidence

### 3.1 Deployment (Evidence 1)
Wazuh was deployed on the Ubuntu VM using the all-in-one installer from the lab brief.

![Ubuntu platform details (a)](evidence/01a-ubuntu-platform-a.png)
![Ubuntu platform details (b)](evidence/01b-ubuntu-platform-b.png)
![VirtualBox VM details](evidence/01c-virtualbox-vm-details.png)
![VirtualBox settings: system and storage](evidence/01d-vbox-settings-system-storage.png)
![VirtualBox settings: Bridged network adapter](evidence/01d-vbox-settings-storage-network.png)
![Firewall rules restricted to lab host](evidence/01e-ufw-rules.png)
![Wazuh version and IP](evidence/02c-ip-addr-and-wazuh-version.png)
![Manager and indexer services active](evidence/02b-manager-indexer-active.png)
![Dashboard service active](evidence/02b-dashboard-service-active.png)
![Dashboard login page (https://192.168.100.17)](evidence/02-dashboard-login-page.png)
![Dashboard access after login (credentials not shown)](evidence/02-dashboard-login-success.png)

### 3.2 Agent registration (Evidence 2)
Agent key generated with `manage_agents` on the manager and applied in the Windows Wazuh Agent Manager.

![Agent before registration (no key imported)](evidence/03c-agent-before-registration.png)
![Agent service running on Windows](evidence/03b-agent-installed.png)
![Agent Active on the manager (agent_control -i 001)](evidence/04b-agent-details.png)

### 3.3 Monitoring configuration (Evidence 3)
Excerpt from `C:\Program Files (x86)\ossec-agent\ossec.conf` (no secrets):

```xml
<syscheck>
  ...
  <directories realtime="yes">C:\Users\USER\SensitiveFiles</directories>
</syscheck>
```

![ossec.conf excerpt](evidence/05-ossec-conf-excerpt.png)
![Agent connected to manager](evidence/05b-agent-connected-log.png)
![Manager address in ossec.conf](evidence/05c-ossec-conf-manager-address.png)

### 3.4 Control verification (Evidence 4)

**Timestamped test log** (see `logs/test-log.csv`; timezone: WAT, UTC+1):

| # | Action | File | Time (WAT) |
|---|---|---|---|
| 1 | Create | Q4_Financial_Forecast.docx | 2026-11-20 23:19:47 (UTC 22:19:47) |
| 2 | Modify (text appended) | Q4_Financial_Forecast.docx | 2026-11-20 23:20:17 (UTC 22:20:17) |
| 3 | Delete | Q4_Financial_Forecast.docx | 2026-11-20 23:20:47 (UTC 22:20:47) |

**Alerts located in the dashboard:**

| Action | Rule ID | Rule description | Alert time | Matches test log? |
|---|---|---|---|---|
| Added | 554 | File added to the system | 22:19:47 UTC (23:19:47 WAT); Mode: realtime; size 0 | Yes, same second |
| Modified | 550 | Integrity checksum changed | 22:20:17 UTC (23:20:17 WAT); size 0→45 bytes; md5, sha1, sha256 changed | Yes, same second |
| Deleted | 553 | File deleted | 22:20:47 UTC (23:20:47 WAT); size 45 | Yes, same second |


![Timestamped test log](evidence/09-test-log.png)
![Alerts on the manager (command line)](evidence/06-alerts-cli.png)
![Deleted event in the Wazuh dashboard (Discover, syscheck)](evidence/08b-dashboard-discover-deleted-event.png)

Alerts as logged by the manager: `logs/fim-alerts-from-manager.txt` (transcribed from `evidence/06-alerts-cli.png`). Test log: `logs/test-log.csv`.

**Monitoring coverage and retention.** Absence of alerts is not treated as proof that nothing changed. Coverage was verified before testing: the agent was *Active* (`agent_control -i 001`: Windows 11 Pro, Wazuh v4.12.0, recent keep-alive), the monitored path is present in `ossec.conf` with `realtime="yes"`, and each alert shows `Mode: realtime`. Alerts are kept in `/var/ossec/logs/alerts/` and the Wazuh indexer; no retention policy was configured or tested in this short lab, so no conclusion is drawn about periods outside the test window.

---

## 4. GRC analysis (workshop questions)

### 4.1 Risk identification and analysis

**Business impact if the risk were realised.**
- *Financial:* altered forecasts can drive wrong budgeting, investment and pricing decisions, and may cause misstated reporting, penalties or fraud losses.
- *Reputational:* investors, regulators and clients lose confidence if figures are shown to have been tampered with.
- *Operational:* teams lose time investigating and restoring trusted versions; decisions are delayed while data integrity is in doubt.
- *Legal/compliance:* failing to protect financial records can breach SOX, PCI DSS, or similar obligations.

**How the control helps quantify the risk.** Each alert is a timestamped, countable event. Counting events by type (added/modified/deleted), by file, by user/endpoint, and by period gives a measurable **frequency (likelihood indicator)**. Trends (for example, a spike in deletions near quarter-end) support re-rating likelihood in the risk register. In this lab, 3 events were generated in 1 minute (23:19:47 to 23:20:47 WAT) and 3 alerts (rules 554, 550, 553) were raised with timestamps matching the test log to the second, showing the control records every change. Impact is then estimated by pairing these counts with the value of the affected documents.

### 4.2 Control evaluation and treatment

**Preventive control (complementary).** Least-privilege access control with NTFS permissions on the folder (read-only for most users, write for named owners), plus file-server versioning/immutable backups, application whitelisting and endpoint DLP. These **stop** or limit the change; FIM only **detects** it.

**Corrective control scenario.** Wazuh raises a "file deleted" alert for a forecast file at 02:00, outside business hours. The SOC/GRC analyst triages it, confirms with the file owner that it was not authorised, isolates the endpoint, **restores the file from backup**, resets the user's credentials, and opens an incident. Restoration and containment are the corrective controls. A Wazuh active response could automate part of this.

**Detective vs. preventive.** FIM does not block changes; it records them. Importantly, **an alert shows that a change occurred, not that it was unauthorised.** A legitimate edit by the owner produces the same alert, so analysts must correlate with change tickets and user context before declaring an incident.

### 4.3 Risk monitoring and reporting

**Three metrics for management:**
1. **FIM event volume by type, path, and time** (added/modified/deleted per week), showing activity levels and trends.
2. **Agent coverage/availability**: percentage of in-scope endpoints with agent status *Active* during the period (an offline control provides no assurance).
3. **Alerts by rule ID and severity level, with the top changed file paths** (Events dashboard breakdown), used to prioritise triage. Detection latency (file event time in the test log vs alert time in the dashboard) is reported as a supporting figure; in this lab each alert carried the same timestamp second as its action, so latency was under one second.

**Why central monitoring improves governance and auditability.** One consolidated, time-synchronised audit trail across all endpoints replaces checking logs machine by machine. Logs are harder for a local attacker to alter or delete, retention and access are managed centrally, reporting and sampling for auditors is faster and consistent, and gaps in coverage are visible in one place. This supports accountability, segregation of duties (monitoring separate from the monitored user), and repeatable evidence.

### 4.4 Compliance mapping

**Evidence for audits.** Wazuh provides tamper-evident, timestamped records of file events (path, action, checksums before/after, agent), the configuration showing which paths are monitored, and agent status history. Together, they show the control is **designed** (config) and **operating** (alerts and coverage). This maps to file-integrity-monitoring expectations in PCI DSS (Req. 11.5), SOX IT general controls, and HIPAA integrity safeguards.

**Demonstrating a file was unchanged in a period (e.g., last quarter).**
1. Confirm the agent was *Active* and the path was monitored for the whole quarter, and that alert retention covers the quarter.
2. In the dashboard, filter `agent.name`, `syscheck.path : "<full path>"` and `rule.groups: syscheck` over the quarter's date range.
3. Show that no *modified/deleted* events exist, and show from the FIM inventory that the file's current checksum equals its baseline checksum.
Absence of alerts is only meaningful if steps 1 and 3 are verified; otherwise, it could reflect a monitoring gap rather than no change.

---

## 5. Recommended controls

| Type | Recommendation |
|---|---|
| Preventive | NTFS least-privilege permissions, file versioning/immutable backups, MFA on accounts with write access, DLP |
| Detective (enhance) | Enable `whodata` auditing on Windows to capture *who/which process* changed the file; email/Slack alert for rule 553 and 550 on this path; alert on agent disconnection |
| Corrective | Documented incident runbook, restore-from-backup procedure, credential reset, post-incident review |

## 6. Limitations encountered

- Single-node, all-in-one lab deployment (no component separation or redundancy); production would separate components to avoid a single point of failure.
- Real-time monitoring records the change but, without who-data, not the user responsible.
- Lab uses dummy files; Word may create extra temporary-file events (e.g. `~$` files).
- Clock/timezone differences: Windows (WAT) vs. manager logs (UTC) required conversion when matching the test log.
- The first Ubuntu VM (`Ubuntu-Wazuh`) could not be used because its login was unknown, so a second Ubuntu VM (`ubuntu-server`) was prepared instead.
- The VM initially had 1.9 GiB RAM and a NAT adapter (10.0.2.15). RAM was raised to 6144 MB, and the adapter was changed to Bridged, as the lab requires.
- Only 12 GB of the 25 GB virtual disk was in use; the LVM root volume was extended to 23 GB with `lvextend -r -l +100%FREE`.
- Windows could ping the VM, but TCP port 22 timed out. The cause was the Ubuntu `ufw` firewall, which was active. Rules were added allowing ports 22 (SSH), 443 (dashboard), and 1514 (agent) **only from the lab Windows host (192.168.100.3)**, which also satisfies the instruction to restrict communication to lab systems. If the host IP changes, the rules must be updated.
- The VirtualBox console does not support copy/paste, so SSH from Windows PowerShell was used to run long commands.
- The brief creates the monitored folder in Part 6, after the agent restart in Part 5. I created `SensitiveFiles` **before** restarting the agent so that real-time monitoring is attached to the folder at start-up; the configuration line itself is exactly as specified.
- The brief names the dashboard menu "Security Events" and the agent fields "Management tab / Agent key / Manager address". In the installed version, the equivalent screens are labelled Threat Hunting / Discover (Events) and Manager IP / Authentication key; the function is the same.
- The brief describes `-i` as "interactive mode". In the Wazuh installer, it is the option that ignores the hardware-requirements check; the command was run exactly as given.
- The first installation attempt (started 11:57 UTC) failed after about 20 minutes with `Cannot install dependency: debhelper`. Speed tests showed the default Ubuntu mirror returned 0 bytes over the VM's IPv6 route, but 121 kB/s with IPv4 forced. `apt` was set to IPv4 only (`Acquire::ForceIPv4`) and switched to `archive.ubuntu.com` (about 397 kB/s). The second attempt succeeded; it took about 3.5 hours (14:06 to 17:32 UTC) because downloads from `packages.wazuh.com` averaged roughly 0.1 to 0.25 MB/s.
- The Ubuntu VM and Wazuh logs use UTC; Windows uses WAT (UTC+1). Times in alerts were converted when matching the test log.
- The installer printed the generated admin password on screen. It was copied to a private file outside the repository, and no screenshot showing it is included.
- An older Wazuh agent installation on the Windows host was configured for a different manager (192.168.100.25) and was left without a service or executables. It was uninstalled, its folder deleted, and the agent reinstalled and pointed at the lab manager (192.168.100.17).
- The manager VM's 23 GB root volume reached 100% because the vulnerability-detection feed downloaded about 13 GB into `/var/ossec/queue`. This caused database write errors (`wazuh-db: error assigning groups to agent`), so the agent was connected on the endpoint but showed as `Never connected` on the manager. Vulnerability detection is not needed for FIM; it was disabled, the temporary feed files were deleted, and the agent then showed as Active.
- A second, unused Host-Only network adapter is attached to the VM; it was not used. A pre-existing firewall rule (80/tcp from 192.168.56.101) from earlier use of the VM was left unchanged and is unrelated to the lab traffic.

### Troubleshooting screenshots

- [Firewall before the fix](evidence/troubleshooting/90-ufw-before.png), [ping works](evidence/troubleshooting/91-ping-ok.png), [port 22 blocked](evidence/troubleshooting/91-port22-false.png), [port 22 open after the fix](evidence/troubleshooting/92-port22-true.png)
- [Manager database errors](evidence/troubleshooting/98-manager-group-errors.png), [VM out of space](evidence/troubleshooting/99-vm-no-space-left.png), [disk 100% full](evidence/troubleshooting/99b-df-full.png), [after cleanup](evidence/troubleshooting/99c-after-cleanup.png)

## 7. Evidence checklist

- [x] E1 Deployment: Ubuntu details + dashboard access (credentials hidden)
- [x] E2 Agent registered: Active status
- [x] E3 Configuration: path + `ossec.conf` excerpt (no secrets)
- [x] E4 Create/modify/delete alerts + timestamped test log
- [x] E5 GRC report (this document)
- [x] Name, registration number, versions, architecture, limitations
- [ ] Demonstration video (live or recorded) for instructor

## 8. Suggested repository layout

```
README.md
configs/ossec-fim-excerpt.xml
evidence/*.png                    (deployment, agent, configuration and alert screenshots)
evidence/troubleshooting/*.png    (screenshots of problems solved during the lab)
logs/test-log.csv                 (timestamped create/modify/delete log)
logs/fim-alerts-from-manager.txt  (the three FIM alerts as logged by the manager)
```
