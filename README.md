# SSH Brute Force Attack Detection Using Splunk

## Overview

This project demonstrates the detection of SSH brute-force attacks using Splunk SIEM. The solution analyzes Linux authentication logs, identifies multiple failed login attempts, detects successful logins following repeated failures, and visualizes attack patterns through interactive dashboards.

The objective is to simulate a real-world SOC use case where security analysts monitor authentication events, investigate suspicious activity, and respond to potential unauthorized access attempts.

---

## Project Objectives

* Monitor SSH authentication logs
* Detect brute-force attack attempts
* Identify successful compromise after multiple failed logins
* Track attacker IP addresses
* Monitor targeted user accounts
* Visualize attack trends using Splunk dashboards
* Improve incident detection and response capabilities

---

## Technologies Used

* Splunk Enterprise
* Splunk Universal Forwarder
* Linux Authentication Logs
* SPL (Search Processing Language)
* Ubuntu / Kali Linux
* Cybersecurity Monitoring Concepts

---

## Data Source

Linux authentication logs:

```bash
/var/log/auth.log
```

Events analyzed:

* Failed password
* Accepted password
* Invalid user
* Authentication failure

---

## Detection Logic

### SSH Brute Force Detection

```spl
index=linux_log sourcetype=linux_secure_log ("Failed password" OR "Accepted password")
| eval action=if(searchmatch("Failed password"),"Failed","Success")
| stats count(eval(action="Failed")) as Failed_Attempts,
        count(eval(action="Success")) as Successful_Logins
        by src_ip, host_name
| where Failed_Attempts>=5 AND Successful_Logins>=1
```

### Top Attacker IPs

```spl
index=linux_log sourcetype=linux_secure_log "Failed password"
| stats count by src_ip
| sort -count
```

### Top Targeted Users

```spl
index=linux_log sourcetype=linux_secure_log "Failed password"
| stats count by user
| sort -count
```

### Failed Login Trend

```spl
index=linux_log sourcetype=linux_secure_log "Failed password"
| timechart count
```

---

## Dashboards

The project includes the following security dashboards:

### Failed SSH Login Trend

Visualizes failed login attempts over time.

### Top Attacker IPs

Displays the most active source IP addresses generating failed login attempts.

### Top Targeted Users

Shows user accounts targeted during brute-force attacks.

### Brute Force Followed by Success

Detects potential account compromise where multiple failed logins are followed by a successful authentication.

### Authentication Statistics

Provides an overview of failed and successful login events.

---

## Security Use Case

### MITRE ATT&CK Mapping

| Technique | Description    |
| --------- | -------------- |
| T1110     | Brute Force    |
| T1078     | Valid Accounts |

---

## SOC Investigation Workflow

1. Monitor authentication logs.
2. Identify excessive failed login attempts.
3. Correlate successful logins after failures.
4. Investigate attacker IP addresses.
5. Review targeted accounts.
6. Escalate suspicious activity.
7. Recommend remediation actions.

---

## Sample Attack Scenario

* Attacker attempts multiple SSH logins.
* Several authentication failures occur.
* One login succeeds.
* Splunk correlates the events.
* Dashboard highlights suspicious activity.
* SOC analyst investigates and escalates the incident.

---

## Key Learning Outcomes

* Splunk SPL Development
* SIEM Monitoring
* Log Analysis
* Linux Security Monitoring
* Incident Detection
* Threat Hunting Fundamentals
* SOC Analyst Workflow

---

## Future Enhancements

* Real-time alerting
* Email notifications
* Integration with MITRE ATT&CK dashboards
* Risk-based alerting
* Automated incident response
* Threat intelligence enrichment

---

## Author

**Avishkar Salve**

SOC Analyst Fresher | Splunk | Incident Monitoring | SIEM | Cybersecurity | CEH

LinkedIn:
https://www.linkedin.com/in/avishkar-salve-036539323

---

## Repository Structure

```text
SSH-Brute-Force-Attack-Detection
│
├── dashboards
├── screenshots
├── spl_queries
├── sample_logs
├── README.md
└── project_report.pdf
```

---

⭐ If you found this project useful, feel free to star the repository.
