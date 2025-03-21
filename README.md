# SIEM Queries & Dashboards

## Overview
This repository contains a comprehensive collection of **SIEM queries and dashboards** for Splunk, Microsoft Sentinel, and ArcSight. These queries facilitate threat detection, log analysis, security monitoring, and compliance tracking, while dashboards provide real-time visibility into security events and incidents.

## Features
✅ **Extensive Query Library** – Covers a wide range of use cases, including malware analysis, authentication monitoring, network anomalies, and compliance reports.  
✅ **Custom Dashboards** – Interactive dashboards for real-time monitoring and visualization of security incidents.  
✅ **Threat Detection Rules** – Predefined queries to identify malicious activities across enterprise environments.  
✅ **Multi-SIEM Support** – Queries optimized for Splunk, Microsoft Sentinel, and ArcSight.  
✅ **Compliance & Audit Reports** – Queries tailored for compliance frameworks like PCI-DSS, NIST, and ISO 27001.  

## Repository Structure
```
📂 SIEM-Queries-Dashboards/
 ├── 📁 Splunk/
 │   ├── queries/
 │   │   ├── malware_detection.spl
 │   │   ├── phishing_analysis.spl
 │   │   ├── user_activity_monitoring.spl
 │   │   ├── brute_force_attempts.spl
 │   │   ├── insider_threats.spl
 │   │   ├── data_exfiltration.spl
 │   │   ├── compliance_audit_pci.spl
 │   ├── dashboards/
 │       ├── Security_Overview_Dashboard.json
 │       ├── Threat_Detection_Dashboard.json
 │       ├── Compliance_Monitoring_Dashboard.json
 │
 ├── 📁 Sentinel/
 │   ├── queries/
 │   │   ├── failed_logins.kql
 │   │   ├── suspicious_network_activity.kql
 │   │   ├── anomalous_user_behavior.kql
 │   │   ├── rare_process_execution.kql
 │   │   ├── excessive_failed_auth.kql
 │   │   ├── cloud_data_leak.kql
 │   │   ├── compliance_audit_nist.kql
 │   ├── dashboards/
 │       ├── Incident_Response_Dashboard.json
 │       ├── User_Behavior_Analytics_Dashboard.json
 │       ├── Cloud_Security_Dashboard.json
 │
 ├── 📁 ArcSight/
 │   ├── queries/
 │   │   ├── endpoint_alerts.arcsight
 │   │   ├── firewall_traffic_analysis.arcsight
 │   │   ├── privilege_escalation.arcsight
 │   │   ├── anomalous_traffic.arcsight
 │   │   ├── lateral_movement.arcsight
 │   │   ├── compliance_audit_iso27001.arcsight
 │   ├── dashboards/
 │       ├── SOC_Operations_Dashboard.json
 │       ├── Incident_Management_Dashboard.json
 │       ├── Compliance_Reporting_Dashboard.json
 │
 ├── README.md
```

## Queries & Dashboards
### **Splunk Queries**
#### Malware Detection
```spl
index=security_logs sourcetype=malware_alerts | stats count by malware_type, severity, src_ip, dest_ip
```

#### Brute Force Attempts
```spl
index=auth_logs action=failed | stats count by user, src_ip | where count > 10
```

#### Insider Threat Monitoring
```spl
index=activity_logs | search "unauthorized access" OR "data download" | stats count by user, src_ip
```

#### Data Exfiltration Detection
```spl
index=network_logs | search "large data transfer" | stats sum(bytes) by user, src_ip, dest_ip
```

### **Microsoft Sentinel Queries**
#### Failed Login Attempts
```kql
SecurityEvent | where EventID == 4625 | summarize count() by Account, Computer, TimeGenerated
```

#### Rare Process Execution
```kql
DeviceProcessEvents | where ProcessCommandLine contains "powershell" and isnotempty(ProcessExecutionTime) | summarize count() by DeviceId, ProcessCommandLine
```

#### Excessive Failed Authentication Attempts
```kql
SigninLogs | where ResultType == "50126" | summarize count() by UserPrincipalName, IPAddress
```

#### Cloud Data Leakage Detection
```kql
StorageBlobLogs | where OperationName == "PutBlob" and RequesterIPAddress != "Company_IP_Range" | summarize count() by RequesterIPAddress, StorageAccountName
```

### **ArcSight Queries**
#### Privilege Escalation Attempts
```arcsight
SELECT sourceUserName, destinationUserName, eventOutcome FROM events WHERE eventName = 'Privilege Escalation'
```

#### Anomalous Network Traffic
```arcsight
SELECT sourceAddress, destinationAddress, bytesIn, bytesOut FROM events WHERE bytesOut > 1000000
```

#### Lateral Movement Detection
```arcsight
SELECT sourceAddress, destinationAddress, requestUrl FROM events WHERE deviceVendor = 'Windows' AND eventName LIKE '%remote login%'
```

## Dashboards
We provide JSON-based dashboards for each SIEM platform, including:
- **Splunk Security Overview Dashboard** – Monitors malware, phishing, and authentication logs.
- **Splunk Threat Detection Dashboard** – Analyzes anomalous activities and threats.
- **Splunk Compliance Monitoring Dashboard** – Ensures compliance with PCI-DSS and NIST.
- **Sentinel Incident Response Dashboard** – Tracks security alerts and response actions.
- **Sentinel User Behavior Analytics Dashboard** – Detects unusual user behavior and privilege escalations.
- **Sentinel Cloud Security Dashboard** – Monitors cloud-related threats and unauthorized data access.
- **ArcSight SOC Operations Dashboard** – Provides an overview of endpoint and network security alerts.
- **ArcSight Incident Management Dashboard** – Tracks security incidents and response workflows.
- **ArcSight Compliance Reporting Dashboard** – Helps with audit logs and compliance tracking.

## Contributions
We welcome contributions! Submit new queries, dashboards, or improvements via pull requests.

## License
This project is licensed under the [MIT License](LICENSE).
