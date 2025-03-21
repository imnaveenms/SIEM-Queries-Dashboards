# SIEM Queries & Dashboards

## Overview
This repository contains a collection of **SIEM queries and dashboards** for Splunk, Microsoft Sentinel, and ArcSight. These queries help in threat detection, log analysis, and security monitoring, while dashboards provide real-time insights into security events.

## Features
✅ **Predefined Queries** – A library of useful SIEM queries for security operations.  
✅ **Custom Dashboards** – Interactive dashboards for monitoring threats and incidents.  
✅ **Threat Detection Rules** – Queries tailored for detecting specific security threats.  
✅ **Multi-SIEM Support** – Queries compatible with Splunk, Microsoft Sentinel, and ArcSight.  

## Repository Structure
```
📂 SIEM-Queries-Dashboards/
 ├── 📁 Splunk/
 │   ├── queries/
 │   │   ├── malware_detection.spl
 │   │   ├── phishing_analysis.spl
 │   │   ├── user_activity_monitoring.spl
 │   ├── dashboards/
 │       ├── Security_Overview_Dashboard.json
 │
 ├── 📁 Sentinel/
 │   ├── queries/
 │   │   ├── failed_logins.kql
 │   │   ├── suspicious_network_activity.kql
 │   │   ├── anomalous_user_behavior.kql
 │   ├── dashboards/
 │       ├── Incident_Response_Dashboard.json
 │
 ├── 📁 ArcSight/
 │   ├── queries/
 │   │   ├── endpoint_alerts.arcsight
 │   │   ├── firewall_traffic_analysis.arcsight
 │   ├── dashboards/
 │       ├── SOC_Operations_Dashboard.json
 │
 ├── README.md
```

## Queries & Dashboards
### **Splunk Queries**
#### Malware Detection
```spl
index=security_logs sourcetype=malware_alerts | stats count by malware_type, severity, src_ip, dest_ip
```

#### Phishing Email Analysis
```spl
index=email_logs "subject=*urgent*" OR "body=*click here*" | table sender, recipient, subject, timestamp
```

### **Microsoft Sentinel Queries**
#### Failed Login Attempts
```kql
SecurityEvent | where EventID == 4625 | summarize count() by Account, Computer, TimeGenerated
```

#### Suspicious Network Traffic
```kql
AzureDiagnostics | where Category == "NetworkSecurityGroupFlowEvent" and Direction == "Inbound" | summarize count() by SourceIP, DestinationIP, Protocol
```

### **ArcSight Queries**
#### Firewall Traffic Analysis
```arcsight
SELECT sourceAddress, destinationAddress, requestUrl FROM events WHERE deviceVendor = 'Firewall'
```

## Dashboards
We provide JSON-based dashboards for each SIEM platform, including:
- **Splunk Security Overview Dashboard** – Monitors malware, phishing, and access logs.
- **Sentinel Incident Response Dashboard** – Tracks security alerts and response actions.
- **ArcSight SOC Operations Dashboard** – Provides an overview of endpoint alerts and firewall logs.

## Contributions
We welcome contributions! Submit new queries, dashboards, or improvements via pull requests.

## License
This project is licensed under the [MIT License](LICENSE).
