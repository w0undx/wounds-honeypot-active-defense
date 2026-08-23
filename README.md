# WOUNDS 🛡️ | Active Defense & Threat Hunting Platform

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Shell Script](https://img.shields.io/badge/Shell_Script-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=Prometheus&logoColor=white)
![Grafana](https://img.shields.io/badge/Grafana-F46800?style=for-the-badge&logo=grafana&logoColor=white)
![CrowdSec](https://img.shields.io/badge/CrowdSec-191919?style=for-the-badge&logo=security&logoColor=white)

> Enterprise-grade infrastructure for threat intelligence acquisition, active defense, and proactive Threat Hunting.

## 📌 Overview

WOUNDS is a custom-built Security Operations Center (SOC) environment designed to emulate vulnerable enterprise services, capture real-world attacks, and extract actionable Cyber Threat Intelligence (CTI). By deploying high-interaction honeypots and integrating CrowdSec for real-time mitigation, this platform provides deep visibility into attacker Tactics, Techniques, and Procedures (TTPs).

## 📊 Visual Intelligence
   
<p align="center">
  <img src="https://github.com/user-attachments/assets/73f1a48e-c868-4957-97c5-47d0f4c06ab4" width="32%" alt="Dashboard Overview" />
</p>

## 🏗️ Architecture & Core Components

* **High-Interaction Honeypots:** Deployment of Cowrie (SSH/Telnet) and Dionaea (SMB, FTP, MSSQL) to capture active malware, brute-force attempts, and unauthorized command executions.
* **Automated IOC Extraction:** Custom Python-based telemetry exporter (`wounds_counters.py`) designed to parse honeypot logs, extract malicious IP addresses, correlate credentials, and map geolocations via MaxMind GeoIP.
* **Active Defense & Mitigation:** Integration with CrowdSec and custom Bash watchdog scripts (`check_dionaea_cpu.sh`) to prevent resource exhaustion and automatically block persistent threats at the infrastructure level.
* **Continuous Monitoring:** Seamless integration with Prometheus for time-series metrics collection and Grafana for the real-time visual auditing of attack vectors and geographical heatmaps.

## 📂 Repository Structure

This repository contains the Infrastructure as Code (IaC), custom Python automation, and configuration models used to build the environment:

* `wounds_counters.py`: Custom Python IOC extractor — parses Cowrie/Dionaea logs, deduplicates IPs, geolocates attackers, and exposes Prometheus metrics.
* `check_dionaea_cpu.sh`: Bash watchdog that restarts Dionaea if it exceeds a CPU threshold.
* `dionaea.service`: systemd unit for running Dionaea as a managed service.
* `prometheus.yml`: Metric scraping configuration for Prometheus.
* `grafana_soc_dashboard.json`: Importable Grafana dashboard (attack tables, credential/command feeds, geo heatmap).
* `docs/`: Technical documentation and operational manual.

## 📖 Official Documentation

For a detailed breakdown of the infrastructure, deployment steps, and operational commands, please refer to the documentation directory:

👉 **[View the WOUNDS Operational Manual](docs/Documentation.docx)**

---
*Disclaimer: This repository contains configuration files and monitoring scripts for educational, Threat Hunting, and portfolio demonstration purposes. Live databases, real threat actor credentials, and raw malware samples are strictly excluded from this public repository.*
