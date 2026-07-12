# 📡 Network Egress Monitor - v3.0 

[![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-blue)](https://microsoft.com/powershell)
[![Windows 11](https://img.shields.io/badge/Windows-11%20Pro-0078D4)](https://microsoft.com/windows)
[![License MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status Active](https://img.shields.io/badge/Status-Active-brightgreen)](https://github.com/Lucas18062025/NETWORK-EGRESS-MONITOR-)

**Real-time TCP Egress Monitoring for Windows 11 with Forensic Audit Context**


## Descripción

Network Egress Monitor is a PowerShell-based monitoring tool that captures outbound TCP connections in real time.

Each connection is correlated with:

- Process Name
- PID
- Reverse DNS
- Organization
- Timestamp
- User Context
- Operating System

The tool is intended for DFIR investigations, SOC monitoring, malware analysis and threat hunting.

## Installation

Clone repository

```powershell
git clone https://github.com/Lucas18062025/NETWORK-EGRESS-MONITOR.git
```

## Uso

```powershell
# Ejecución básica (intervalo 3 segundos)
.\monitor-egress.ps1

# Intervalo personalizado (1 segundo)
.\monitor-egress.ps1 -IntervalSeconds 1

# Con ejecución policy
powershell -ExecutionPolicy Bypass -File .\monitor-egress.ps1 -IntervalSeconds 1
```
## Captura en Vivo

![Network Egress Monitor Screenshot](https://raw.githubusercontent.com/Lucas18062025/NETWORK-EGRESS-MONITOR-/main/NETWORK-EGRESS-MONITOR-.png)


## Features

✅ Real-time TCP monitoring

✅ Reverse DNS lookup

✅ Organization identification

✅ Process correlation

✅ Log generation

✅ Lightweight

✅ Native PowerShell

✅ No external dependencies

```mermaid
graph TD

A[Windows]

B[Get-NetTCPConnection]

C[Process Correlation]

D[Reverse DNS]

E[Organization Detection]

F[Logger]

G[Console]

A --> B

B --> C

C --> D

D --> E

E --> F

E --> G
```
## Roadmap

- [ ] v3.1: Agregar alertas por Email
- [ ] v3.2: Exportar logs a CSV/JSON
- [ ] v3.3: Integración con Splunk/ELK
- [ ] v4.0: Versión GUI (WinForms)
- [ ] v4.1: API REST para queries remotas

---

## 👤 Autor

**Lucas Villagra**  
Cybersecurity Analyst | Ethical Hacker | SOC Analyst  
📍 San Miguel de Tucumán, Argentina

[![LinkedIn](https://img.shields.io/badge/LinkedIn-lucas--villagra--cybersecurity-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/lucas-villagra-cybersecurity)
[![GitHub](https://img.shields.io/badge/GitHub-Lucas18062025-181717?style=flat&logo=github)](https://github.com/Lucas18062025)
[![Portfolio](https://img.shields.io/badge/Portfolio-lucas18062025.github.io-00D4FF?style=flat&logo=githubpages)](https://lucas18062025.github.io/Portafolio/)

---
