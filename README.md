# 🛰️ Network Egress Monitor

Real-time TCP Egress Monitoring Tool for Windows.

Designed for SOC Analysts, DFIR Investigators and Blue Teams.

---

**LinkedIn:** [lucas-villagra-cybersecurity](https://linkedin.com/in/lucas-villagra-cybersecurity)

---

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

## Uso

```powershell
# Ejecución básica (intervalo 3 segundos)
.\monitor-egress.ps1

# Intervalo personalizado (1 segundo)
.\monitor-egress.ps1 -IntervalSeconds 1

# Con ejecución policy
powershell -ExecutionPolicy Bypass -File .\monitor-egress.ps1 -IntervalSeconds 1
```

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
