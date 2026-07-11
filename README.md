# 🛰️ Network Egress Monitor

Real-time TCP Egress Monitoring Tool for Windows.

Designed for SOC Analysts, DFIR Investigators and Blue Teams.

---

**LinkedIn:** [lucas-villagra-cybersecurity](https://linkedin.com/in/lucas-villagra-cybersecurity)

---

## Descripción

Monitor de tráfico saliente (egress) en tiempo real para Windows 11. Captura conexiones TCP ESTABLISHED con contexto completo de auditoría forense.

### Features
- ✅ Captura conexiones TCP establecidas en tiempo real
- ✅ Identifica proceso + PID + IP destino + puerto
- ✅ Reverse DNS lookup (hostname)
- ✅ Extracción automática de organización (Akamai, Microsoft, Google, AWS, Cloudflare)
- ✅ WHOIAM context (usuario, dominio, hostname, SO)
- ✅ Logging en C:\Logs\network-egress-final.log
- ✅ Intervalo configurable (default: 3s)

## Uso

```powershell
# Ejecución básica (intervalo 3 segundos)
.\monitor-egress.ps1

# Intervalo personalizado (1 segundo)
.\monitor-egress.ps1 -IntervalSeconds 1

# Con ejecución policy
powershell -ExecutionPolicy Bypass -File .\monitor-egress.ps1 -IntervalSeconds 1
```

