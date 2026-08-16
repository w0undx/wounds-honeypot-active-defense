#!/bin/bash
# Watchdog: reinicia Dionaea si su CPU supera el umbral

THRESHOLD=80          # porcentaje de CPU
SERVICE="dionaea"

# Obtener el PID del proceso principal del servicio
PID=$(systemctl show --property MainPID --value "$SERVICE" 2>/dev/null)

# Si el servicio no está corriendo, no hacer nada
if [ -z "$PID" ] || [ "$PID" -eq 0 ]; then
    exit 0
fi

# Obtener uso de CPU actual (como entero)
CPU=$(ps -p "$PID" -o %cpu --no-headers 2>/dev/null | awk '{print int($1)}')

# Si no se pudo obtener CPU, salir
if [ -z "$CPU" ]; then
    exit 0
fi

# Si supera el umbral, reiniciar el servicio y dejar registro en syslog
if [ "$CPU" -gt "$THRESHOLD" ]; then
    logger -t dionaea-watchdog "CPU=${CPU}% > ${THRESHOLD}%. Reiniciando ${SERVICE}..."
    systemctl restart "$SERVICE"
fi
