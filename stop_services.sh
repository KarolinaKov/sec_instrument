#!/usr/bin/env bash
set -uo pipefail

PROJECT_DIR="${HOME}/sec_instrument"
RUN_DIR="${PROJECT_DIR}/run"

LOG() { echo -e "\n\033[1;32m==> $1\033[0m"; }
WARN() { echo -e "\033[1;33m[WARN] $1\033[0m"; }

stop_pidfile() {
    local name="$1"
    local pidfile="${RUN_DIR}/${name}.pid"

    if [[ -f "${pidfile}" ]]; then
        local pid
        pid=$(cat "${pidfile}")
        if kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null
            echo "Stopped ${name} (PID ${pid})"
        else
            WARN "${name} pidfile present but process ${pid} not running"
        fi
        rm -f "${pidfile}"
    else
        pkill -f "$2" 2>/dev/null && echo "Stopped ${name} (matched by pattern)" \
            || WARN "${name} not running"
    fi
}

LOG "Stopping application processes"
stop_pidfile "runserver"       "manage.py runserver"
stop_pidfile "celery_beat"     "celery -A sec_instrument beat"
stop_pidfile "celery_worker"   "celery -A sec_instrument worker"
stop_pidfile "mailhog"         "mailhog"

LOG "Stopping system services (PostgreSQL, RabbitMQ left running - they're shared services)"
echo "Run 'sudo systemctl stop postgresql rabbitmq-server' manually if you also want those down."

echo ""
echo "Done."
