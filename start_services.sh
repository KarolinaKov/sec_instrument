#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${HOME}/sec_instrument"
VENV_DIR="${PROJECT_DIR}/venv"
LOG_DIR="${PROJECT_DIR}/logs"
RUN_DIR="${PROJECT_DIR}/run"
BACKGROUND_RUNSERVER=false

[[ "${1:-}" == "--bg" ]] && BACKGROUND_RUNSERVER=true

LOG() { echo -e "\n\033[1;32m==> $1\033[0m"; }
WARN() { echo -e "\033[1;33m[WARN] $1\033[0m"; }
FAIL() { echo -e "\033[1;31m[FAIL] $1\033[0m"; exit 1; }

mkdir -p "${LOG_DIR}" "${RUN_DIR}"
cd "${PROJECT_DIR}"

[[ -d "${VENV_DIR}" ]] || FAIL "venv not found at ${VENV_DIR} - run setup_kali_env.sh first"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

LOG "Starting PostgreSQL"
sudo systemctl start postgresql
sudo systemctl is-active --quiet postgresql && echo "PostgreSQL is running" || FAIL "PostgreSQL failed to start"

LOG "Starting RabbitMQ"
sudo systemctl start rabbitmq-server
sudo systemctl is-active --quiet rabbitmq-server && echo "RabbitMQ is running" || FAIL "RabbitMQ failed to start"

LOG "Configuring daily report schedule"
python manage.py setup_daily_report

LOG "Starting MailHog"
if pgrep -f "^mailhog$|/mailhog$" >/dev/null 2>&1; then
    WARN "MailHog already running, skipping"
else
    command -v mailhog >/dev/null 2>&1 || FAIL "mailhog not found - run setup_kali_env.sh first"
    nohup mailhog > "${LOG_DIR}/mailhog.log" 2>&1 &
    echo $! > "${RUN_DIR}/mailhog.pid"
    sleep 1
    echo "MailHog started (PID $(cat "${RUN_DIR}/mailhog.pid")), UI: http://127.0.0.1:8025"
fi

LOG "Starting Celery worker"
if pgrep -f "celery -A sec_instrument worker" >/dev/null 2>&1; then
    WARN "Celery worker already running, skipping"
else
    nohup celery -A sec_instrument worker --loglevel=info \
        > "${LOG_DIR}/celery_worker.log" 2>&1 &
    echo $! > "${RUN_DIR}/celery_worker.pid"
    sleep 1
    echo "Celery worker started (PID $(cat "${RUN_DIR}/celery_worker.pid"))"
fi

LOG "Starting Celery beat"
if pgrep -f "celery -A sec_instrument beat" >/dev/null 2>&1; then
    WARN "Celery beat already running, skipping"
else
    nohup celery -A sec_instrument beat --loglevel=info \
        --scheduler django_celery_beat.schedulers:DatabaseScheduler \
        > "${LOG_DIR}/celery_beat.log" 2>&1 &
    echo $! > "${RUN_DIR}/celery_beat.pid"
    sleep 1
    echo "Celery beat started (PID $(cat "${RUN_DIR}/celery_beat.pid"))"
fi

LOG "Starting Django runserver"
if $BACKGROUND_RUNSERVER; then
    nohup python manage.py runserver > "${LOG_DIR}/runserver.log" 2>&1 &
    echo $! > "${RUN_DIR}/runserver.pid"
    echo "Django runserver started in background (PID $(cat "${RUN_DIR}/runserver.pid"))"
    echo ""
    echo "All services up. Web UI: http://127.0.0.1:8000"
    echo "Tail logs with: tail -f ${LOG_DIR}/*.log"
    echo "Stop everything with: ./stop_services.sh"
else
    echo ""
    echo "All background services up. Starting Django runserver in the foreground"
    echo "(Ctrl+C stops the web server only - other services keep running)."
    echo "Web UI: http://127.0.0.1:8000"
    echo ""
    exec python manage.py runserver
fi
