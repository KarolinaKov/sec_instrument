#!/usr/bin/env bash
################################################################################
# sec_instrument - Automated Kali Linux Dev Environment Setup
#
# Builds Python 3.13, PostgreSQL, RabbitMQ, MailHog, scan tools, and a venv
# matching the project's real settings.py (DB: sec_instrument_db, user: kali,
# apps: frontend + backend).
#
# Usage:
#   chmod +x setup_kali_env.sh
#   ./setup_kali_env.sh
#
# Safe to re-run: every step checks whether it already happened.
################################################################################
set -euo pipefail

# ---- Config (edit if you want different values) ----------------------------
PROJECT_DIR="${HOME}/sec_instrument"
VENV_DIR="${PROJECT_DIR}/venv"
DB_NAME="sec_instrument_db"
DB_USER="kali"
DB_PASSWORD="kali"
RABBIT_USER="kali"
RABBIT_PASSWORD="kali"
LOG() { echo -e "\n\033[1;32m==> $1\033[0m"; }
WARN() { echo -e "\033[1;33m[WARN] $1\033[0m"; }

# ---- 0. Sanity check ---------------------------------------------------------
if [[ $EUID -eq 0 ]]; then
    echo "Don't run this as root. Run as your normal user (it uses sudo internally)."
    exit 1
fi

# ==============================================================================
# SECTION 1: System update + build deps
# ==============================================================================
LOG "Updating system packages"
sudo apt update && sudo apt upgrade -y

LOG "Installing build tools + general dev libs"
sudo apt install -y build-essential libssl-dev libffi-dev \
    libncurses5-dev zlib1g-dev libbz2-dev libreadline-dev \
    libsqlite3-dev wget curl llvm libncursesw5-dev \
    xz-utils tk-dev libxml2-dev libxmlsec1-dev liblzma-dev git

# ==============================================================================
# SECTION 2: Python 3 (system, via apt)
# ==============================================================================
LOG "Installing system Python 3 + venv/dev packages"
sudo apt install -y python3 python3-venv python3-dev python3-pip

python3 --version

# ==============================================================================
# SECTION 3: PostgreSQL
# ==============================================================================
LOG "Installing PostgreSQL"
sudo apt install -y postgresql postgresql-contrib libpq-dev
sudo systemctl enable --now postgresql

LOG "Configuring PostgreSQL role/db (idempotent)"
sudo -u postgres psql -v ON_ERROR_STOP=0 <<SQL
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
      CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';
   END IF;
END
\$\$;

SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec

ALTER ROLE ${DB_USER} SET client_encoding TO 'utf8';
ALTER ROLE ${DB_USER} SET default_transaction_isolation TO 'read committed';
ALTER ROLE ${DB_USER} SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
SQL

sudo -u postgres psql -d "${DB_NAME}" <<SQL
GRANT ALL ON SCHEMA public TO ${DB_USER};
GRANT USAGE ON SCHEMA public TO ${DB_USER};
ALTER SCHEMA public OWNER TO ${DB_USER};
GRANT CREATE ON SCHEMA public TO ${DB_USER};
SQL

# ==============================================================================
# SECTION 4: RabbitMQ
# ==============================================================================
LOG "Installing RabbitMQ"
sudo apt install -y rabbitmq-server
sudo systemctl enable --now rabbitmq-server
sudo rabbitmq-plugins enable rabbitmq_management || true

if sudo rabbitmqctl list_users | grep -q "^${RABBIT_USER}"; then
    WARN "RabbitMQ user ${RABBIT_USER} already exists, skipping create"
else
    sudo rabbitmqctl add_user "${RABBIT_USER}" "${RABBIT_PASSWORD}"
fi
sudo rabbitmqctl set_user_tags "${RABBIT_USER}" administrator
sudo rabbitmqctl set_permissions -p / "${RABBIT_USER}" ".*" ".*" ".*"
sudo systemctl restart rabbitmq-server

# ==============================================================================
# SECTION 5: MailHog (used for EMAIL_HOST=localhost:1025 in settings.py)
# ==============================================================================
if command -v mailhog >/dev/null 2>&1; then
    LOG "MailHog already installed"
else
    LOG "Installing MailHog"
    MAILHOG_URL="https://github.com/mailhog/MailHog/releases/latest/download/MailHog_linux_amd64"
    sudo wget -q "${MAILHOG_URL}" -O /usr/local/bin/mailhog
    sudo chmod +x /usr/local/bin/mailhog
fi

# ==============================================================================
# SECTION 6: Kali scan tools used by backend_tasks_kali.py
# ==============================================================================
LOG "Installing scan tools (nmap, nikto, whatweb, sslyze)"
sudo apt install -y nmap nikto whatweb sslyze golang-go

if command -v nuclei >/dev/null 2>&1; then
    LOG "nuclei already installed"
else
    LOG "Installing nuclei via go install (not in apt)"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || \
        WARN "nuclei install failed - install manually later, scans will just log 'nuclei: not installed' and continue"
    if [[ -f "${HOME}/go/bin/nuclei" ]]; then
        sudo ln -sf "${HOME}/go/bin/nuclei" /usr/local/bin/nuclei
    fi
fi

# ==============================================================================
# SECTION 7: Project dir + venv
# ==============================================================================
LOG "Setting up project directory at ${PROJECT_DIR}"
mkdir -p "${PROJECT_DIR}"
cd "${PROJECT_DIR}"

if [[ -d "${VENV_DIR}" ]]; then
    WARN "venv already exists at ${VENV_DIR}, skipping creation"
else
    python3 -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip

LOG "Installing Python dependencies"
cat > "${PROJECT_DIR}/requirements.txt" <<'REQS'
Django>=5.2,<6.0
djangorestframework>=3.15,<3.16
django-celery-beat>=2.9,<3.0
celery>=5.4,<5.5
psycopg2-binary>=2.9,<3.0
REQS
pip install -r "${PROJECT_DIR}/requirements.txt"

# ==============================================================================
# SECTION 8: Logs dir (matches LOGGING config in settings.py)
# ==============================================================================
mkdir -p "${PROJECT_DIR}/logs"
chmod 755 "${PROJECT_DIR}/logs"

# ==============================================================================
# DONE
# ==============================================================================
LOG "Setup complete."
cat <<EOF

Next steps (manual, since this is where YOUR project code goes):

  1. Copy/clone your sec_instrument Django project (with 'frontend' and
     'backend' apps) into: ${PROJECT_DIR}

  2. Activate the venv every time you work:
       source ${VENV_DIR}/bin/activate

  3. From the project root (where manage.py lives):
       python manage.py makemigrations
       python manage.py migrate
       python manage.py createsuperuser (kali, kali)

  4. Start everything (separate terminals, venv active in each):
       mailhog &
       python manage.py runserver
       celery -A sec_instrument worker --loglevel=info
       celery -A sec_instrument beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler

  5. Web UI:        http://127.0.0.1:8000
     Django admin:  http://127.0.0.1:8000/admin
     MailHog UI:    http://127.0.0.1:8025
     RabbitMQ UI:   http://127.0.0.1:15672  (user: ${RABBIT_USER} / ${RABBIT_PASSWORD})

  DB:  ${DB_NAME}  (user: ${DB_USER} / ${DB_PASSWORD})

EOF
