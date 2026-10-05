#!/usr/bin/env bash
# Install Quick Access Center as a loopback-only systemd/Gunicorn service.
set -Eeuo pipefail
umask 077

readonly SERVICE_NAME="quick-access-center"
readonly UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly DATA_DIR="/var/lib/quick-access-center"
readonly VENV_DIR="/opt/quick-access-center-venv"
readonly DATA_MARKER="${DATA_DIR}/.quick-access-center-data"
readonly VENV_MARKER="${VENV_DIR}/.quick-access-center-venv"
readonly DATA_MARKER_CONTENT="Managed by quick_access_center/deploy/install.sh (runtime data)"
readonly VENV_MARKER_CONTENT="Managed by quick_access_center/deploy/install.sh (virtual environment)"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '[quick-access-install] %s\n' "$*"
}

systemd_quote() {
    local value=$1
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "Values containing newlines are not supported"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//\$/\$\$}
    value=${value//%/%%}
    printf '"%s"' "$value"
}

# Path-valued unit settings do not strip surrounding quotes. Encode characters
# that need escaping using systemd's C-style escapes instead.
systemd_path_escape() {
    local value=$1 encoded='' char index
    [[ "$value" == /* ]] || fail "Working directory must be an absolute path"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "Paths containing newlines are not supported"
    for ((index = 0; index < ${#value}; index++)); do
        char=${value:index:1}
        case "$char" in
            ' ') encoded+='\x20' ;;
            $'\t') encoded+='\x09' ;;
            $'\\') encoded+='\x5c' ;;
            '"') encoded+='\x22' ;;
            '$') encoded+='\x24' ;;
            '%') encoded+='%%' ;;
            *) encoded+=$char ;;
        esac
    done
    printf '%s' "$encoded"
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Run as root, usually: sudo $0"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required (systemd Linux host)"
[[ -d /run/systemd/system ]] || fail "systemd is not running; this installer supports systemd Linux hosts"
command -v realpath >/dev/null 2>&1 || fail "realpath is required"
command -v runuser >/dev/null 2>&1 || fail "runuser is required (util-linux)"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEFAULT_APP_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
APP_DIR="$(realpath -e -- "${QUICK_ACCESS_APP_DIR:-$DEFAULT_APP_DIR}")" \
    || fail "Application directory does not exist"

[[ -f "${APP_DIR}/app.py" ]] || fail "${APP_DIR}/app.py not found"
[[ -f "${APP_DIR}/requirements.txt" ]] || fail "${APP_DIR}/requirements.txt not found"
[[ -f "${APP_DIR}/access_control/setup_access.py" ]] || fail "Access setup wizard not found"
[[ -f "${APP_DIR}/vault_control/setup_vault.py" ]] || fail "Vault setup wizard not found"

SERVICE_USER="${QUICK_ACCESS_SERVICE_USER:-${SUDO_USER:-}}"
[[ -n "$SERVICE_USER" ]] || fail "Set QUICK_ACCESS_SERVICE_USER or run through sudo from the intended service account"
id "$SERVICE_USER" >/dev/null 2>&1 || fail "Unix account '$SERVICE_USER' does not exist"
[[ "$SERVICE_USER" != root ]] || fail "The service must not run as root"
SERVICE_UID="$(id -u "$SERVICE_USER")"
[[ "$SERVICE_UID" -ne 0 ]] || fail "The service must not run as root"
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"

if ! runuser -u "$SERVICE_USER" -- test -r "${APP_DIR}/app.py" \
    || ! runuser -u "$SERVICE_USER" -- test -x "$APP_DIR"; then
    fail "Service account '$SERVICE_USER' cannot read/traverse $APP_DIR. Use an accessible checkout or set QUICK_ACCESS_APP_DIR."
fi

PORT="${QUICK_ACCESS_PORT:-5050}"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) \
    || fail "QUICK_ACCESS_PORT must be an integer from 1 to 65535"

if [[ -n "${QUICK_ACCESS_PYTHON_BIN:-}" ]]; then
    PYTHON_BIN="$QUICK_ACCESS_PYTHON_BIN"
elif command -v python3.11 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3.11)"
else
    PYTHON_BIN="$(command -v python3 || true)"
fi
[[ -n "$PYTHON_BIN" && -x "$PYTHON_BIN" ]] || fail "Python 3.11+ is required (set QUICK_ACCESS_PYTHON_BIN if needed)"
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
    || fail "Python 3.11 or newer is required; found: $($PYTHON_BIN --version 2>&1)"

systemd_quote "$APP_DIR" >/dev/null

if [[ -L "$UNIT_FILE" ]]; then
    fail "$UNIT_FILE is a symlink; refusing to replace it"
fi
if [[ -e "$UNIT_FILE" ]] && ! grep -Fq '# Managed by quick_access_center/deploy/install.sh' "$UNIT_FILE"; then
    fail "$UNIT_FILE already exists and is not managed by this installer; refusing to overwrite it"
fi

if [[ -L "$DATA_DIR" ]]; then
    fail "$DATA_DIR is a symlink; refusing to use or modify it"
fi
if [[ -e "$DATA_DIR" ]]; then
    [[ -d "$DATA_DIR" ]] || fail "$DATA_DIR exists but is not a directory"
    [[ -f "$DATA_MARKER" && ! -L "$DATA_MARKER" ]] \
        || fail "$DATA_DIR already exists without a regular installer marker; move or back it up before installing"
    grep -Fxq -- "$DATA_MARKER_CONTENT" "$DATA_MARKER" \
        || fail "$DATA_DIR has an unrecognized installer marker; refusing to modify it"
fi

if [[ -L "$VENV_DIR" ]]; then
    fail "$VENV_DIR is a symlink; refusing to use or modify it"
fi
if [[ -e "$VENV_DIR" ]]; then
    [[ -d "$VENV_DIR" ]] || fail "$VENV_DIR exists but is not a directory"
    [[ -f "$VENV_MARKER" && ! -L "$VENV_MARKER" ]] \
        || fail "$VENV_DIR already exists without a regular installer marker; move it or choose another host before installing"
    grep -Fxq -- "$VENV_MARKER_CONTENT" "$VENV_MARKER" \
        || fail "$VENV_DIR has an unrecognized installer marker; refusing to modify it"
fi

ACCESS_ENV="${APP_DIR}/access_control/access.env"
VAULT_ENV="${APP_DIR}/vault_control/vault.env"
for config_file in "$ACCESS_ENV" "$VAULT_ENV"; do
    [[ ! -L "$config_file" ]] || fail "$config_file is a symlink; handle it manually before installing"
    [[ ! -e "$config_file" || -f "$config_file" ]] || fail "$config_file exists but is not a regular file"
done
if [[ ! -f "$ACCESS_ENV" ]] && ! runuser -u "$SERVICE_USER" -- test -w "${APP_DIR}/access_control"; then
    fail "Service account '$SERVICE_USER' cannot create $ACCESS_ENV; make the config directory writable or pre-create the file securely"
fi
if [[ ! -f "$VAULT_ENV" ]] && ! runuser -u "$SERVICE_USER" -- test -w "${APP_DIR}/vault_control"; then
    fail "Service account '$SERVICE_USER' cannot create $VAULT_ENV; make the config directory writable or pre-create the file securely"
fi

# Do not mutate live state or dependencies while the current service is running.
if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "Stopping the currently installed service before updating its venv"
    systemctl stop "$SERVICE_NAME"
fi

# Keep runtime state separate from the checkout. Only adopt data directories
# bearing this installer's marker; this prevents accidental chown of unrelated data.
if [[ ! -e "$DATA_DIR" ]]; then
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR"
    printf '%s\n' "$DATA_MARKER_CONTENT" > "$DATA_MARKER"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_MARKER"
    chmod 0600 "$DATA_MARKER"
fi
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
chmod 0700 "$DATA_DIR"

# Install dependencies into a root-owned, runtime-read-only venv. Do not reuse
# an unrelated directory at this fixed path.
if [[ ! -e "$VENV_DIR" ]]; then
    install -d -o root -g root -m 0755 "$(dirname -- "$VENV_DIR")" "$VENV_DIR"
    printf '%s\n' "$VENV_MARKER_CONTENT" > "$VENV_MARKER"
    chmod 0644 "$VENV_MARKER"
    chown root:root "$VENV_MARKER"
fi
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR" \
        || fail "Could not create venv; install the Python venv package for $PYTHON_BIN and retry"
fi
[[ -x "${VENV_DIR}/bin/python" ]] || fail "Invalid venv at $VENV_DIR"
"${VENV_DIR}/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
    || fail "Existing venv at $VENV_DIR uses Python older than 3.11"
chmod -R a+rX "$VENV_DIR"

info "Installing Python dependencies"
"${VENV_DIR}/bin/python" -m pip install -r "${APP_DIR}/requirements.txt"

# Run credential setup with the non-root service identity. The prompts are
# interactive; neither credentials nor the Vault key are overwritten on reruns.
if [[ ! -f "$ACCESS_ENV" ]]; then
    info "First run: creating the main administrator credentials"
    runuser -u "$SERVICE_USER" -- env \
        "MSB_QUICK_ACCESS_DATA_DIR=$DATA_DIR" \
        "MSB_QUICK_ACCESS_LOG_DIR=${DATA_DIR}/logs" \
        "$VENV_DIR/bin/python" "${APP_DIR}/access_control/setup_access.py"
fi
if [[ ! -f "$VAULT_ENV" ]]; then
    info "First run: creating the separate Vault credentials and encryption key"
    runuser -u "$SERVICE_USER" -- env \
        "MSB_QUICK_ACCESS_DATA_DIR=$DATA_DIR" \
        "MSB_QUICK_ACCESS_LOG_DIR=${DATA_DIR}/logs" \
        "$VENV_DIR/bin/python" "${APP_DIR}/vault_control/setup_vault.py"
fi
[[ -f "$ACCESS_ENV" && -f "$VAULT_ENV" ]] || fail "Setup did not create both access.env files"
for config_file in "$ACCESS_ENV" "$VAULT_ENV"; do
    [[ -f "$config_file" && ! -L "$config_file" ]] || fail "$config_file is missing or is not a regular file"
done
chown --no-dereference "$SERVICE_USER:$SERVICE_GROUP" -- "$ACCESS_ENV" "$VAULT_ENV"
for config_file in "$ACCESS_ENV" "$VAULT_ENV"; do
    [[ -f "$config_file" && ! -L "$config_file" ]] || fail "$config_file changed type during installation"
    runuser -u "$SERVICE_USER" -- chmod 0600 "$config_file"
    runuser -u "$SERVICE_USER" -- test -r "$config_file" \
        || fail "Service account cannot read $config_file"
done

UNIT_TMP="$(mktemp "${UNIT_FILE}.XXXXXX")"
trap 'rm -f -- "$UNIT_TMP"' EXIT
cat > "$UNIT_TMP" <<EOF
[Unit]
Description=MSB Quick Access Center (Flask/Gunicorn)
# Managed by quick_access_center/deploy/install.sh
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$(systemd_path_escape "$APP_DIR")
StateDirectory=quick-access-center
StateDirectoryMode=0700
UMask=0077
Environment=$(systemd_quote "MSB_QUICK_ACCESS_DATA_DIR=$DATA_DIR")
Environment=$(systemd_quote "MSB_QUICK_ACCESS_LOG_DIR=${DATA_DIR}/logs")
Environment=MSB_QUICK_ACCESS_COOKIE_SECURE=1
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$(systemd_quote "${VENV_DIR}/bin/gunicorn") --workers 1 --bind 127.0.0.1:$PORT --access-logfile - --error-logfile - app:app
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
LimitNOFILE=4096

# The service listens only on loopback; put an HTTPS reverse proxy in front.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectHostname=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_TMP"
chown root:root "$UNIT_TMP"
mv -f -- "$UNIT_TMP" "$UNIT_FILE"
trap - EXIT

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl --no-pager --full status "$SERVICE_NAME" || true
    journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
    fail "Service did not become active; see the logs above"
fi

info "Installed and running as $SERVICE_USER"
info "Gunicorn listens only on 127.0.0.1:$PORT; configure HTTPS reverse proxy before remote use"
info "Main/Vault allowlists default to localhost. Review access.env before exposing the proxy"
info "Status: systemctl status $SERVICE_NAME"
info "Logs:   journalctl -u $SERVICE_NAME -f"
info "State:  $DATA_DIR (preserved by uninstall unless --purge-data is explicitly requested)"
