#!/usr/bin/env bash
# Remove the systemd service. Persistent data/config are preserved by default.
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

usage() {
    cat <<'EOF'
Usage: sudo deploy/uninstall.sh [--remove-venv] [--purge-data]

Default: stop/disable the systemd service and remove its unit only.
         Application source, access.env, vault.env, encryption key, venv and data remain.

--remove-venv  Also remove the installer-marked venv at /opt/quick-access-center-venv.
--purge-data   Irreversibly remove /var/lib/quick-access-center (SQLite DB, images,
               logs and rate-limit state) after an explicit typed confirmation.
-h, --help     Show this help.
EOF
}

remove_venv=false
purge_data=false
while (($#)); do
    case "$1" in
        --remove-venv) remove_venv=true ;;
        --purge-data) purge_data=true ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "Unknown option: $1" ;;
    esac
    shift
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Run as root, usually: sudo $0"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required"

confirm_exact_path() {
    local prompt=$1
    local expected=$2
    local answer
    [[ -t 0 ]] || fail "Destructive cleanup requires an interactive terminal"
    printf '%s\nType exactly: %s\n> ' "$prompt" "$expected" >&2
    IFS= read -r answer || fail "No confirmation received; nothing was changed"
    [[ "$answer" == "$expected" ]] || fail "Confirmation did not match; nothing was changed"
}

# Validate ownership markers and collect all confirmations before stopping or
# removing anything. The fixed paths below are never taken from user input.
if [[ -L "$UNIT_FILE" ]]; then
    fail "$UNIT_FILE is a symlink; refusing to remove it"
fi
if [[ -e "$UNIT_FILE" ]]; then
    [[ -f "$UNIT_FILE" ]] || fail "$UNIT_FILE is not a regular file"
    grep -Fq '# Managed by quick_access_center/deploy/install.sh' "$UNIT_FILE" \
        || fail "$UNIT_FILE is not marked as managed by this installer; refusing to remove it"
fi

if [[ -L "$DATA_DIR" ]]; then
    fail "$DATA_DIR is a symlink; refusing to remove it"
fi
if "$purge_data" && [[ -e "$DATA_DIR" ]]; then
    [[ -d "$DATA_DIR" ]] || fail "$DATA_DIR is not a directory"
    [[ -f "$DATA_MARKER" && ! -L "$DATA_MARKER" ]] \
        || fail "$DATA_DIR has no regular installer marker; refusing to remove it"
    grep -Fxq -- "$DATA_MARKER_CONTENT" "$DATA_MARKER" \
        || fail "$DATA_DIR has an unrecognized installer marker; refusing to remove it"
    confirm_exact_path \
        "This permanently deletes the database, uploaded images, logs and rate-limit state." \
        "DELETE $DATA_DIR"
fi

if [[ -L "$VENV_DIR" ]]; then
    fail "$VENV_DIR is a symlink; refusing to remove it"
fi
if "$remove_venv" && [[ -e "$VENV_DIR" ]]; then
    [[ -d "$VENV_DIR" ]] || fail "$VENV_DIR is not a directory"
    [[ -f "$VENV_MARKER" && ! -L "$VENV_MARKER" ]] \
        || fail "$VENV_DIR has no regular installer marker; refusing to remove it"
    grep -Fxq -- "$VENV_MARKER_CONTENT" "$VENV_MARKER" \
        || fail "$VENV_DIR has an unrecognized installer marker; refusing to remove it"
    confirm_exact_path "Remove the application virtual environment?" "REMOVE $VENV_DIR"
fi

if [[ ! -e "$UNIT_FILE" ]] && systemctl is-active --quiet "$SERVICE_NAME"; then
    fail "$SERVICE_NAME is active but its managed unit file is missing; stop it manually before cleanup"
fi
if [[ -e "$UNIT_FILE" ]]; then
    systemctl stop "$SERVICE_NAME" || fail "Could not stop $SERVICE_NAME; no files were removed"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        fail "$SERVICE_NAME is still active; no files were removed"
    fi
    systemctl disable "$SERVICE_NAME" || fail "Could not disable $SERVICE_NAME; no files were removed"
    rm -f -- "$UNIT_FILE"
    systemctl daemon-reload
    systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
    printf '[quick-access-uninstall] Removed and stopped %s.service\n' "$SERVICE_NAME"
else
    printf '[quick-access-uninstall] No installed systemd unit found\n'
fi

if "$remove_venv"; then
    if [[ -e "$VENV_DIR" ]]; then
        rm -rf -- "$VENV_DIR"
        printf '[quick-access-uninstall] Removed installer-managed venv\n'
    else
        printf '[quick-access-uninstall] No venv found\n'
    fi
fi

if "$purge_data"; then
    if [[ -e "$DATA_DIR" ]]; then
        rm -rf -- "$DATA_DIR"
        printf '[quick-access-uninstall] Deleted installer-managed data directory\n'
    else
        printf '[quick-access-uninstall] No data directory found\n'
    fi
fi

cat <<'EOF'
Uninstall finished. Source files and access_control/access.env / vault_control/vault.env
were preserved. Keep VAULT_ENCRYPTION_KEY with any Vault database backup; without it,
existing Vault records cannot be decrypted. Revoke target-service PATs separately.
EOF
