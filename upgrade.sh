#!/usr/bin/env bash
set -euo pipefail

# CyberStrikeAI GitHub one-click upgrade script (Branch/Tag)
#
# Default preserves:
# - config.yaml
# - data/
# - venv/ (disabled with --no-venv)
# - tools/ (user extensions; never overwritten by upgrade)
#
# Default syncs (overwrites with upstream):
# - roles/
# - skills/

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BINARY_NAME="cyberstrike-ai"
CONFIG_FILE="$ROOT_DIR/config.yaml"
DATA_DIR="$ROOT_DIR/data"
VENV_DIR="$ROOT_DIR/venv"
KNOWLEDGE_BASE_DIR="$ROOT_DIR/knowledge_base"

BACKUP_BASE_DIR="$ROOT_DIR/.upgrade-backup"
TMP_DIR=""

GITHUB_REPO="langbyyi/CyberStrikeAI-SRC"

TAG=""
BRANCH="${GITHUB_BRANCH:-master}"
TAG_SET=0
BRANCH_SET=0
PRESERVE_VENV=1
STOP_SERVICE=1
FORCE_STOP=0
YES=0
SYNC_ROLES_SKILLS=1

usage() {
  cat <<EOF
Usage:
  ./upgrade.sh [--branch master | --tag vX.Y.Z] [--no-venv] [--no-stop]
                [--force-stop] [--yes] [--no-sync-roles-skills]

Options:
  --branch <branch>        Upgrade from a GitHub source branch (default: master).
                            The default can also be set with GITHUB_BRANCH.
  --tag <tag>              Upgrade from a GitHub source tag (e.g. v1.3.28).
  --no-venv                 Do not preserve venv/ (Python deps will be re-installed).
  --no-stop                 Do not try to stop the running service.
  --force-stop             If no process matching current directory is found, also stop
                            any cyberstrike-ai processes (use with caution).
  --yes                     Do not ask for confirmation.
  --no-sync-roles-skills   Preserve local roles/ and skills/ instead of syncing from
                            upstream (default: roles/skills are synced).
                            tools/ is always preserved (user extensions).

Description:
  The script backs up config.yaml/data/tools/roles/skills/ (and optionally venv/) to
  .upgrade-backup/. By default roles/ and skills/ are synced from upstream so the
  latest predefined roles and skill packs ship on upgrade; pass --no-sync-roles-skills
  to keep your local edits.
EOF
}

log() { printf "%s\n" "$*"; }
info() { log "[INFO]  $*"; }
warn() { log "[WARN]  $*"; }
err() { log "[ERROR] $*"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

http_get() {
  # $1: url
  if have_cmd curl; then
    curl -fsSL "$1"
  elif have_cmd wget; then
    wget -qO- "$1"
  else
    err "curl or wget is required to download GitHub source archives. Please install one of them."
    exit 1
  fi
}

stop_service() {
  # Try to stop the service that is running from the current project directory.
  # If nothing is found and --force-stop is enabled, stop all cyberstrike-ai processes.
  if [[ "$STOP_SERVICE" -ne 1 ]]; then
    return 0
  fi

  local pids=""
  if have_cmd pgrep; then
    # Prefer matches where the command line contains the current project path.
    pids="$(pgrep -f "${ROOT_DIR}.*${BINARY_NAME}" || true)"
    if [[ -z "$pids" && "$FORCE_STOP" -eq 1 ]]; then
      warn "No ${BINARY_NAME} process found under the current directory. Will try to force-stop all matching ${BINARY_NAME} processes."
      pids="$(pgrep -f "${BINARY_NAME}" || true)"
    fi
  fi

  if [[ -z "$pids" ]]; then
    info "No ${BINARY_NAME} process detected (or no matching process). Skipping stop step."
    return 0
  fi

  warn "Detected running PID(s): ${pids}"
  for pid in $pids; do
    if kill -0 "$pid" 2>/dev/null; then
      info "Sending SIGTERM to PID=${pid}..."
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done

  # Wait for exit
  local deadline=$((SECONDS + 20))
  while [[ $SECONDS -lt $deadline ]]; do
    local alive=0
    for pid in $pids; do
      if kill -0 "$pid" 2>/dev/null; then
        alive=1
        break
      fi
    done
    if [[ "$alive" -eq 0 ]]; then
      info "Service stopped."
      return 0
    fi
    sleep 1
  done

  warn "Timed out waiting for processes to exit. Still running PID(s): ${pids} (may still hold file handles)."
  return 0
}

backup_dir_tgz() {
  # $1: label, $2: path
  local label="$1"
  local path="$2"
  if [[ -e "$path" ]]; then
    info "Backing up ${label} -> ${BACKUP_BASE_DIR}/$(basename "$path").tgz"
    tar -czf "${BACKUP_BASE_DIR}/$(basename "$path").tgz" -C "$ROOT_DIR" "$(basename "$path")"
  fi
}

backup_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    cp -a "$CONFIG_FILE" "${BACKUP_BASE_DIR}/config.yaml"
  fi
}

ensure_git_style_env() {
  # No hard requirement; just a sanity check.
  if [[ ! -f "$CONFIG_FILE" ]]; then
    err "Could not find ${CONFIG_FILE}. Please verify you are in the correct project directory."
    exit 1
  fi
}

confirm_or_exit() {
  if [[ "$YES" -eq 1 ]]; then
    return 0
  fi

  if [[ ! -t 0 ]]; then
    err "Non-interactive terminal detected. Please add --yes to continue."
    exit 1
  fi

  warn "About to perform upgrade:"
  info " - Preserve config.yaml: yes"
  info " - Preserve data/: yes"
  if [[ "$PRESERVE_VENV" -eq 1 ]]; then
    info " - Preserve venv/: yes"
  else
    info " - Preserve venv/: no (will remove old venv and re-install deps)"
  fi
  info " - Preserve tools/: yes (always)"
  if [[ "$SYNC_ROLES_SKILLS" -eq 1 ]]; then info " - Sync roles/skills from upstream: yes (default; use --no-sync-roles-skills to preserve local)"; else info " - Preserve roles/skills: yes"; fi
  info " - Stop service: ${STOP_SERVICE}"
  echo ""
  read -r -p "Continue? (y/N) " ans
  if [[ "${ans:-N}" != "y" && "${ans:-N}" != "Y" ]]; then
    err "Cancelled."
    exit 1
  fi
}

update_config_version() {
  # Replace config.yaml's version: ... with the selected source version.
  local new_tag="$1"
  python3 - "$CONFIG_FILE" "$new_tag" <<PY
import re, sys
path=sys.argv[1]
tag=sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    lines=f.readlines()

out=[]
replaced=False
for line in lines:
    if re.match(r'^\s*version\s*:', line):
        out.append(f'version: "{tag}"\\n')
        replaced=True
    else:
        out.append(line)

if not replaced:
    # If no version field is found, insert at the beginning (near the top).
    out.insert(0, f'version: "{tag}"\\n')

with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
PY
}

sync_code() {
  local tmp_dir="$1"
  local new_src_dir="$2"

  # rsync sync: overwrite files from the new version and delete removed files.
  # Preserve user data/config (and optional directories).

  if ! have_cmd rsync; then
    err "rsync not found. This script depends on rsync for safe synchronization. Please install it and retry."
    exit 1
  fi

  local -a rsync_excludes
  rsync_excludes+=( "--exclude=.upgrade-backup/" )
  rsync_excludes+=( "--exclude=.git/" )
  rsync_excludes+=( "--exclude=config.yaml" )
  rsync_excludes+=( "--exclude=data/" )

  if [[ "$PRESERVE_VENV" -eq 1 ]]; then
    rsync_excludes+=( "--exclude=venv/" )
  fi

  # knowledge_base may not be referenced in config, but many users treat it as the knowledge files directory.
  if [[ -d "$KNOWLEDGE_BASE_DIR" ]]; then
    rsync_excludes+=( "--exclude=knowledge_base/" )
  fi

  # User tool extensions: never replace or delete during upgrade.
  rsync_excludes+=( "--exclude=tools/" )
  # roles/ and skills/ default preserved; --sync-roles-skills overrides to sync from upstream.
  if [[ "$SYNC_ROLES_SKILLS" -ne 1 ]]; then
    rsync_excludes+=( "--exclude=roles/" )
    rsync_excludes+=( "--exclude=skills/" )
  fi

  # shellcheck disable=SC2068
  info "Syncing code into current directory (preserving data/config; using rsync --delete)..."
  rsync -a --delete \
    ${rsync_excludes[@]} \
    "${new_src_dir}/" "${ROOT_DIR}/"
}

main() {
  ensure_git_style_env

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        if [[ $# -lt 2 || -z "${2:-}" ]]; then
          err "--tag requires a non-empty tag."
          exit 1
        fi
        TAG="$2"
        TAG_SET=1
        shift 2
        ;;
      --branch)
        if [[ $# -lt 2 || -z "${2:-}" ]]; then
          err "--branch requires a non-empty branch."
          exit 1
        fi
        BRANCH="$2"
        BRANCH_SET=1
        shift 2
        ;;
      --no-venv)
        PRESERVE_VENV=0
        shift 1
        ;;
      --no-stop)
        STOP_SERVICE=0
        shift 1
        ;;
      --force-stop)
        FORCE_STOP=1
        shift 1
        ;;
      --yes)
        YES=1
        shift 1
        ;;
      --no-sync-roles-skills)
        SYNC_ROLES_SKILLS=0
        shift 1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "Unknown parameter: $1"
        usage
        exit 1
        ;;
    esac
  done

  if [[ "$TAG_SET" -eq 1 && "$BRANCH_SET" -eq 1 ]]; then
    err "--tag and --branch cannot be used together."
    exit 1
  fi

  confirm_or_exit

  stop_service

  local ts
  ts="$(date +"%Y%m%d_%H%M%S")"
  BACKUP_BASE_DIR="${BACKUP_BASE_DIR}/${ts}"
  mkdir -p "$BACKUP_BASE_DIR"

  info "Starting backup into: $BACKUP_BASE_DIR"
  backup_config
  backup_dir_tgz "data" "$DATA_DIR"
  if [[ "$PRESERVE_VENV" -eq 1 ]]; then
    backup_dir_tgz "venv" "$VENV_DIR"
  else
    if [[ -d "$VENV_DIR" ]]; then
      warn "With --no-venv: removing old venv/ (run.sh will re-install Python deps after upgrade)."
      rm -rf "$VENV_DIR"
    fi
  fi
  if [[ -d "$KNOWLEDGE_BASE_DIR" ]]; then
    backup_dir_tgz "knowledge_base" "$KNOWLEDGE_BASE_DIR"
  fi
  if [[ -d "$ROOT_DIR/tools" ]]; then
    backup_dir_tgz "tools" "$ROOT_DIR/tools"
  fi
  if [[ -d "$ROOT_DIR/roles" ]]; then
    backup_dir_tgz "roles" "$ROOT_DIR/roles"
  fi
  if [[ -d "$ROOT_DIR/skills" ]]; then
    backup_dir_tgz "skills" "$ROOT_DIR/skills"
  fi

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR" >/dev/null 2>&1 || true' EXIT

  local tarball="${TMP_DIR}/source.tar.gz"
  local source_version
  local url
  if [[ "$TAG_SET" -eq 1 ]]; then
    source_version="$TAG"
    url="https://github.com/${GITHUB_REPO}/archive/refs/tags/${TAG}.tar.gz"
    info "Using source tag: $TAG"
  else
    source_version="branch:${BRANCH}"
    url="https://github.com/${GITHUB_REPO}/archive/refs/heads/${BRANCH}.tar.gz"
    info "Using source branch: $BRANCH"
  fi
  info "Downloading source package: ${url}"
  http_get "$url" >"$tarball"

  info "Extracting source package..."
  tar -xzf "$tarball" -C "$TMP_DIR"

  # GitHub tarball usually creates a top-level directory.
  local extracted_dir
  extracted_dir="$(ls -d "${TMP_DIR}"/*/ 2>/dev/null | head -n 1 || true)"
  if [[ -z "$extracted_dir" || ! -f "${extracted_dir}/run.sh" ]]; then
    err "run.sh not found in the extracted directory. Please check network/download contents."
    exit 1
  fi

  sync_code "$TMP_DIR" "$extracted_dir"

  # Update config.yaml version display
  if [[ -f "$CONFIG_FILE" ]]; then
    info "Updating config.yaml version field to: $source_version"
    update_config_version "$source_version"
  fi

  info "Upgrade complete. Starting service..."
  chmod +x ./run.sh
  ./run.sh
}

main "$@"

