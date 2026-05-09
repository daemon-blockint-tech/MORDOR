#!/usr/bin/env bash
set -euo pipefail

MORDOR_REPO="https://github.com/daemon-blockint-tech/MORDOR.git"
BRANCH="main"
INSTALL_DIR="${MORDOR_DIR:-$HOME/.mordor}"

print_banner() {
  cat <<'BANNER'
╔══════════════════════════════════════════════════════════════╗
║                     M O R D O R                             ║
║  Malware Orchestration & Reverse engineering                ║
║  Detection Operations Runtime                               ║
║                                                            ║
║  "One does not simply walk into Mordor —                    ║
║   and no malware simply hides within it."                   ║
╚══════════════════════════════════════════════════════════════╝
BANNER
}

info()  { printf "  \033[1;34m→\033[0m %s\n" "$*"; }
success() { printf "  \033[1;32m✔\033[0m %s\n" "$*"; }
warn()  { printf "  \033[1;33m⚠\033[0m %s\n" "$*"; }
fail()  { printf "  \033[1;31m✖\033[0m %s\n" "$*" >&2; exit 1; }

check_deps() {
  local missing=0
  for cmd in python3 git curl; do
    if ! command -v "$cmd" &>/dev/null; then
      warn "Missing dependency: $cmd"
      missing=1
    fi
  done
  if ! python3 -c "import sys; assert sys.version_info >= (3, 10)" 2>/dev/null; then
    warn "Python 3.10+ required (found: $(python3 --version 2>&1 || echo 'none'))"
    missing=1
  fi
  [ "$missing" -eq 1 ] && fail "Install missing dependencies above and re-run."
  success "All dependencies satisfied"
}

install_mordor() {
  if [ -d "$INSTALL_DIR" ]; then
    warn "MORDOR already installed at $INSTALL_DIR"
    info "Pulling latest..."
    git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH" 2>/dev/null || {
      warn "Could not auto-update. Remove $INSTALL_DIR and re-run to re-clone."
    }
  else
    info "Cloning MORDOR into $INSTALL_DIR..."
    git clone --depth 1 --branch "$BRANCH" "$MORDOR_REPO" "$INSTALL_DIR"
    success "Repository cloned"
  fi
}

setup_venv() {
  info "Creating Python virtual environment..."
  python3 -m venv "$INSTALL_DIR/.venv"
  source "$INSTALL_DIR/.venv/bin/activate"
  info "Installing Python dependencies..."
  pip install --quiet --upgrade pip
  pip install --quiet -r "$INSTALL_DIR/requirements.txt"
  success "Dependencies installed"
}

setup_env() {
  if [ ! -f "$INSTALL_DIR/.env" ]; then
    info "Creating .env from .env.example..."
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    warn "EDIT $INSTALL_DIR/.env and add your API keys:"
    warn "  ANTHROPIC_API_KEY  (for Claude-powered agents)"
    warn "  SHODAN_API_KEY     (for OSINT lookups via ARAGORN)"
    warn "  OPENROUTER_KEY     (for LLM routing via OpenRouter)"
  else
    success ".env already configured"
  fi
}

verify() {
  info "Verifying installation..."
  (
    source "$INSTALL_DIR/.venv/bin/activate"
    python3 -c "import langgraph; print('  LangGraph:', langgraph.__version__)" 2>/dev/null || warn "  langgraph not importable (run pip install)"
    python3 -c "import yara; print('  YARA:', yara.__version__)" 2>/dev/null || warn "  yara-python not installed (optional)"
    python3 -c "import shodan; print('  Shodan:', shodan.__version__)" 2>/dev/null || warn "  shodan not installed"
  )
}

print_usage() {
  cat <<USAGE

  MORDOR is ready at: $INSTALL_DIR

  ── Quick Start ──────────────────────────────────────────────

    Activate environment:
      source $INSTALL_DIR/.venv/bin/activate

    Analyze a binary (standard tier):
      python $INSTALL_DIR/scripts/run_analysis.py /path/to/sample.bin --tier standard

    Quick triage (no LLM calls):
      python $INSTALL_DIR/scripts/run_analysis.py /path/to/sample.bin --tier quick

    Deep investigation:
      python $INSTALL_DIR/scripts/run_analysis.py /path/to/sample.bin --tier deep

    Stream live updates:
      python $INSTALL_DIR/scripts/run_analysis.py /path/to/sample.bin --stream

  ── Help & Docs ─────────────────────────────────────────────

    Full documentation in: $INSTALL_DIR/CLAUDE.md

  "One does not simply walk into Mordor —
   and no malware simply hides within it."

USAGE
}

main() {
  print_banner
  echo ""
  info "Installing MORDOR — AI Reverse Engineering Pipeline"
  echo ""

  check_deps
  install_mordor
  setup_venv
  setup_env
  verify

  echo ""
  success "MORDOR installation complete"
  print_usage
}

main
