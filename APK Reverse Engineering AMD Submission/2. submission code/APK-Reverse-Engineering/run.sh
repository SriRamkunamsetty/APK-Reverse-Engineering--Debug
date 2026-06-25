#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# RAKSHAK — Startup Script
# DRDO APK Threat Intelligence Platform v3.0.0
# ═══════════════════════════════════════════════════════════════════════

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ─────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; BOLD='\033[1m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; DIM='\033[2m'; RESET='\033[0m'

banner() {
  echo -e "${GREEN}${BOLD}"
  echo "  ██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗"
  echo "  ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝"
  echo "  ██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝ "
  echo "  ██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██╔═██╗ "
  echo "  ██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║  ██╗"
  echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"
  echo -e "${RESET}"
  echo -e "${BOLD}  APK Threat Intelligence Platform v3.0.0${RESET}"
  echo -e "${DIM}  DRDO Cybersecurity Division | IIT Hyderabad${RESET}"
  echo -e "${RED}${BOLD}  ⬛  SENSITIVE — DRDO CYBERSECURITY DIVISION${RESET}"
  echo ""
}

check_python() {
  if ! command -v python3 &>/dev/null; then
    echo -e "${RED}✗ Python 3 not found. Install Python 3.10+${RESET}"; exit 1
  fi
  PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  echo -e "${GREEN}✓${RESET} Python ${PYVER}"
}

check_deps() {
  echo -e "${DIM}Checking dependencies...${RESET}"
  python3 -c "import fastapi, androguard, anthropic, reportlab, rich" 2>/dev/null && \
    echo -e "${GREEN}✓${RESET} All dependencies present" || \
    { echo -e "${YELLOW}! Installing dependencies...${RESET}"
      pip install -r requirements.txt --break-system-packages -q; }
}

setup_dirs() {
  mkdir -p uploads reports database static
  echo -e "${GREEN}✓${RESET} Directories ready"
}

check_api_key() {
  if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${YELLOW}⚠ ANTHROPIC_API_KEY not set — GenAI reasoning will use fallback mode${RESET}"
    echo -e "${DIM}  Set it: export ANTHROPIC_API_KEY=sk-ant-...${RESET}"
  else
    echo -e "${GREEN}✓${RESET} Anthropic API key configured"
  fi
}

start_server() {
  echo ""
  echo -e "${GREEN}${BOLD}Starting RAKSHAK server...${RESET}"
  echo -e "${DIM}Dashboard: http://localhost:${PORT:-8000}${RESET}"
  echo -e "${DIM}API Docs:  http://localhost:${PORT:-8000}/api/docs${RESET}"
  echo -e "${DIM}Press Ctrl+C to stop${RESET}"
  echo ""
  python3 -m uvicorn main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}" --reload
}

# ── Main ─────────────────────────────────────────────────────────────────────
banner
check_python
check_deps
setup_dirs
check_api_key
start_server
