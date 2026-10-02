#!/usr/bin/env bash
# ==============================================================================
# CryptoLens v2 — Automated Defense Audit & Verification Demonstration
# Core Claim: Zero Decryption | Zero Plaintext | Passive IPsec Telemetry
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Color constants
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "================================================================================"
echo "    CryptoLens v2 — Passive IPsec Security Audit Platform (Live Demo)"
echo "    Target: Defense & Intelligence Technical Evaluation"
echo "    Claim:  ZERO DECRYPTION, ZERO PLAINTEXT ACCESS"
echo "================================================================================"
echo -e "${NC}"

# Virtualenv check
PYTHON_BIN="python3"
if [ -f "${PROJECT_ROOT}/.venv/bin/python3" ]; then
    PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python3"
    echo -e "${GREEN}[+] Using active virtual environment: ${PYTHON_BIN}${NC}"
fi

echo -e "\n${YELLOW}[*] Executing 5-Stage End-to-End Pipeline Audit...${NC}\n"

cd "${PROJECT_ROOT}"
if "${PYTHON_BIN}" "${PROJECT_ROOT}/scripts/test_v2_features.py"; then
    echo -e "\n${GREEN}${BOLD}================================================================================"
    echo " [+] DEMO AUDIT VERIFICATION COMPLETE: ALL SYSTEMS NOMINAL (5/5 PASSED)"
    echo -e "================================================================================${NC}"
    echo -e "${CYAN}Key Audit Verification Highlights for NTRO / Technical Judges:${NC}"
    echo -e " 1. ${BOLD}Control-Plane AST${NC}: Parses raw IKE exchange metadata without inspecting plaintext."
    echo -e " 2. ${BOLD}Data-Plane 1D-CNN${NC}: Traffic classification (VoIP/Streaming) inferred purely from ESP packet length/IAT."
    echo -e " 3. ${BOLD}XAI Attribution${NC}: Grad-CAM attribution localizes model decisions with strict non-cryptographic semantics."
    echo -e " 4. ${BOLD}Anti-Replay Window${NC}: RFC 4303 64-bit sliding window flags duplicated sequences within 2 seconds."
    echo -e " 5. ${BOLD}Automated Remediation${NC}: Emits validated swanctl.conf enforcing AES-256-GCM / DH 19/20."
    exit 0
else
    echo -e "\n${RED}${BOLD}================================================================================"
    echo " [-] DEMO AUDIT VERIFICATION FAILED"
    echo "================================================================================${NC}"
    exit 1
fi
