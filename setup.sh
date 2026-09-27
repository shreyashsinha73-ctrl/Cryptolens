#!/usr/bin/env bash

# ==============================================================================
# Cryptolens Universal One-Command Setup & Startup Script
# Automatically verifies/installs Python virtualenv & backend dependencies,
# verifies/installs Node dependencies, and boots both servers concurrently.
# Press Ctrl+C to cleanly terminate all services.
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "=================================================="
echo " Cryptolens Automated Setup & Launcher"
echo "=================================================="

# ------------------------------------------------------------------------------
# 1. Python Environment & Dependency Check
# ------------------------------------------------------------------------------
echo "[1/4] Checking Python environment..."

# Locate python3 command
if command -v python3 &>/dev/null; then
  SYSTEM_PYTHON="python3"
elif command -v python &>/dev/null; then
  SYSTEM_PYTHON="python"
else
  echo "Error: Neither 'python3' nor 'python' was found in your PATH."
  echo "Please install Python 3.10+ to run Cryptolens."
  exit 1
fi

VENV_DIR="$PROJECT_ROOT/.venv"
PYTHON_BIN=""
PIP_BIN=""

# Python virtualenv layouts differ between Linux/WSL and Windows Git Bash.
if [ -f "$VENV_DIR/bin/python" ]; then
  PYTHON_BIN="$VENV_DIR/bin/python"
  PIP_BIN="$VENV_DIR/bin/pip"
elif [ -f "$VENV_DIR/Scripts/python.exe" ]; then
  PYTHON_BIN="$VENV_DIR/Scripts/python.exe"
  PIP_BIN="$VENV_DIR/Scripts/pip.exe"
elif [ -f "$VENV_DIR/Scripts/python" ]; then
  PYTHON_BIN="$VENV_DIR/Scripts/python"
  PIP_BIN="$VENV_DIR/Scripts/pip"
fi

# Create virtual environment if not already present
if [ -z "$PYTHON_BIN" ] || [ ! -f "$PYTHON_BIN" ]; then
  echo "Creating virtual environment at .venv using $SYSTEM_PYTHON..."
  "$SYSTEM_PYTHON" -m venv "$VENV_DIR" || {
    echo "Notice: Standard venv module failed, trying system python directly."
    PYTHON_BIN="$SYSTEM_PYTHON"
    PIP_BIN="$SYSTEM_PYTHON -m pip"
  }
fi

# Refresh the Python helper paths after creation in case the venv layout is OS-specific.
if [ -f "$VENV_DIR/bin/python" ]; then
  PYTHON_BIN="$VENV_DIR/bin/python"
  PIP_BIN="$VENV_DIR/bin/pip"
elif [ -f "$VENV_DIR/Scripts/python.exe" ]; then
  PYTHON_BIN="$VENV_DIR/Scripts/python.exe"
  PIP_BIN="$VENV_DIR/Scripts/pip.exe"
elif [ -f "$VENV_DIR/Scripts/python" ]; then
  PYTHON_BIN="$VENV_DIR/Scripts/python"
  PIP_BIN="$VENV_DIR/Scripts/pip"
fi

# Install/Update backend dependencies from requirements.txt
if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
  echo "Verifying / Installing Python dependencies from requirements.txt..."
  if [ -n "$PIP_BIN" ] && [ -f "$PIP_BIN" ]; then
    "$PIP_BIN" install --quiet --upgrade pip
    "$PIP_BIN" install --quiet -r "$PROJECT_ROOT/requirements.txt"
  else
    eval "$PIP_BIN install --quiet -r \"$PROJECT_ROOT/requirements.txt\""
  fi
fi

# ------------------------------------------------------------------------------
# 2. Node & Frontend Dependency Check
# ------------------------------------------------------------------------------
echo "[2/4] Checking Node & Frontend environment..."

if ! command -v npm &>/dev/null; then
  echo "Error: 'npm' was not found in your PATH."
  echo "Please install Node.js (version 18+) to run the frontend."
  exit 1
fi

if [ ! -d "$PROJECT_ROOT/node_modules" ]; then
  echo "Installing frontend dependencies via npm install..."
  npm install --silent
else
  echo "Frontend dependencies are already installed."
fi

# Ensure storage runtime folders exist
mkdir -p "$PROJECT_ROOT/backend/uploads"
mkdir -p "$PROJECT_ROOT/backend/stored_results"
mkdir -p "$PROJECT_ROOT/backend/generated_reports"

# ------------------------------------------------------------------------------
# 3. Process Cleanup Handler (Ctrl+C)
# ------------------------------------------------------------------------------
cleanup() {
  echo ""
  echo "Shutting down Cryptolens servers..."
  if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  echo "All processes stopped cleanly."
  exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# ------------------------------------------------------------------------------
# 4. Launch Services
# ------------------------------------------------------------------------------
BACKEND_PID=""

if python3 - "$PROJECT_ROOT" <<'PY'
import socket, sys
host = '127.0.0.1'
port = 8000
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.5)
try:
    sock.connect((host, port))
except OSError:
    sys.exit(0)
else:
    print(f"Port {port} is already in use on {host}; reusing the existing backend instance.")
    sys.exit(1)
finally:
    sock.close()
PY
then
  echo "[3/4] Launching FastAPI Backend on http://localhost:8000 ..."
  "$PYTHON_BIN" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 &
  BACKEND_PID=$!
  sleep 1
else
  echo "[3/4] Backend already running on http://localhost:8000; continuing without restarting it."
fi

echo "[4/4] Launching Vite Frontend on http://localhost:5173 ..."
npm run dev &
FRONTEND_PID=$!

echo ""
echo "=================================================="
echo " Cryptolens is ready!"
echo " - Web Dashboard:  http://localhost:5173"
echo " - REST API:       http://localhost:8000"
echo " - API Swagger UI: http://localhost:8000/docs"
echo " Press Ctrl+C at any time to stop both servers."
echo "=================================================="
echo ""

if [ -n "$BACKEND_PID" ]; then
  wait $BACKEND_PID
fi
if [ -n "$FRONTEND_PID" ]; then
  wait $FRONTEND_PID
fi
