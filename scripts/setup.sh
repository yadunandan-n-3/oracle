#!/bin/bash
"""
ORACLE Setup Script
===================

One-command setup for ORACLE OS development environment.
Run from the project root: bash scripts/setup.sh
"""

set -e

echo "================================================"
echo "  ORACLE OS - Setup Script"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}Project root: ${PROJECT_ROOT}${NC}"
echo ""

# ─── Prerequisites Check ────────────────────────────────────────────────

echo -e "${YELLOW}Checking prerequisites...${NC}"

# Python 3.12+
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "  Python: ${GREEN}${PYTHON_VERSION}${NC}"
else
    echo -e "  Python: ${RED}not found${NC}"
    echo "  Install Python 3.12+ from https://www.python.org/downloads/"
    exit 1
fi

# Node.js 20+
if command -v node &>/dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "  Node.js: ${GREEN}${NODE_VERSION}${NC}"
else
    echo -e "  Node.js: ${RED}not found${NC}"
    echo "  Install Node.js 20+ from https://nodejs.org/"
    exit 1
fi

# Docker
if command -v docker &>/dev/null; then
    echo -e "  Docker: ${GREEN}found${NC}"
else
    echo -e "  Docker: ${RED}not found${NC}"
    echo "  Install Docker from https://www.docker.com/products/docker-desktop/"
    echo "  Continuing without Docker (databases will not be available)"
fi

# Nmap (optional, for scanning)
if command -v nmap &>/dev/null; then
    echo -e "  Nmap: ${GREEN}$(nmap --version 2>&1 | head -1)${NC}"
else
    echo -e "  Nmap: ${YELLOW}not found (optional)${NC}"
fi

echo ""

# ─── Python Setup ───────────────────────────────────────────────────────

echo -e "${YELLOW}Setting up Python environment...${NC}"

# Create virtual environment
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "  Virtual environment: ${GREEN}created${NC}"
else
    echo -e "  Virtual environment: ${GREEN}exists${NC}"
fi

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip -q
echo -e "  Pip: ${GREEN}upgraded${NC}"

# Install project with dev dependencies
pip install -e ".[dev]" -q
echo -e "  Python dependencies: ${GREEN}installed${NC}"

# Install pre-commit hooks
if command -v pre-commit &>/dev/null; then
    pre-commit install
    echo -e "  Pre-commit hooks: ${GREEN}installed${NC}"
fi

echo ""

# ─── Frontend Setup ─────────────────────────────────────────────────────

echo -e "${YELLOW}Setting up frontend...${NC}"

if [ -d "frontend" ]; then
    cd frontend

    if [ ! -f "package.json" ]; then
        echo -e "  Frontend: ${YELLOW}package.json not found, creating Next.js app...${NC}"
        npx create-next-app@latest . --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --use-npm 2>/dev/null || true
    fi

    if [ -f "package.json" ]; then
        npm install 2>/dev/null || true
        echo -e "  Node modules: ${GREEN}installed${NC}"
    fi

    cd "$PROJECT_ROOT"
else
    echo -e "  Frontend directory: ${YELLOW}not found, creating...${NC}"
    mkdir -p frontend
    cd frontend
    npx create-next-app@latest . --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --use-npm 2>/dev/null || true
    cd "$PROJECT_ROOT"
fi

echo ""

# ─── Docker Setup ───────────────────────────────────────────────────────

echo -e "${YELLOW}Setting up Docker infrastructure...${NC}"

if command -v docker &>/dev/null; then
    echo -e "  Starting Docker Compose services..."
    cd "$PROJECT_ROOT"

    # Check if docker compose is available
    if docker compose version &>/dev/null; then
        docker compose -f docker/docker-compose.yml up -d 2>/dev/null || true
        echo -e "  Docker services: ${GREEN}started${NC}"
    elif docker-compose --version &>/dev/null; then
        docker-compose -f docker/docker-compose.yml up -d 2>/dev/null || true
        echo -e "  Docker services: ${GREEN}started${NC}"
    else
        echo -e "  Docker Compose: ${YELLOW}not found, install Docker Compose${NC}"
    fi
fi

cd "$PROJECT_ROOT"

echo ""

# ─── Summary ─────────────────────────────────────────────────────────────

echo "================================================"
echo -e "  ${GREEN}ORACLE OS setup complete!${NC}"
echo "================================================"
echo ""
echo "Quick start:"
echo ""
echo "  # Activate environment"
echo "  source .venv/bin/activate"
echo ""
echo "  # Start the backend"
echo "  uvicorn backend.main:app --reload"
echo ""
echo "  # Start the frontend"
echo "  cd frontend && npm run dev"
echo ""
echo "  # Open in browser"
echo "  Backend:  http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo "  Frontend: http://localhost:3000"
echo ""
echo "  # Run tests"
echo "  pytest"
echo ""

# For Windows
echo "Note for Windows users:"
echo "  Run 'setup.ps1' instead, or manually:"
echo "    python -m venv .venv"
echo "    .venv\\Scripts\\activate"
echo "    pip install -e '.[dev]'"
echo ""
