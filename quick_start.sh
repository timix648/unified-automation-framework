#!/bin/bash

# ============================================================================
# UAF Quick Start Script
# ============================================================================
# This script automates the initial setup of the UAF Backend
# ============================================================================

set -e  # Exit on error

echo "=============================================="
echo "UAF - Unified Automation Framework"
echo "Quick Start Setup Script"
echo "=============================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        echo "Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_success "Docker is installed"
}

# Check if Docker Compose is installed
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        echo "Visit: https://docs.docker.com/compose/install/"
        exit 1
    fi
    print_success "Docker Compose is installed"
}

# Create .env file if it doesn't exist
setup_env() {
    if [ ! -f backend/.env ]; then
        print_info "Creating .env file..."
        cp backend/.env.example backend/.env 2>/dev/null || cat > backend/.env << EOF
# --- SYSTEM SETTINGS ---
PROJECT_NAME="UAF - Unified Automation Framework"
VERSION="1.0.0"
MOCK_MODE=True

# --- CISCO SWITCH (SSH) ---
CISCO_IP=192.168.1.10
CISCO_PORT=22
CISCO_USER=admin
CISCO_PASS=cisco123
CISCO_SECRET=cisco123

# --- MIKROTIK ROUTER (SSH/API) ---
MIKROTIK_IP=192.168.1.20
MIKROTIK_PORT=22
MIKROTIK_USER=admin
MIKROTIK_PASS=mikrotik123

# --- UNIFI CONTROLLER (API) ---
UNIFI_IP=192.168.1.30
UNIFI_PORT=8443
UNIFI_USER=ubnt
UNIFI_PASS=ubnt123
UNIFI_SITE=default

# --- NETBOX INTEGRATION ---
NETBOX_URL=http://netbox:8080
NETBOX_TOKEN=0123456789abcdef0123456789abcdef01234567
EOF
        print_success ".env file created"
    else
        print_info ".env file already exists"
    fi
}

# Create necessary directories
setup_directories() {
    print_info "Creating necessary directories..."
    mkdir -p backend/logs
    mkdir -p backend/tests
    print_success "Directories created"
}

# Pull Docker images
pull_images() {
    print_info "Pulling Docker images (this may take a few minutes)..."
    docker-compose pull
    print_success "Docker images pulled"
}

# Start services
start_services() {
    print_info "Starting UAF services..."
    docker-compose up -d
    print_success "Services started"
}

# Wait for services to be ready
wait_for_services() {
    print_info "Waiting for services to be ready..."
    
    # Wait for backend
    echo -n "  Backend API: "
    for i in {1..30}; do
        if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
            print_success "Ready"
            break
        fi
        sleep 2
        echo -n "."
    done
    
    # Wait for NetBox
    echo -n "  NetBox: "
    for i in {1..60}; do
        if curl -s http://localhost:8080/api/ > /dev/null 2>&1; then
            print_success "Ready"
            break
        fi
        sleep 2
        echo -n "."
    done
}

# Display access information
display_info() {
    echo ""
    echo "=============================================="
    echo "🎉 UAF Setup Complete!"
    echo "=============================================="
    echo ""
    echo "Access your services:"
    echo ""
    echo "  📡 UAF Backend API:"
    echo "     http://localhost:8000"
    echo "     Docs: http://localhost:8000/docs"
    echo ""
    echo "  📊 NetBox (Source of Truth):"
    echo "     http://localhost:8080"
    echo "     Username: admin"
    echo "     Password: admin"
    echo ""
    echo "Default API Credentials:"
    echo "  Admin: admin/admin123"
    echo "  Operator: operator/operator123"
    echo "  Viewer: viewer/viewer123"
    echo ""
    echo "Quick Test:"
    echo "  curl http://localhost:8000/"
    echo ""
    echo "View Logs:"
    echo "  docker-compose logs -f uaf-backend"
    echo ""
    echo "Stop Services:"
    echo "  docker-compose down"
    echo ""
    echo "=============================================="
}

# Main execution
main() {
    check_docker
    check_docker_compose
    setup_env
    setup_directories
    pull_images
    start_services
    wait_for_services
    display_info
}

# Run main function
main
