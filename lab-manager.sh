#!/bin/bash
# Docker Lab Management Script for ARP DoS Storm
# Educational/Research Purpose Only

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Lab configuration
LAB_NAME="arp-dos-storm-lab"
COMPOSE_FILE="docker-compose.yml"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================================${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    print_status "Docker found: $(docker --version)"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    print_status "Docker Compose found: $(docker-compose --version)"
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    print_status "Docker daemon is running"
    
    # Check compose file exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        print_error "docker-compose.yml not found in current directory"
        exit 1
    fi
    print_status "Docker Compose file found"
}

# Function to build containers
build_lab() {
    print_header "Building ARP DoS Storm Lab Containers"
    
    print_status "Building containers..."
    docker-compose build --no-cache
    
    print_status "Containers built successfully!"
}

# Function to start the lab
start_lab() {
    print_header "Starting ARP DoS Storm Lab"
    
    # Create necessary directories
    mkdir -p logs results captures
    
    print_status "Starting containers..."
    docker-compose up -d
    
    print_status "Waiting for containers to initialize..."
    sleep 10
    
    # Check container status
    print_status "Container status:"
    docker-compose ps
    
    print_status "Lab started successfully!"
    print_status "Web dashboard: http://localhost:8080"
    print_status "Victim services: http://localhost:80"
}

# Function to stop the lab
stop_lab() {
    print_header "Stopping ARP DoS Storm Lab"
    
    print_status "Stopping containers..."
    docker-compose down
    
    print_status "Lab stopped successfully!"
}

# Function to restart the lab
restart_lab() {
    print_header "Restarting ARP DoS Storm Lab"
    
    stop_lab
    sleep 5
    start_lab
}

# Function to show lab status
show_status() {
    print_header "ARP DoS Storm Lab Status"
    
    print_status "Container status:"
    docker-compose ps
    
    echo ""
    print_status "Container logs (last 10 lines each):"
    
    echo -e "\n${YELLOW}=== Attacker Logs ===${NC}"
    docker-compose logs --tail=10 attacker 2>/dev/null || echo "Attacker container not running"
    
    echo -e "\n${YELLOW}=== Victim Logs ===${NC}"
    docker-compose logs --tail=10 victim 2>/dev/null || echo "Victim container not running"
    
    echo -e "\n${YELLOW}=== Observer Logs ===${NC}"
    docker-compose logs --tail=10 observer 2>/dev/null || echo "Observer container not running"
}

# Function to access container shell
access_container() {
    local container_name=$1
    
    if [ -z "$container_name" ]; then
        print_error "Please specify container name: attacker, victim, or observer"
        exit 1
    fi
    
    print_status "Accessing $container_name container..."
    docker-compose exec $container_name /bin/bash
}

# Function to view logs
view_logs() {
    local container_name=$1
    
    if [ -z "$container_name" ]; then
        print_status "Showing logs for all containers..."
        docker-compose logs -f
    else
        print_status "Showing logs for $container_name..."
        docker-compose logs -f $container_name
    fi
}

# Function to clean up everything
cleanup_lab() {
    print_header "Cleaning Up ARP DoS Storm Lab"
    
    print_warning "This will remove all containers, networks, and volumes!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Stopping and removing containers..."
        docker-compose down -v --remove-orphans
        
        print_status "Removing images..."
        docker-compose down --rmi all
        
        print_status "Cleaning up Docker system..."
        docker system prune -f
        
        print_status "Cleanup completed!"
    else
        print_status "Cleanup cancelled"
    fi
}

# Function to run attack scenarios
run_attack() {
    local attack_type=$1
    
    case $attack_type in
        "basic")
            print_status "Running basic ARP storm attack..."
            docker-compose exec attacker python attacker_main.py --basic-storm
            ;;
        "intense")
            print_status "Running high-intensity attack..."
            docker-compose exec attacker python attacker_main.py --intense
            ;;
        "poison")
            print_status "Running targeted poisoning attack..."
            docker-compose exec attacker python attacker_main.py --poison
            ;;
        *)
            print_status "Available attack types: basic, intense, poison"
            print_status "Usage: $0 attack <type>"
            ;;
    esac
}

# Function to export results
export_results() {
    print_header "Exporting Lab Results"
    
    local export_dir="lab_export_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$export_dir"
    
    print_status "Exporting logs..."
    cp -r logs "$export_dir/" 2>/dev/null || echo "No logs to export"
    
    print_status "Exporting results..."
    cp -r results "$export_dir/" 2>/dev/null || echo "No results to export"
    
    print_status "Exporting captures..."
    cp -r captures "$export_dir/" 2>/dev/null || echo "No captures to export"
    
    print_status "Exporting container logs..."
    docker-compose logs > "$export_dir/container_logs.txt" 2>/dev/null || echo "No container logs"
    
    print_status "Creating archive..."
    tar -czf "${export_dir}.tar.gz" "$export_dir"
    rm -rf "$export_dir"
    
    print_status "Results exported to ${export_dir}.tar.gz"
}

# Function to show help
show_help() {
    echo "ARP DoS Storm Lab Management Script"
    echo "Educational/Research Purpose Only"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  check          Check prerequisites"
    echo "  build          Build lab containers"
    echo "  start          Start the lab"
    echo "  stop           Stop the lab"
    echo "  restart        Restart the lab"
    echo "  status         Show lab status"
    echo "  logs [name]    View logs (all or specific container)"
    echo "  shell <name>   Access container shell (attacker/victim/observer)"
    echo "  attack <type>  Run attack scenario (basic/intense/poison)"
    echo "  export         Export lab results"
    echo "  cleanup        Clean up everything"
    echo "  help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 start                    # Start the lab"
    echo "  $0 shell attacker          # Access attacker container"
    echo "  $0 logs observer           # View observer logs"
    echo "  $0 attack basic            # Run basic attack"
    echo ""
    echo "Web Interfaces:"
    echo "  http://localhost:8080      # Monitoring dashboard"
    echo "  http://localhost:80        # Victim services"
}

# Main script logic
case "${1:-help}" in
    "check")
        check_prerequisites
        ;;
    "build")
        check_prerequisites
        build_lab
        ;;
    "start")
        check_prerequisites
        start_lab
        ;;
    "stop")
        stop_lab
        ;;
    "restart")
        restart_lab
        ;;
    "status")
        show_status
        ;;
    "logs")
        view_logs $2
        ;;
    "shell")
        access_container $2
        ;;
    "attack")
        run_attack $2
        ;;
    "export")
        export_results
        ;;
    "cleanup")
        cleanup_lab
        ;;
    "help"|"--help"|"-h")
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
