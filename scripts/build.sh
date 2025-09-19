#!/bin/bash
# CamRelay Build Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
BUILD_TYPE="release"
CLEAN=false
INSTALL=false
VERBOSE=false

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE     Build type (debug|release) [default: release]"
    echo "  -c, --clean         Clean build directory before building"
    echo "  -i, --install       Install after building"
    echo "  -v, --verbose       Verbose output"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Build release version"
    echo "  $0 -t debug -c      # Clean build debug version"
    echo "  $0 -i               # Build and install"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -i|--install)
            INSTALL=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate build type
if [[ "$BUILD_TYPE" != "debug" && "$BUILD_TYPE" != "release" ]]; then
    print_error "Invalid build type: $BUILD_TYPE"
    print_error "Valid types: debug, release"
    exit 1
fi

print_status "Building CamRelay ($BUILD_TYPE mode)"

# Check if we're in the right directory
if [[ ! -f "Makefile" ]]; then
    print_error "Makefile not found. Please run this script from the project root."
    exit 1
fi

# Clean if requested
if [[ "$CLEAN" == true ]]; then
    print_status "Cleaning build directory..."
    make clean
fi

# Set build flags
if [[ "$BUILD_TYPE" == "debug" ]]; then
    print_status "Building debug version..."
    make debug
else
    print_status "Building release version..."
    make release
fi

# Check if build was successful
if [[ $? -eq 0 ]]; then
    print_status "Build completed successfully!"
    
    # Show build info
    if [[ -f "build/bin/camrelay" ]]; then
        print_status "Binary location: build/bin/camrelay"
        ls -lh build/bin/camrelay
    fi
    
    # Install if requested
    if [[ "$INSTALL" == true ]]; then
        print_status "Installing CamRelay..."
        sudo make install
        
        if [[ $? -eq 0 ]]; then
            print_status "Installation completed successfully!"
            print_status "You can now run: systemctl start camrelay"
        else
            print_error "Installation failed!"
            exit 1
        fi
    fi
else
    print_error "Build failed!"
    exit 1
fi
