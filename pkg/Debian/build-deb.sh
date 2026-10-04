#!/bin/bash

# GoCat Debian Package Builder
# Creates .deb packages for Debian/Ubuntu systems

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
PACKAGE_NAME="gocat"
VERSION="${1:-1.0.0}"
ARCH="${2:-amd64}"
MAINTAINER="Ibrahim <ibrahim@example.com>"
DESCRIPTION="Modern netcat alternative written in Go"
HOMEPAGE="https://github.com/realibrahimsql/Gocat"

# Create package structure
create_package_structure() {
    log_info "Creating package structure for $PACKAGE_NAME v$VERSION ($ARCH)..."
    
    PACKAGE_DIR="${PACKAGE_NAME}_${VERSION}_${ARCH}"
    
    # Clean previous builds
    rm -rf "$PACKAGE_DIR" "${PACKAGE_DIR}.deb"
    
    # Create directory structure
    mkdir -p "$PACKAGE_DIR/DEBIAN"
    mkdir -p "$PACKAGE_DIR/usr/local/bin"
    mkdir -p "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME"
    mkdir -p "$PACKAGE_DIR/usr/share/man/man1"
    
    log_success "Package structure created"
}

# Create control file
create_control_file() {
    log_info "Creating control file..."
    
    cat > "$PACKAGE_DIR/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Depends: libc6 (>= 2.17)
Homepage: $HOMEPAGE
Description: $DESCRIPTION
 GoCat is a modern, feature-rich alternative to netcat written in Go.
 It provides  functionality for network communication, debugging,
 and penetration testing with improved IPv6 support, interactive modes,
 and cross-platform compatibility.
 .
 Features:
  * TCP connection handling (client and server modes)
  * Interactive and local interactive modes
  * IPv6 support with proper address formatting
  * Signal handling and graceful shutdown
  * Cross-platform support (Linux, macOS, Windows)
  * Colored logging output
  * Command history in interactive mode
EOF
    
    log_success "Control file created"
}

# Create postinst script
create_postinst_script() {
    log_info "Creating post-installation script..."
    
    cat > "$PACKAGE_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Create symlink for compatibility
if [ ! -e /usr/bin/gocat ]; then
    ln -s /usr/local/bin/gocat /usr/bin/gocat
fi

# Update man database
if command -v mandb >/dev/null 2>&1; then
    mandb -q
fi

echo "GoCat installed successfully!"
echo "Usage: gocat --help"
EOF
    
    chmod 755 "$PACKAGE_DIR/DEBIAN/postinst"
    log_success "Post-installation script created"
}

# Create prerm script
create_prerm_script() {
    log_info "Creating pre-removal script..."
    
    cat > "$PACKAGE_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Remove symlink
if [ -L /usr/bin/gocat ]; then
    rm -f /usr/bin/gocat
fi
EOF
    
    chmod 755 "$PACKAGE_DIR/DEBIAN/prerm"
    log_success "Pre-removal script created"
}

# Copy binary and documentation
copy_files() {
    log_info "Copying files..."
    
    # Copy binary (assuming it's built)
    if [ -f "../../gocat" ]; then
        cp "../../gocat" "$PACKAGE_DIR/usr/local/bin/"
        chmod 755 "$PACKAGE_DIR/usr/local/bin/gocat"
    elif [ -f "../gocat" ]; then
        cp "../gocat" "$PACKAGE_DIR/usr/local/bin/"
        chmod 755 "$PACKAGE_DIR/usr/local/bin/gocat"
    elif [ -f "gocat" ]; then
        cp "gocat" "$PACKAGE_DIR/usr/local/bin/"
        chmod 755 "$PACKAGE_DIR/usr/local/bin/gocat"
    else
        log_error "Binary not found. Please build gocat first."
        exit 1
    fi
    
    # Create documentation
    cat > "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/README.Debian" << EOF
GoCat for Debian
================

GoCat has been installed to /usr/local/bin/gocat with a symlink at /usr/bin/gocat.

Basic usage:
  gocat listen 8080          # Listen on port 8080
  gocat connect host 8080    # Connect to host:8080

For more information, see the manual page: man gocat
EOF
    
    # Create changelog
    cat > "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/changelog.Debian" << EOF
gocat ($VERSION) unstable; urgency=low

  * Initial Debian package release
  * Modern netcat alternative with Go
  * IPv6 support and interactive modes
  * Cross-platform compatibility

 -- $MAINTAINER  $(date -R)
EOF
    
    # Compress changelog
    gzip -9 "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/changelog.Debian"
    
    # Create copyright file
    cat > "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: gocat
Upstream-Contact: $MAINTAINER
Source: $HOMEPAGE

Files: *
Copyright: $(date +%Y) Ibrahim
License: Apache-2.0

License: Apache-2.0
 Licensed under the Apache License, Version 2.0. You may obtain a copy
 of the License at http://www.apache.org/licenses/LICENSE-2.0. On Debian
 systems the full text lives in /usr/share/common-licenses/Apache-2.0.
EOF
    
    log_success "Files copied successfully"
}

# Create man page
create_man_page() {
    log_info "Creating manual page..."
    
    cat > "$PACKAGE_DIR/usr/share/man/man1/gocat.1" << EOF
.TH GOCAT 1 "$(date +"%B %Y")" "gocat" "User Commands"
.SH NAME
gocat \- modern netcat alternative written in Go
.SH SYNOPSIS
.B gocat
[\fIGLOBAL OPTIONS\fR] \fICOMMAND\fR [\fICOMMAND OPTIONS\fR] [\fIARGUMENTS\fR...]
.SH DESCRIPTION
GoCat is a modern, feature-rich alternative to netcat written in Go. It provides  functionality for network communication, debugging, and penetration testing.
.SH COMMANDS
.TP
.B connect, c
Connect to a remote host
.TP
.B listen, l
Start a listener for incoming connections
.TP
.B help, h
Show help information
.SH GLOBAL OPTIONS
.TP
.B \-h, \-\-help
Show help
.TP
.B \-v, \-\-version
Show version information
.SH EXAMPLES
.TP
Start a listener on port 8080:
.B gocat listen 8080
.TP
Connect to a remote host:
.B gocat connect example.com 8080
.TP
Start interactive listener:
.B gocat listen -i 8080
.SH SEE ALSO
.BR nc (1),
.BR netcat (1),
.BR socat (1)
.SH AUTHOR
Written by Ibrahim.
.SH REPORTING BUGS
Report bugs to: https://github.com/realibrahimsql/Gocat/issues
EOF
    
    # Compress man page
    gzip -9 "$PACKAGE_DIR/usr/share/man/man1/gocat.1"
    
    log_success "Manual page created"
}

# Build the package
build_package() {
    log_info "Building Debian package..."
    
    # Calculate installed size
    INSTALLED_SIZE=$(du -sk "$PACKAGE_DIR" | cut -f1)
    echo "Installed-Size: $INSTALLED_SIZE" >> "$PACKAGE_DIR/DEBIAN/control"
    
    # Build package
    dpkg-deb --build "$PACKAGE_DIR"
    
    if [ -f "${PACKAGE_DIR}.deb" ]; then
        log_success "Package built successfully: ${PACKAGE_DIR}.deb"
        
        # Show package info
        echo -e "\n${CYAN}Package Information:${NC}"
        dpkg-deb --info "${PACKAGE_DIR}.deb"
        
        # Show package contents
        echo -e "\n${CYAN}Package Contents:${NC}"
        dpkg-deb --contents "${PACKAGE_DIR}.deb"
        
        # Cleanup build directory
        rm -rf "$PACKAGE_DIR"
        
        echo -e "\n${GREEN}Debian package ready: ${PACKAGE_DIR}.deb${NC}"
        echo -e "${YELLOW}Install with: sudo dpkg -i ${PACKAGE_DIR}.deb${NC}"
    else
        log_error "Package build failed"
        exit 1
    fi
}

# Main function
main() {
    echo -e "${CYAN}GoCat Debian Package Builder${NC}\n"
    
    # Check if dpkg-deb is available
    if ! command -v dpkg-deb >/dev/null 2>&1; then
        log_error "dpkg-deb not found. Please install dpkg-dev package."
        exit 1
    fi
    
    create_package_structure
    create_control_file
    create_postinst_script
    create_prerm_script
    copy_files
    create_man_page
    build_package
    
    log_success "Debian package build completed!"
}

# Show usage if no arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 <version> [architecture]"
    echo "Example: $0 1.0.0 amd64"
    exit 1
fi

main "$@"
