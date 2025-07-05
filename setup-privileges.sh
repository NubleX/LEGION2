#!/bin/bash
# setup-privileges.sh - Setup privilege elevation for LEGION2

echo "LEGION2 Privilege Setup Script"
echo "=============================="

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "This script is for Linux systems only."
    exit 1
fi

# Create polkit policy for LEGION2
POLICY_FILE="/usr/share/polkit-1/actions/com.nublex.legion2.policy"

# Check if we need sudo
if [ "$EUID" -ne 0 ]; then 
    echo "This script needs to run with sudo privileges to install the polkit policy."
    echo "Please run: sudo $0"
    exit 1
fi

echo "Creating polkit policy for LEGION2..."

cat > "$POLICY_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <vendor>LEGION2</vendor>
  <vendor_url>https://github.com/nublex/legion2</vendor_url>

  <action id="com.nublex.legion2.pkexec.nmap">
    <description>Run nmap as root for LEGION2</description>
    <message>Authentication is required to run network scans with nmap</message>
    <icon_name>network-wired</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/bin/nmap</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>

  <action id="com.nublex.legion2.pkexec.masscan">
    <description>Run masscan as root for LEGION2</description>
    <message>Authentication is required to run network scans with masscan</message>
    <icon_name>network-wired</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/bin/masscan</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
EOF

echo "Polkit policy created at: $POLICY_FILE"

# Create wrapper scripts
echo "Creating wrapper scripts..."

WRAPPER_DIR="/usr/local/bin"

# Nmap wrapper
cat > "$WRAPPER_DIR/legion2-nmap" << 'EOF'
#!/bin/bash
pkexec /usr/bin/nmap "$@"
EOF

# Masscan wrapper
cat > "$WRAPPER_DIR/legion2-masscan" << 'EOF'
#!/bin/bash
pkexec /usr/bin/masscan "$@"
EOF

chmod +x "$WRAPPER_DIR/legion2-nmap"
chmod +x "$WRAPPER_DIR/legion2-masscan"

echo "Wrapper scripts created:"
echo "  - $WRAPPER_DIR/legion2-nmap"
echo "  - $WRAPPER_DIR/legion2-masscan"

# Update the Rust code to use wrappers
echo ""
echo "Now update your Rust code to use the wrapper commands:"
echo "  - Change 'nmap' to 'legion2-nmap'"
echo "  - Change 'masscan' to 'legion2-masscan'"
echo ""
echo "Or alternatively, use pkexec directly in your Rust code."

# Check if tools are installed
echo ""
echo "Checking required tools..."

if command -v nmap &> /dev/null; then
    echo "✓ nmap is installed"
else
    echo "✗ nmap is NOT installed. Install with: sudo apt install nmap"
fi

if command -v masscan &> /dev/null; then
    echo "✓ masscan is installed"
else
    echo "✗ masscan is NOT installed. Install with: sudo apt install masscan"
fi

echo ""
echo "Setup complete! LEGION2 will now prompt for authentication when running scans."