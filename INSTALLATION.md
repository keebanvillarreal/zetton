# Zetton Installation Guide

Complete installation and setup guide for the Zetton Quantum-Assisted Binary Analysis Framework.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Detailed Installation Steps](#detailed-installation-steps)
4. [Platform-Specific Instructions](#platform-specific-instructions)
5. [Quantum Backend Configuration](#quantum-backend-configuration)
6. [Verification and Testing](#verification-and-testing)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Installation Options](#advanced-installation-options)
9. [Uninstallation](#uninstallation)
10. [Getting Help](#getting-help)

---

## System Requirements

### Operating System
- **Recommended**: Kali Linux 2023.3+, Ubuntu 20.04+, Debian 11+
- **Supported**: Any modern Linux distribution
- **Note**: macOS and Windows support via WSL2

### Python
- **Required**: Python 3.9 or higher
- **Recommended**: Python 3.10 or 3.11
- Check your version: `python3 --version`

### Hardware
- **CPU**: Modern multi-core processor (quantum simulation benefits from more cores)
- **RAM**: Minimum 4GB, recommended 8GB+ (16GB for large-scale quantum simulations)
- **Disk Space**: ~2GB for Zetton and all dependencies
- **Network**: Required for downloading dependencies and accessing cloud quantum backends

### Dependencies
System packages required:
- `python3` - Python interpreter
- `python3-pip` - Python package manager
- `python3-venv` - Virtual environment support
- `build-essential` - C/C++ compilation tools
- `git` - Version control

---

## Quick Installation

For experienced users who just want to get started:

```bash
# Install system dependencies
sudo apt update && sudo apt install -y python3 python3-pip python3-venv build-essential git

# Clone repository
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton

# Create and activate virtual environment
python3 -m venv zetton-env
source zetton-env/bin/activate

# Install Zetton
pip install --upgrade pip setuptools wheel
pip install -e ".[all]"

# Verify installation
zetton --version
zetton status
```

**Done!** Skip to [Verification and Testing](#verification-and-testing) to confirm everything works.

---

## Detailed Installation Steps

### Step 1: Install System Dependencies

#### On Kali Linux / Debian / Ubuntu

```bash
# Update package list
sudo apt update

# Install required packages
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    git \
    libffi-dev \
    libssl-dev \
    python3-dev
```

#### On Fedora / RHEL / CentOS

```bash
sudo dnf install -y \
    python3 \
    python3-pip \
    python3-virtualenv \
    gcc \
    gcc-c++ \
    make \
    git \
    libffi-devel \
    openssl-devel \
    python3-devel
```

#### On Arch Linux

```bash
sudo pacman -S \
    python \
    python-pip \
    base-devel \
    git
```

### Step 2: Clone the Repository

```bash
# Navigate to where you want to install Zetton
cd ~

# Clone from GitHub
git clone https://github.com/keebanvillarreal/zetton.git

# Enter the directory
cd zetton
```

**Alternative**: Download as ZIP from GitHub and extract:
```bash
wget https://github.com/keebanvillarreal/zetton/archive/refs/heads/main.zip
unzip main.zip
cd zetton-main
```

### Step 3: Create Virtual Environment

**⚠️ CRITICAL**: Modern Debian-based systems (Kali, Ubuntu 23.04+, Debian 12+) require virtual environments due to PEP 668.

```bash
# Create virtual environment named 'zetton-env'
python3 -m venv zetton-env
```

This creates a new directory `zetton-env/` containing an isolated Python installation.

### Step 4: Activate Virtual Environment

```bash
# Activate the environment
source zetton-env/bin/activate
```

**Success indicators**:
- Your prompt should now show `(zetton-env)` at the beginning
- Running `which python` should show a path inside `zetton-env/`

**Important**: You must activate this environment every time you want to use Zetton in a new terminal session.

### Step 5: Upgrade pip

```bash
# Upgrade pip to the latest version
pip install --upgrade pip setuptools wheel
```

This ensures you have the latest packaging tools for a smooth installation.

### Step 6: Install Zetton

Choose one of the following installation options:

#### Option A: Full Installation (Recommended)

Installs Zetton with all optional features (development tools, forensics, visualization):

```bash
pip install -e ".[all]"
```

#### Option B: Basic Installation

Installs just the core Zetton framework:

```bash
pip install -e .
```

#### Option C: Custom Installation

Install with specific optional dependencies:

```bash
# With development tools only
pip install -e ".[dev]"

# With forensics support
pip install -e ".[forensics]"

# With visualization support
pip install -e ".[visualization]"

# Mix and match
pip install -e ".[dev,forensics]"
```

**What does `-e` mean?**
- `-e` installs in "editable" or "development" mode
- Changes to the code take effect immediately without reinstalling
- Perfect for contributors and active development

### Step 7: Verify Installation

```bash
# Check Zetton version
zetton --version
# Expected output: Zetton version 0.1.0

# View available commands
zetton --help

# Check feature status
zetton status

# List quantum backends
zetton quantum list-backends
```

If all commands work, **congratulations!** Zetton is successfully installed.

---

## Platform-Specific Instructions

### Kali Linux

Kali uses PEP 668 "externally-managed-environment" protection. **You must use a virtual environment.**

```bash
# Standard installation works perfectly
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

**Common Kali Issue**: If you get "command not found: pip" after activation:
```bash
python3 -m pip install --upgrade pip
```

### Ubuntu 24.04 / Debian 12+

Same as Kali - requires virtual environment:

```bash
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

### WSL2 (Windows Subsystem for Linux)

1. Install WSL2 with Ubuntu/Debian
2. Follow the Ubuntu instructions above
3. Access from Windows using: `wsl` command

```bash
# In PowerShell/CMD
wsl

# Then follow Linux installation steps
cd /mnt/c/Users/YourName/
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.9+
brew install python@3.11

# Clone and install Zetton
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

### Docker (Alternative Installation)

If you prefer containerized deployment:

```bash
# Clone repository
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton

# Build Docker image
docker build -t zetton:latest .

# Run Zetton in container
docker run -it --rm zetton:latest zetton status

# Mount workspace for analysis
docker run -it --rm -v $(pwd):/workspace zetton:latest zetton analyze /workspace/binary
```

---

## Quantum Backend Configuration

### Local Simulation (Default)

No configuration needed! Zetton uses Qiskit Aer for local quantum simulation by default.

```bash
# Test local simulator
zetton quantum list-backends
```

You should see `qasm_simulator` and `statevector_simulator` available.

### IBM Quantum

To use real IBM quantum hardware:

1. **Get API Token**:
   - Visit https://quantum.ibm.com/
   - Create an account or log in
   - Go to Account Settings → API Token
   - Copy your token

2. **Configure Zetton**:
   ```bash
   zetton config --key ibm-token --value YOUR_IBM_QUANTUM_TOKEN
   ```

3. **Verify Connection**:
   ```bash
   zetton quantum test-backend --backend ibmq_qasm_simulator
   ```

### AWS Braket

To use Amazon Braket quantum services:

1. **Configure AWS Credentials**:
   ```bash
   # Install AWS CLI if needed
   pip install awscli
   
   # Configure credentials
   aws configure
   # Enter: Access Key ID, Secret Access Key, Region (e.g., us-east-1)
   ```

2. **Set Zetton Region**:
   ```bash
   zetton config --key aws-region --value us-east-1
   ```

3. **Verify**:
   ```bash
   zetton quantum list-backends
   ```

---

## Verification and Testing

### Basic Verification

Run these commands to ensure everything is working:

```bash
# 1. Check version
zetton --version

# 2. View help
zetton --help

# 3. Check status
zetton status

# 4. List backends
zetton quantum list-backends

# 5. View configuration
zetton config --list
```

### Test Python Import

```bash
# Test Python API
python -c "import zetton; print(f'Zetton {zetton.__version__} loaded successfully')"

# Test dependencies
python -c "import qiskit; import click; import rich; print('All dependencies OK')"
```

### Run Sample Commands

```bash
# Try analyzing a system binary (will show "in development" message)
zetton analyze /bin/ls

# This is expected! The command exists but advanced features are still being built.
```

---

## Troubleshooting

### Error: "externally-managed-environment"

**Problem**: Trying to install packages system-wide on Kali/Debian.

**Full Error Message**:
```
error: externally-managed-environment

This environment is externally managed
To install Python packages system-wide, try apt install python3-xyz
```

**Cause**: PEP 668 protection prevents system Python modification.

**Solution**: Always use a virtual environment:
```bash
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

---

### Error: "Could not find a version that satisfies the requirement zetton"

**Problem**: Trying to install Zetton via `pip install zetton` directly.

**Cause**: Zetton is not yet published to PyPI.

**Solution**: Install from source:
```bash
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e .
```

---

### Error: "does not appear to be a Python project"

**Problem**: Missing `pyproject.toml` or `setup.py`.

**Full Error Message**:
```
ERROR: file:///path/to/zetton does not appear to be a Python project: 
neither 'setup.py' nor 'pyproject.toml' found.
```

**Cause**: Invalid directory structure or missing configuration files.

**Solution**:
```bash
# Verify you're in the correct directory
ls -la pyproject.toml setup.py

# If files are missing, re-clone the repository
cd ~
rm -rf zetton
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e .
```

---

### Error: "No module named 'zetton.cli'"

**Problem**: CLI module not found after installation.

**Full Error Message**:
```
Traceback (most recent call last):
  File "/home/kali/zetton/zetton-env/bin/zetton", line 5, in <module>
    from zetton.cli import main
ModuleNotFoundError: No module named 'zetton.cli'
```

**Possible Causes**:
1. Package structure incorrect (nested zetton folders)
2. cli.py or __init__.py missing
3. Installation incomplete

**Solution**:
```bash
# Verify correct structure
ls zetton/cli.py zetton/__init__.py

# Check for nested folders (WRONG structure)
ls zetton/zetton/cli.py  # If this exists, you have a problem

# Fix nested structure if needed
cd ~/zetton
mv zetton/zetton/* zetton/
rm -rf zetton/zetton

# Reinstall
source zetton-env/bin/activate
pip install -e . --force-reinstall
zetton --version
```

---

### Error: "command not found: zetton"

**Problem**: `zetton` command not available in PATH.

**Solution**:
```bash
# 1. Ensure virtual environment is activated
source zetton-env/bin/activate

# 2. Verify installation
pip list | grep zetton

# 3. Reinstall if needed
pip install -e . --force-reinstall

# 4. Check if command exists
which zetton
```

---

### Error: Build failures (gcc, compiler errors)

**Problem**: Missing C/C++ compilation tools.

**Full Error Message**:
```
error: command 'gcc' failed
unable to execute 'gcc': No such file or directory
```

**Solution**:
```bash
# Debian/Ubuntu/Kali
sudo apt install build-essential python3-dev libffi-dev libssl-dev

# Fedora/RHEL
sudo dnf install gcc gcc-c++ python3-devel libffi-devel openssl-devel

# Then retry installation
pip install -e ".[all]"
```

---

### Error: "ModuleNotFoundError" for dependencies

**Problem**: Required packages not installed.

**Solution**:
```bash
# Reinstall with all dependencies
pip install -e ".[all]" --force-reinstall

# Or install specific missing packages
pip install click rich qiskit qiskit-aer
```

---

### Virtual Environment Not Activating

**Problem**: `source zetton-env/bin/activate` doesn't work.

**Solution**:
```bash
# Check if venv exists
ls -la zetton-env/

# If not, create it
python3 -m venv zetton-env

# Try alternative activation
. zetton-env/bin/activate

# For fish shell
source zetton-env/bin/activate.fish

# For csh/tcsh
source zetton-env/bin/activate.csh
```

---

### Permission Errors

**Problem**: Permission denied errors during installation.

**Solution**:
```bash
# DO NOT use sudo with pip in virtual environment

# If you see permission errors:
# 1. Make sure you're in virtual environment
source zetton-env/bin/activate

# 2. Check ownership
ls -la zetton-env/

# 3. Fix if needed
sudo chown -R $USER:$USER zetton-env/

# 4. Reinstall
pip install -e ".[all]"
```

---

### Quantum Backend Connection Errors

**Problem**: Cannot connect to IBM Quantum or AWS Braket.

**Solution**:

For IBM Quantum:
```bash
# 1. Verify token is set
zetton config --key ibm-token

# 2. Test with local simulator first
zetton quantum test-backend --backend qasm_simulator

# 3. Check IBM Quantum status: https://quantum.ibm.com/
```

For AWS Braket:
```bash
# 1. Verify AWS credentials
aws sts get-caller-identity

# 2. Check region
zetton config --key aws-region

# 3. Verify Braket access in AWS Console
```

---

## Advanced Installation Options

### Installing from Specific Branch

```bash
# Clone specific branch
git clone -b develop https://github.com/keebanvillarreal/zetton.git

# Or switch branches after cloning
git checkout develop

# Then install
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

### Installing Specific Version

```bash
# Install from specific commit
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton
git checkout <commit-hash>
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

### Development Installation with Pre-commit Hooks

For contributors:

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Hooks will now run automatically on commit
```

### Installing in System Python (Not Recommended)

**Only do this if you know what you're doing:**

```bash
# Override PEP 668 (NOT RECOMMENDED)
pip install -e ".[all]" --break-system-packages

# Better: use pipx for isolated app installation
sudo apt install pipx
pipx install -e .
```

---

## Uninstallation

### Remove Zetton

```bash
# Activate environment
source zetton-env/bin/activate

# Uninstall
pip uninstall zetton

# Deactivate environment
deactivate
```

### Remove Everything

```bash
# Remove repository and virtual environment
cd ~
rm -rf zetton/

# Remove configuration (if any)
rm -rf ~/.zetton/
```

### Clean Reinstall

```bash
# Remove and reinstall
cd ~/zetton
rm -rf zetton-env/
python3 -m venv zetton-env
source zetton-env/bin/activate
pip install -e ".[all]"
```

---

## Getting Help

### Documentation
- **Main README**: [README.md](README.md)
- **Contributing Guide**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **This Installation Guide**: [INSTALLATION.md](INSTALLATION.md)

### Support Channels
- **GitHub Issues**: [Report bugs or request features](https://github.com/keebanvillarreal/zetton/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/keebanvillarreal/zetton/discussions)
- **Email**: keeban.villarreal@my.utsa.edu

### Before Asking for Help

Please include:
1. Your operating system and version (`uname -a`)
2. Python version (`python3 --version`)
3. Pip version (`pip --version`)
4. Installation method used
5. Complete error message
6. Steps you've already tried

### Common Questions

**Q: Can I install Zetton without virtual environment?**  
A: Not recommended on modern Debian-based systems. Use `pipx` as alternative.

**Q: Which Python version should I use?**  
A: Python 3.10 or 3.11 recommended. 3.9+ required.

**Q: Do I need quantum hardware?**  
A: No! Zetton works perfectly with local quantum simulation via Qiskit Aer.

**Q: Can I use Zetton on Windows?**  
A: Yes, via WSL2 (Windows Subsystem for Linux). Native Windows support planned.

**Q: How much disk space does Zetton need?**  
A: About 2GB including all dependencies.

---

## Next Steps

After successful installation:

1. **Read the README**: [README.md](README.md)
2. **Try the CLI**: `zetton status`, `zetton --help`
3. **Configure backends**: Set up IBM Quantum or AWS Braket
4. **Join the community**: Check out [CONTRIBUTING.md](CONTRIBUTING.md)
5. **Start contributing**: Pick an issue from GitHub

---

## Installation Checklist

Use this checklist to track your progress:

- [ ] System dependencies installed
- [ ] Repository cloned
- [ ] Virtual environment created
- [ ] Virtual environment activated
- [ ] Pip upgraded
- [ ] Zetton installed
- [ ] Installation verified with `zetton --version`
- [ ] Status checked with `zetton status`
- [ ] Quantum backends listed
- [ ] (Optional) IBM Quantum configured
- [ ] (Optional) AWS Braket configured

---

**Installation complete!** 

You're now ready to explore Zetton's quantum-assisted binary analysis capabilities.

---

*Last updated: February 2026*  
*UTSA Cyber Jedis Quantum Cybersecurity RIG*
