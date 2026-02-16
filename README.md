![ZETTON logo](zetton/assets/zetton_namelogowht.png)
# Zetton 
> **⚠ Active Development**: Zetton is in active alpha development. Core analysis commands are functional with real output. See the [Roadmap](#roadmap) for current status.

## Quantum Software Reverse Engineering Framework

A next-generation reverse engineering framework that combines classical binary analysis with quantum computing algorithms. Zetton bridges the gap between traditional tools like Ghidra and the emerging capabilities of quantum computers for enhanced cryptanalysis and pattern detection.

**🔗 [Live Interactive Demo](https://keebanvillarreal.github.io/zetton/)**

---

## Features

### Binary Analysis
- ELF/PE/Mach-O format detection and parsing via LIEF
- Section enumeration with entropy analysis (flags packed/encrypted data)
- Symbol, import, and export extraction
- Security feature detection (PIE, NX, RELRO, Canary, FORTIFY)
- File hashing (MD5, SHA-1, SHA-256)

### Cryptographic Detection
- Pattern matching against 15+ cryptographic algorithm signatures
- AES S-box, SHA-256, SHA-512, MD5, DES, Blowfish, ChaCha20, RSA, ECDSA detection
- Both big-endian and little-endian constant matching
- Quantum-assisted search metrics (Grover's O(√N) speedup calculation)

### Digital Forensics
- Embedded timestamp extraction and timeline analysis
- Hardcoded key detection (null keys, known test vectors)
- ECB mode and weak PRNG identification
- Dangerous function flagging (command injection, buffer overflow sinks)
- Quantum threat assessment per detected algorithm

### Control Flow Analysis
- Capstone-powered disassembly (x86, x64, ARM, AARCH64, MIPS, RISC-V)
- Basic block construction and CFG edge detection
- Loop detection via back-edge analysis
- Cyclomatic complexity calculation
- DOT graph export for visualization

### Data Flow & Taint Analysis
- Taint source detection (network, file, environment, stdin)
- Taint sink identification with severity ratings
- Source-to-sink flow tracing via disassembly
- Cross-function taint propagation detection

### Post-Quantum Cryptography Analysis
- Classical vs post-quantum algorithm classification
- NIST FIPS 203 (ML-KEM/Kyber) detection
- NIST FIPS 204 (ML-DSA/Dilithium) detection
- NIST FIPS 205 (SLH-DSA/SPHINCS+) detection
- Migration readiness scoring (Grade A-D)
- Actionable replacement recommendations

### Quantum Engine
- Qiskit-based circuit construction
- Local simulation via Aer backend
- Hardware backend support (IBM Quantum, AWS Braket)
- 🚧 Hybrid classical-quantum algorithm orchestration (in progress)

---

## Installation

### Prerequisites
Ensure you have Python 3.9+ and required system packages:
```bash
# On Kali Linux / Debian / Ubuntu
sudo apt update
sudo apt install -y python3 python3-pip python3-venv build-essential git
```

### Step-by-Step Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/keebanvillarreal/zetton.git
cd zetton
```

#### 2. Create Virtual Environment
**⚠ Important**: On Kali Linux and modern Debian-based systems, you **must** use a virtual environment to avoid the "externally-managed-environment" error.
```bash
# Create virtual environment
python3 -m venv zetton-env

# Activate it
source zetton-env/bin/activate
```
Your prompt should now show `(zetton-env)` indicating the environment is active.

#### 3. Install Zetton
```bash
# Upgrade pip first
pip install --upgrade pip setuptools wheel

# Install Zetton in development mode
pip install -e .

# Or install with all optional features (recommended)
pip install -e ".[all]"
```

#### 4. Verify Installation
```bash
# Check version
zetton --version

# View the banner and available commands
zetton

# Check system status
zetton status
```
You should see output confirming Zetton v0.1.0 is installed.

---

## Getting Started

### Daily Usage
Every time you want to use Zetton, activate the virtual environment:
```bash
cd ~/zetton
source zetton-env/bin/activate
```
When you're done:
```bash
deactivate
```

### First Steps
Try these commands to explore Zetton:
```bash
# 1. See the banner and command list
zetton

# 2. View system status and feature readiness
zetton status

# 3. Analyze a binary
zetton analyze /usr/bin/ls

# 4. Scan for crypto
zetton crypto /usr/bin/ls
```

---

## Command Line Interface

### Analysis Commands
```bash
# Full binary analysis (format, sections, security features, hashes)
zetton analyze ./binary
zetton analyze ./binary -v              # Verbose (imports/exports)
zetton analyze ./binary -o report.json  # JSON export

# Cryptographic algorithm detection
zetton crypto ./binary
zetton crypto ./binary --quantum        # Show Grover's speedup metrics
zetton crypto ./binary -a aes -a sha256 # Filter by algorithm

# Digital forensics (weaknesses, timestamps, quantum threat)
zetton forensics ./binary
zetton forensics ./binary -v -o report.json

# Control flow graph analysis
zetton cfg ./binary                              # All functions
zetton cfg ./binary --function main              # Specific function
zetton cfg ./binary -f main --export dot -o cfg.dot  # DOT export

# Data flow and taint tracking
zetton dataflow --taint ./binary
zetton dataflow --taint --sources recv,getenv ./binary
zetton dataflow --taint --sinks system,strcpy ./binary

# Post-quantum crypto compliance
zetton pqc ./binary
zetton pqc ./binary --compliance        # NIST FIPS 203/204/205 check
```

### Utility Commands
```bash
# Display banner and command list
zetton

# Feature status dashboard
zetton status

# Configuration management
zetton config --list
zetton config --key ibm-token --value YOUR_TOKEN

# Quantum backends
zetton quantum list-backends
zetton quantum test-backend
```

---

## Demo

Zetton ships with three purpose-built sample binaries in `examples/samples/` designed to showcase all analysis capabilities:

| Sample | Purpose | Highlights |
|--------|---------|------------|
| `sample_aes_ecb` | Crypto weakness demo | AES S-box, SHA-256, hardcoded key, ECB mode, weak PRNG |
| `sample_network_vuln` | Taint/CFG demo | Complex control flow, taint chains, dangerous functions |
| `sample_pqc` | PQC migration demo | RSA, ECDSA, DES + Kyber, Dilithium, SPHINCS+ |

### Build the Samples
```bash
cd ~/zetton/examples/samples
gcc -o sample_aes_ecb sample_aes_ecb.c -g
gcc -o sample_network_vuln sample_network_vuln.c -g
gcc -o sample_pqc sample_pqc.c -g
```

### Run the Full Demo
```bash
~/zetton/examples/zetton_demo.sh
```

### Try Individual Commands
```bash
# Detect crypto in a binary with AES and SHA-256
zetton crypto ~/zetton/examples/samples/sample_aes_ecb

# Analyze control flow of a complex function
zetton cfg ~/zetton/examples/samples/sample_network_vuln -f classify_packet

# Check quantum readiness with FIPS compliance
zetton pqc --compliance ~/zetton/examples/samples/sample_pqc
```

---

## Architecture
```
zetton/
├── analyzers/        # Analysis engines
│   ├── disasm.py     # Capstone disassembly engine ✅
│   ├── cfg.py        # Control flow analysis ✅
│   └── dataflow.py   # Data flow / taint analysis ✅
├── core/             # Core framework
│   ├── binary.py     # Binary representation (LIEF) ✅
│   ├── project.py    # Project management
│   └── config.py     # Configuration handling ✅
├── crypto/           # Cryptanalysis tools
│   ├── identify.py   # Algorithm identification ✅
│   └── constants.py  # Crypto constants database (15+ algos) ✅
├── forensics/        # Digital forensics
│   ├── crypto.py     # Cryptographic analysis
│   ├── timeline.py   # Event reconstruction
│   └── report.py     # Report generation
├── loaders/          # Binary format parsers
│   ├── pe.py         # PE/COFF loader ✅
│   └── macho.py      # Mach-O loader ✅
├── quantum/          # Quantum computing
│   ├── engine.py     # Quantum execution engine 🚧
│   ├── circuits.py   # Pre-built circuits 🚧
│   ├── grover.py     # Grover's algorithm 🚧
│   └── qaoa.py       # QAOA optimization 🚧
├── cli.py            # Command-line interface (6 commands) ✅
└── __init__.py       # Package initialization ✅
```

---

## Quantum Algorithms

| Algorithm | Application | Theoretical Speedup |
|-----------|-------------|---------------------|
| Grover's Search | Pattern matching, constant finding | O(√N) |
| Quantum Counting | Solution estimation | O(√N) |
| QAOA | SAT solving, constraint optimization | Problem-dependent |
| VQE | Ground state problems | Exponential (certain cases) |
| Quantum Walks | Graph traversal in CFG | O(√N) |

### Quantum Backend Modes

1. **Simulation Mode** (Default): Local quantum simulation using Qiskit Aer. Best for development and testing.
2. **Hybrid Mode**: Classical preprocessing with quantum acceleration for specific subtasks. Optimal balance of practicality and capability.
3. **Hardware Mode**: Real quantum hardware via IBM Quantum or AWS Braket. For problems beyond classical simulation capacity.

---

## Roadmap

### ✅ Completed
- [x] Project structure and packaging (pyproject.toml, setup.py)
- [x] Command-line interface with Click (6 analysis commands)
- [x] Rich terminal output formatting with ASCII banner
- [x] Binary format loading (ELF, PE, Mach-O) via LIEF
- [x] Section analysis with entropy calculation
- [x] Security feature detection (PIE, NX, RELRO, Canary, FORTIFY)
- [x] Cryptographic constant database (15+ algorithms, both endiannesses)
- [x] Crypto pattern scanning with algorithm identification
- [x] Digital forensics (timestamps, weakness detection, quantum threat assessment)
- [x] Capstone disassembly integration
- [x] Control flow graph construction with basic blocks and edge detection
- [x] Loop detection and cyclomatic complexity calculation
- [x] DOT graph export for CFG visualization
- [x] Taint source/sink detection with severity classification
- [x] Source-to-sink taint flow tracing
- [x] Post-quantum crypto analysis (ML-KEM, ML-DSA, SLH-DSA detection)
- [x] NIST FIPS 203/204/205 compliance checking
- [x] Migration readiness scoring
- [x] Configuration management framework
- [x] Quantum backend listing
- [x] Purpose-built demo binaries and demo script
- [x] Interactive web demo (GitHub Pages)

### 🚧 In Progress
- [ ] Quantum engine implementation (Grover's search on binary data)
- [ ] QAOA constraint solver for path analysis
- [ ] Quantum-classical hybrid orchestration

### 📋 Planned
- [ ] Unified report generation (HTML/JSON/text)
- [ ] Integration with radare2, YARA, Volatility
- [ ] GUI interface
- [ ] Ghidra interoperability
- [ ] PyPI publication

---

## Troubleshooting

### Common Issues

**Error: "externally-managed-environment"**
```
Solution: Always use a virtual environment on Kali/Debian systems
→ python3 -m venv zetton-env && source zetton-env/bin/activate
```

**Error: "No module named 'zetton.cli'"**
```
Solution: Make sure the zetton package directory has cli.py and __init__.py
→ ls zetton/cli.py zetton/__init__.py
```

**Error: "command not found: zetton"**
```
Solution: Reinstall after activating virtual environment
→ source zetton-env/bin/activate
→ pip install -e . --force-reinstall
```

**Module import errors (rich, click, qiskit)**
```
Solution: These should auto-install, but if not:
→ pip install click rich qiskit qiskit-aer
```

**LIEF RuntimeWarning about segment types**
```
This is a known LIEF 0.17 compatibility issue and is suppressed automatically.
It does not affect analysis results.
```

### Getting Help
- **Issues**: Report bugs at [GitHub Issues](https://github.com/keebanvillarreal/zetton/issues)
- **Email**: keeban.villarreal@my.utsa.edu
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Research Applications

Zetton is designed for security researchers working on:

- **Malware Analysis**: Quantum-accelerated pattern matching for signature detection
- **Vulnerability Research**: Constraint solving for path exploration
- **Cryptographic Auditing**: Implementation weakness detection
- **Post-Quantum Security**: PQC algorithm verification and FIPS compliance analysis
- **Digital Forensics**: Evidence extraction and timeline reconstruction

---

## License

MIT License - see [LICENSE](LICENSE) for details.

This project is open source and welcomes contributions under the MIT license.

---

## Acknowledgments

- **Ghidra Team** (NSA) - For pioneering open-source reverse engineering tools
- **Qiskit Team** (IBM) - For the quantum computing framework
- **Capstone Team** - For the disassembly engine
- **LIEF Project** - For cross-platform binary parsing
- **UTSA Cyber Jedis** - For quantum cybersecurity research
- **Quantum & Security Communities** - For ongoing support and collaboration

---

## About

**Zetton** is developed by the **UTSA Cyber Jedis Quantum Cybersecurity Research Interest Group (RIG)**, a group of researchers exploring the intersection of quantum computing and digital security.

**Contact**: keeban.villarreal@my.utsa.edu  
**Repository**: https://github.com/keebanvillarreal/zetton

---

*"Even Ultraman couldn't defeat Zetton alone."*
