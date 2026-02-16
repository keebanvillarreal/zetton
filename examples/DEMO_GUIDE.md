# Zetton Demo Guide — Real Commands, Real Binaries

This guide walks you through using Zetton's actual CLI commands against purpose-built
sample binaries. Each binary is designed to showcase specific Zetton capabilities.

---

## Sample Binaries Overview

| Binary | What It Contains | Zetton Commands to Demo |
|--------|-----------------|------------------------|
| `sample_aes_ecb` | AES S-box, SHA-256 constants, hardcoded key, ECB mode, weak PRNG | `analyze`, `crypto`, `forensics` |
| `sample_network_vuln` | recv→sprintf→system taint chain, format string vuln, complex CFG | `analyze`, `cfg`, `dataflow --taint` |
| `sample_pqc` | RSA + ECDSA (vulnerable) alongside Kyber + Dilithium (PQC) | `pqc`, `crypto`, `report` |

---

## Setup

```bash
# Activate your environment
cd ~/zetton-workspace
source zetton-env/bin/activate

# Copy the sample binaries to a working directory
mkdir -p ~/zetton-workspace/samples
cp sample_aes_ecb sample_network_vuln sample_pqc ~/zetton-workspace/samples/
cd ~/zetton-workspace/samples
```

If you want to recompile from source (requires gcc):

```bash
gcc -o sample_aes_ecb sample_aes_ecb.c -no-pie -g
gcc -o sample_network_vuln sample_network_vuln.c -no-pie -g
gcc -o sample_pqc sample_pqc.c -no-pie -g
```

The `-no-pie` flag disables position-independent executable (makes addresses predictable
for demo purposes) and `-g` includes debug symbols.

---

## Demo 1: Binary Analysis

**Target:** `sample_aes_ecb`
**What it shows:** Zetton loading an ELF binary, detecting format, extracting metadata

```bash
zetton analyze ./sample_aes_ecb
```

**What to look for in the output:**
- Format detection: ELF64, x86_64, Little-Endian
- Security features: PIE disabled (we compiled with -no-pie), NX status, etc.
- Section count, symbol count, imports/exports
- File hashes (MD5, SHA-256) for identification

**Try also:**
```bash
# Verbose output
zetton analyze ./sample_aes_ecb --verbose

# JSON output for scripting
zetton analyze ./sample_aes_ecb --output analysis.json
```

---

## Demo 2: Quantum-Assisted Crypto Detection

**Target:** `sample_aes_ecb`
**What it shows:** Finding crypto constants using Grover's O(√N) quantum search

```bash
# Classical crypto detection
zetton crypto ./sample_aes_ecb

# With quantum acceleration enabled
zetton crypto --quantum ./sample_aes_ecb

# Target specific algorithms
zetton crypto --quantum -a aes -a sha256 ./sample_aes_ecb
```

**What to look for in the output:**
- AES S-box detected (full 256-byte table is in the binary)
- SHA-256 initial hash values (H0-H7) detected
- SHA-256 round constants (K) detected
- Hardcoded AES-128 key flagged as a weakness
- Quantum vs classical search comparison metrics

**Why this binary is ideal:** It contains the complete, unmodified AES S-box and SHA-256
constants — exactly what Zetton's pattern-matching quantum circuits are designed to find.

---

## Demo 3: Digital Forensics

**Target:** `sample_aes_ecb`
**What it shows:** Crypto weakness detection, timeline analysis, threat assessment

```bash
# Full forensics analysis
zetton forensics ./sample_aes_ecb

# Generate HTML report
zetton forensics --output report.html ./sample_aes_ecb
```

**What to look for in the output:**
- **Hardcoded key** detected at its offset in the binary
- **ECB mode** usage flagged (the weak_ecb_encrypt function)
- **Weak PRNG** flagged (srand seeded with time())
- **Timeline** from compilation timestamp
- **Quantum threat assessment** for the classical crypto found

---

## Demo 4: Control Flow Graph Analysis

**Target:** `sample_network_vuln`
**What it shows:** Building a CFG, detecting loops, computing complexity

```bash
# Analyze the classify_packet function (has complex branching)
zetton cfg --function classify_packet ./sample_network_vuln

# Export DOT graph for visualization
zetton cfg --function classify_packet --export dot ./sample_network_vuln

# Analyze main
zetton cfg --function main ./sample_network_vuln
```

**What to look for in the output:**
- `classify_packet` has nested if/else, switch/case, and for loops
- High cyclomatic complexity (many branch paths)
- Multiple natural loops detected
- DOT export can be visualized with Graphviz: `dot -Tpng main_cfg.dot -o cfg.png`

**Why this binary is ideal:** The `classify_packet` function was specifically written with
nested conditionals, switch statements, and loops to create an interesting CFG.

---

## Demo 5: Data Flow & Taint Analysis

**Target:** `sample_network_vuln`
**What it shows:** Tracking data from untrusted sources to dangerous sinks

```bash
# Taint analysis with default sources/sinks
zetton dataflow --taint ./sample_network_vuln

# Specify custom taint sources
zetton dataflow --taint --sources recv,getenv,fread ./sample_network_vuln
```

**What to look for in the output:**
- **Vulnerability 1 — Command Injection:**
  `fake_recv()` → `buf` → `memcpy` → `dest` → `sprintf` → `cmd` → `system()`
- **Vulnerability 2 — Format String:**
  `getenv("USER")` → `user` → `sprintf(logmsg, user)` (user as format string)
- **Vulnerability 3 — Buffer Overflow:**
  `fread()` reads 1024 bytes into 32-byte `config` buffer

**Why this binary is ideal:** Each vulnerability follows a clear, traceable taint path
from source to sink — exactly what Zetton's dataflow engine is built to detect.

---

## Demo 6: Post-Quantum Cryptography Analysis

**Target:** `sample_pqc`
**What it shows:** Detecting PQC vs classical crypto, FIPS compliance, migration readiness

```bash
# PQC analysis
zetton pqc ./sample_pqc

# With FIPS compliance checking
zetton pqc --compliance ./sample_pqc
```

**What to look for in the output:**
- **ML-KEM (Kyber)** detected via q=3329, NTT zetas constants
- **ML-DSA (Dilithium)** detected via q=8380417
- **SLH-DSA (SPHINCS+)** — NOT detected (not in binary)
- **RSA-2048** flagged as CRITICAL (vulnerable to Shor's algorithm)
- **ECDSA-P256** flagged as CRITICAL (vulnerable to Shor's)
- **DES** flagged (ancient, deprecated)
- **Migration readiness score:** 2/3 PQC algorithms implemented
- **Recommendation:** Add SLH-DSA, remove RSA/ECDSA

---

## Demo 7: QAOA Constraint Solver

**Target:** Constraint file (not a binary)
**What it shows:** Quantum optimization for path constraint solving

First, create a sample constraint file:

```bash
cat > path_constraints.json << 'CONSTRAINTS'
{
  "variables": 8,
  "clauses": [
    {"vars": [1, 2], "negated": [false, true]},
    {"vars": [2, 3], "negated": [true, false]},
    {"vars": [1, 3, 4], "negated": [false, false, true]},
    {"vars": [4, 5], "negated": [false, false]},
    {"vars": [5, 6], "negated": [true, true]},
    {"vars": [3, 7], "negated": [false, true]},
    {"vars": [6, 7, 8], "negated": [true, false, false]},
    {"vars": [1, 8], "negated": [false, true]}
  ],
  "description": "Path constraints from symbolic execution of classify_packet"
}
CONSTRAINTS
```

```bash
# Solve with QAOA
zetton qaoa --mode sat --constraints path_constraints.json

# With more QAOA layers for better approximation
zetton qaoa --mode sat --constraints path_constraints.json --layers 5
```

---

## Demo 8: Full Report Generation

**Target:** Any/all sample binaries
**What it shows:** Unified report combining all analysis modules

```bash
# Generate comprehensive HTML report
zetton report --format html --all ./sample_aes_ecb

# JSON for programmatic use
zetton report --format json ./sample_pqc

# Compare: run on each binary
zetton report --format html ./sample_aes_ecb -o report_crypto.html
zetton report --format html ./sample_network_vuln -o report_vuln.html
zetton report --format html ./sample_pqc -o report_pqc.html
```

---

## Quick Demo Script

Run all demos back-to-back for a presentation:

```bash
#!/bin/bash
# zetton_demo.sh — Run all Zetton demos sequentially

echo "=========================================="
echo "  ZETTON — Live Demo"
echo "  Quantum Software Reverse Engineering"
echo "=========================================="
echo ""

echo "[1/6] Binary Analysis"
echo "---"
zetton analyze ./sample_aes_ecb
echo ""
read -p "Press Enter to continue..."

echo "[2/6] Quantum Crypto Detection"
echo "---"
zetton crypto --quantum ./sample_aes_ecb
echo ""
read -p "Press Enter to continue..."

echo "[3/6] Digital Forensics"
echo "---"
zetton forensics ./sample_aes_ecb
echo ""
read -p "Press Enter to continue..."

echo "[4/6] Control Flow Analysis"
echo "---"
zetton cfg --function classify_packet ./sample_network_vuln
echo ""
read -p "Press Enter to continue..."

echo "[5/6] Taint Analysis"
echo "---"
zetton dataflow --taint ./sample_network_vuln
echo ""
read -p "Press Enter to continue..."

echo "[6/6] PQC Analysis"
echo "---"
zetton pqc --compliance ./sample_pqc
echo ""

echo "=========================================="
echo "  Demo complete!"
echo "=========================================="
```

Make it executable: `chmod +x zetton_demo.sh`

---

## Compiling for Other Architectures

If you want to test Zetton's multi-architecture support:

```bash
# ARM (requires: apt install gcc-aarch64-linux-gnu)
aarch64-linux-gnu-gcc -o sample_aes_ecb_arm sample_aes_ecb.c -static

# 32-bit x86 (requires: apt install gcc-multilib)
gcc -m32 -o sample_aes_ecb_32 sample_aes_ecb.c -no-pie

# Windows PE (requires: apt install mingw-w64)
x86_64-w64-mingw32-gcc -o sample_aes_ecb.exe sample_aes_ecb.c
```

---

## What Each Binary Exercises

```
sample_aes_ecb
├── loaders/elf.py          (ELF parsing)
├── crypto/identify.py      (AES S-box, SHA-256 detection)
├── crypto/constants.py     (crypto constant database matching)
├── quantum/grover.py       (quantum-accelerated pattern search)
├── quantum/circuits.py     (byte comparator circuits)
├── forensics/crypto.py     (weakness detection: hardcoded key, ECB, weak PRNG)
├── forensics/timeline.py   (compilation timestamp extraction)
└── forensics/report.py     (HTML report generation)

sample_network_vuln
├── loaders/elf.py          (ELF parsing)
├── analyzers/disasm.py     (disassembly of functions)
├── analyzers/cfg.py        (control flow graph building)
├── analyzers/dataflow.py   (taint tracking: source → sink)
└── core/binary.py          (section/symbol extraction)

sample_pqc
├── loaders/elf.py          (ELF parsing)
├── crypto/pqc.py           (ML-KEM/ML-DSA/SLH-DSA detection)
├── crypto/identify.py      (RSA/ECDSA/DES detection)
├── forensics/crypto.py     (quantum threat assessment)
└── forensics/report.py     (migration readiness report)
```

---

*UTSA Cyber Jedis Quantum Cybersecurity Team*
*Zetton v0.1.0-alpha*
