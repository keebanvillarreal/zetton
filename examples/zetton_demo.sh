#!/bin/bash
# zetton_demo.sh — Run all Zetton demos sequentially
# Usage: cd ~/zetton/examples/samples && chmod +x ../zetton_demo.sh && ../zetton_demo.sh

GOLD='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
RED='\033[0;31m'
NC='\033[0m'

SAMPLES="$HOME/zetton/examples/samples"

echo -e "${GOLD}"
echo "  ╔════════════════════════════╗"
echo "  ║              ZETTON — Live Demo                  ║"
echo "  ║                                                  ║"
echo "  ║    UTSA Cyber Jedis Quantum Cybersecurity RIG    ║"
echo "  ╚════════════════════════════╝"
echo -e "${NC}"
echo ""

# Demo 1
echo -e "${CYAN}━━━ [1/8] Binary Analysis ━━━${NC}"
echo -e "${PURPLE}$ zetton analyze ${SAMPLES}/sample_aes_ecb${NC}"
echo ""
zetton analyze ${SAMPLES}/sample_aes_ecb
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 2
echo -e "${CYAN}━━━ [2/8] Quantum Crypto Detection ━━━${NC}"
echo -e "${PURPLE}$ zetton crypto --quantum ${SAMPLES}/sample_aes_ecb${NC}"
echo ""
zetton crypto --quantum ${SAMPLES}/sample_aes_ecb
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 3
echo -e "${CYAN}━━━ [3/8] Digital Forensics ━━━${NC}"
echo -e "${PURPLE}$ zetton forensics ${SAMPLES}/sample_aes_ecb${NC}"
echo ""
zetton forensics ${SAMPLES}/sample_aes_ecb
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 4
echo -e "${CYAN}━━━ [4/8] Control Flow Analysis ━━━${NC}"
echo -e "${PURPLE}$ zetton cfg --function classify_packet ${SAMPLES}/sample_network_vuln${NC}"
echo ""
zetton cfg --function classify_packet ${SAMPLES}/sample_network_vuln
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 5
echo -e "${CYAN}━━━ [5/8] Taint Analysis ━━━${NC}"
echo -e "${PURPLE}$ zetton dataflow --taint ${SAMPLES}/sample_network_vuln${NC}"
echo ""
zetton dataflow --taint ${SAMPLES}/sample_network_vuln
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 6
echo -e "${CYAN}━━━ [6/8] Post-Quantum Crypto Analysis ━━━${NC}"
echo -e "${PURPLE}$ zetton pqc --compliance ${SAMPLES}/sample_pqc${NC}"
echo ""
zetton pqc --compliance ${SAMPLES}/sample_pqc
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 7
echo -e "${CYAN}━━━ [7/8] Multi-Binary Comparison ━━━${NC}"
echo -e "${PURPLE}Scanning all three samples for crypto...${NC}"
echo ""
echo -e "${GREEN}── sample_aes_ecb ──${NC}"
zetton crypto ${SAMPLES}/sample_aes_ecb
echo ""
echo -e "${GREEN}── sample_network_vuln ──${NC}"
zetton crypto ${SAMPLES}/sample_network_vuln
echo ""
echo -e "${GREEN}── sample_pqc ──${NC}"
zetton crypto ${SAMPLES}/sample_pqc
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 8
echo -e "${CYAN}━━━ [8/8] Feature Status ━━━${NC}"
echo -e "${PURPLE}$ zetton status${NC}"
echo ""
zetton status
echo ""

echo -e "${GOLD}"
echo "  ╔════════════════════════════╗"
echo "  ║       Demo Complete!       ║"
echo "  ╚════════════════════════════╝"
echo -e "${NC}"
