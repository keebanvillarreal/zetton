/*
 * sample_network_vuln.c
 * Zetton Demo Target: Network service with taint-trackable vulnerabilities
 * Contains: recv() -> sprintf() -> system() taint chain
 * 
 * Compile: gcc -o sample_network_vuln sample_network_vuln.c -no-pie
 * Purpose: Demonstrates zetton dataflow --taint
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Simulated network receive */
int fake_recv(char *buf, int maxlen) {
    /* In real code this would be recv() from a socket */
    const char *simulated = "user_controlled_data";
    strncpy(buf, simulated, maxlen);
    return strlen(buf);
}

/* 
 * VULNERABILITY CHAIN:
 * fake_recv (source) -> buf -> dest -> cmd -> system (sink)
 * This is exactly what Zetton's taint analysis should trace
 */
void handle_request() {
    char buf[256];
    char dest[256]; 
    char cmd[512];
    
    /* TAINT SOURCE: network input */
    int n = fake_recv(buf, sizeof(buf));
    
    /* Taint propagation via memcpy */
    memcpy(dest, buf, n);
    
    /* Taint propagation via sprintf */
    sprintf(cmd, "process --input=%s --mode=fast", dest);
    
    /* TAINT SINK: command injection */
    system(cmd);
}

/* Another taint chain: getenv -> printf (format string) */
void log_environment() {
    char *user = getenv("USER");       /* TAINT SOURCE */
    char logmsg[256];
    sprintf(logmsg, user);             /* FORMAT STRING VULN - user as format */
    printf("%s\n", logmsg);
}

/* Buffer overflow via read */
void read_config() {
    char config[32];
    FILE *f = fopen("/tmp/zetton_config", "r");
    if (f) {
        /* VULNERABILITY: reads up to 1024 bytes into 32-byte buffer */
        fread(config, 1, 1024, f);
        fclose(f);
    }
}

/* Function with complex control flow for CFG analysis */
int classify_packet(unsigned char *pkt, int len) {
    if (len < 4) return -1;
    
    int type = pkt[0];
    int flags = pkt[1];
    int payload_len = (pkt[2] << 8) | pkt[3];
    
    if (type == 0x01) {
        if (flags & 0x80) {
            for (int i = 4; i < len && i < payload_len + 4; i++) {
                if (pkt[i] == 0xFF) {
                    return 100;
                }
                if (pkt[i] == 0x00) {
                    continue;
                }
                pkt[i] ^= 0xAA;
            }
            return 1;
        } else {
            return 2;
        }
    } else if (type == 0x02) {
        switch (flags & 0x0F) {
            case 0: return 10;
            case 1: return 11;
            case 2: return 12;
            case 3:
                for (int j = 0; j < payload_len; j++) {
                    if (pkt[4+j] > 127) return 13;
                }
                return 14;
            default: return 15;
        }
    } else if (type == 0x03) {
        return (flags > 0) ? 20 : 21;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== Zetton Demo Target: Network Vulnerability Binary ===\n");
    printf("This binary contains taint-trackable vulnerability chains.\n\n");
    
    handle_request();
    log_environment();
    
    unsigned char test_pkt[] = {0x01, 0x80, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00, 0x11, 0x22};
    int result = classify_packet(test_pkt, sizeof(test_pkt));
    printf("Packet classification: %d\n", result);
    
    return 0;
}
