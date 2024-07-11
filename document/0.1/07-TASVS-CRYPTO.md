# TASVS-CRYPTO: Cryptography

## Control Objective



## Testing Checklist

| TASVS-ID         | Description                                                                                                                                       | L1 | L2 | L3 |
| ---- | ------------- | - | - | - |
| TASVS-CRYPTO-1   | Communication                                                                                                                                     |    |    |    |
| TASVS-CRYPTO-1.1 | The TLS settings are in line with current best practices,                                                                                         | X  | X  | X  |
| TASVS-CRYPTO-2   | Storage                                                                                                                                           |    |    |    |
| TASVS-CRYPTO-2.1 | The thick client doesn't re-use the same cryptographic key for multiple purposes.                                                                 | X  | X  | X  |
| TASVS-CRYPTO-2.2 | All random values are generated using a sufficiently secure random number generator.                                                              | X  | X  | X  |
| TASVS-CRYPTO-2.3 | The thick client does not use cryptographic protocols or algorithms that are widely considered deprecated for security purposes.                  | X  | X  | X  |
| TASVS-CRYPTO-2.4 | The thick client does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.                                      | X  | X  | X  |
| TASVS-CRYPTO-3   | General                                                                                                                                           |    |    |    |
| TASVS-CRYPTO-3.1 | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.                 | X  | X  | X  |
| TASVS-CRYPTO-3.2 | Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography. | X  | X  | X  |


## Control Group Definitions

### TASVS-CRYPTO-1.1

TBC

### TASVS-CRYPTO-2.1

TBC

### TASVS-CRYPTO-2.2

TBC

### TASVS-CRYPTO-2.3

TBC

### TASVS-CRYPTO-2.4

TBC

### TASVS-CRYPTO-3.1

TBC

### TASVS-CRYPTO-3.2

TBC





\newpage{}