# TASVS-STORAGE: Data Storage

## Control Objective


## Testing Checklist

| TASVS-ID          | Description                                                                                                                                                                                                                       | L1 | L2 | L3 |
| ---- | ------------- | - | - | - |
| TASVS-STORAGE-1   | Sensitive Information Review                                                                                                                                                                                                      |    |    |    |
| TASVS-STORAGE-1.1 | Binaries or config files contain usernames, password, connection strings or API keys etc                                                                                                                                          | X  | X  | X  |
| TASVS-STORAGE-1.2 | Registry entires contain usernames, password, connection strings or API keys etc                                                                                                                                                  | X  | X  | X  |
| TASVS-STORAGE-1.3 | Make sure that logs are not capturing or saving sensitive data such as PII or any types of credentials used for connecting to external resources or even other resources on the machine where the application is running.         | X  | X  | X  |
| TASVS-STORAGE-1.4 | The thick client does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use.                                                                                                        | X  | X  | X  |
| TASVS-STORAGE-1.5 | Trivial static analysis does not reveal important code or data.                                                                                                                                                                   | X  | X  | X  |
| TASVS-STORAGE-1.6 | Verify that regulated private, health or financial data is stored encrypted while at rest, such as Personally Identifiable Information (PII), sensitive personal information, or data assessed likely to be subject to EU's GDPR. | X  | X  | X  |
| TASVS-STORAGE-1.7 | Authentication or session tokens cannot be easily obtained.                                                                                                                                                                       | X  | X  | X  |
| TASVS-STORAGE-2   | DLL Hijacking (Trusted application manipulation into loading a malicious DLL)                                                                                                                                                     |    |    |    |
| TASVS-STORAGE-2.1 | DLL Replacement: Swapping a genuine DLL with a malicious one, optionally using DLL Proxying to preserve the original DLL's functionality.                                                                                         | X  | X  | X  |
| TASVS-STORAGE-2.2 | <br>DLL Search Order Hijacking: Placing the malicious DLL in a search path ahead of the legitimate one, exploiting the application's search pattern.                                                                              | X  | X  | X  |

## Control Group Definitions

### TASVS-STORAGE-1.1

TBC

### TASVS-STORAGE-1.2

TBC

### TASVS-STORAGE-1.3

TBC

### TASVS-STORAGE-1.4

TBC

### TASVS-STORAGE-1.5

TBC

### TASVS-STORAGE-1.6

TBC

### TASVS-STORAGE-1.7

TBC

### TASVS-STORAGE-2.1

TBC

### TASVS-STORAGE-2.2

TBC



\newpage{}