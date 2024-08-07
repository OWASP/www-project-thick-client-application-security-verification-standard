# TASVS-NETWORK: Communication and Privacy

## Control Objective


## Testing Checklist

| TASVS-ID          | Description                                                                                                                                                                                                                                                                            | L1 | L2 | L3 |
| ---- | ------------- | - | - | - |
| TASVS-NETWORK-1   | Data leakage                                                                                                                                                                                                                                                                           |    |    |    |
| TASVS-NETWORK-1.1 | Tokens and keys sent in plain text or otherwise easily decodable/decryptable by MITM attack                                                                                                                                                                                            | X  | X  | X  |
| TASVS-NETWORK-1.2 | Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app.                                                                                                                                                                                | X  | X  | X  |
| TASVS-NETWORK-2   | Licensing & Authentication Servers (if present)                                                                                                                                                                                                                                        |    |    |    |
| TASVS-NETWORK-2.1 | Verify that session tokens possess at least 64 bits of entropy.                                                                                                                                                                                                                        | X  | X  | X  |
| TASVS-NETWORK-2.2 | Verify the application generates a new session token on user authentication.                                                                                                                                                                                                           | X  | X  | X  |
| TASVS-NETWORK-2.3 | Verify that session tokens are generated using approved cryptographic algorithms.                                                                                                                                                                                                      | X  | X  | X  |
| TASVS-NETWORK-2.4 | If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period.                                                                                                                                 | X  | X  | X  |
| TASVS-NETWORK-2.5 | Verify shared or default accounts are not present (e.g. "root" or "admin").                                                                                                                                                                                                            | X  | X  | X  |
| TASVS-NETWORK-2.6 | Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations.                                                                                                                                                                | X  | X  | X  |
| TASVS-NETWORK-2.7 | Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization. This implies protection against spoofing and elevation of privilege. | X  | X  | X  |
| TASVS-NETWORK-3   | Piracy Detection                                                                                                                                                                                                                                                                       |    |    |    |
| TASVS-NETWORK-3.1 | Memory monitoring in place                                                                                                                                                                                                                                                             | X  | X  | X  |
| TASVS-NETWORK-3.2 | Telemetery capturing data when binary tampering detected, the software's behavior is unusual or when the internet connection is lost or the license is invalid.                                                                                                                        | X  | X  | X  |
| TASVS-NETWORK-4   | Connected Services                                                                                                                                                                                                                                                                     |    |    |    |
| TASVS-NETWORK-4.1 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection.                                                                                                                                                             | X  | X  | X  |
| TASVS-NETWORK-4.2 | Verify that the application sanitizes user input before passing to AD systems to protect against LDAP injection.                                                                                                                                                                       | X  | X  | X  |
| TASVS-NETWORK-4.3 | Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL injection attacks.                                                                                                  | X  | X  | X  |
| TASVS-NETWORK-4.4 | Verify that the thick client doesn't expose services on the network like debugging features, even if bound to the local host.                                                                                                                                                          | X  | X  | X  |


## Control Group Definitions

### TASVS-NETWORK-1.1

TBC

### TASVS-NETWORK-1.2

TBC

### TASVS-NETWORK-2.1

TBC

### TASVS-NETWORK-2.2

TBC

### TASVS-NETWORK-2.3

TBC

### TASVS-NETWORK-2.4

TBC

### TASVS-NETWORK-2.5

TBC

### TASVS-NETWORK-2.6

TBC

### TASVS-NETWORK-2.7

TBC

### TASVS-NETWORK-3.1

TBC

### TASVS-NETWORK-3.2

TBC

### TASVS-NETWORK-4.1

TBC

### TASVS-NETWORK-4.2

TBC

### TASVS-NETWORK-4.3

TBC

### TASVS-NETWORK-4.4

TBC




\newpage{}