# TASVS-CONF: Configuration and Building


## Control Objective



## Testing Checklist

| TASVS-ID       | Description                                                                                                                                                                                                                                                                        | L1 | L2 | L3 |
| ---- | ------------- | - | - | - |
| TASVS-CONF-1   | General Configuration Checks                                                                                                                                                                                                                                                       |    |    |    |
| TASVS-CONF-1.1 | Verify that the application build and deployment processes are performed in a secure and repeatable way, such as CI/CD automation, automated configuration management, and automated deployment scripts.                                                                           | X  | X  | X  |
| TASVS-CONF-1.2 | Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer, or string operations are found. | X  | X  | X  |
| TASVS-CONF-1.3 | Verify that the application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion.                                             |    | X  | X  |
| TASVS-CONF-1.4 | Verify that all unneeded features, documentation, sample applications and configurations are removed.                                                                                                                                                                              | X  | X  | X  |
| TASVS-CONF-1.5 | Verify that third party components come from pre-defined, trusted and continually maintained repositories.                                                                                                                                                                         | X  | X  | X  |
| TASVS-CONF-1.6 | Verify that a Software Bill of Materials (SBOM) is maintained of all third party libraries in use.                                                                                                                                                                                 | X  | X  | X  |
| TASVS-CONF-1.7 | Ensure that all software components, libraries, frameworks, and runtimes used in the application are up-to-date and not end-of-life or obsolete. Outdated or obsolete components can introduce security vulnerabilities, performance issues, and compatibility problems.           | X  | X  | X  |

\newpage{}