# TASVS-CONF: Configuration and Building


## Control Objective

Ensure that the application's configuration management processes are secure, reliable, and automated. This includes verifying secure build and deployment processes, proper compiler flag configurations, automated deployment scripts, removal of unnecessary features, sourcing third-party components from trusted repositories, maintaining a Software Bill of Materials (SBOM), and keeping all software components up-to-date.

This control objective helps mitigate security vulnerabilities, ensures compliance, and maintains the integrity and availability of the application.

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


## Control Group Definitions

### *TASVS-CONF-1 - General Configuration Checks*

### TASVS-CONF-1.1 - Verify that the application build and deployment processes are performed in a secure and repeatable way, such as CI/CD automation, automated configuration management, and automated deployment scripts.

Build and deployments processes should be automated, secure, and repeatable. This includes using CI/CD automation, automated configuration management, and automated deployment scripts. These processes help ensure that the application is built and deployed consistently and securely, reducing the risk of errors and vulnerabilities.

### TASVS-CONF-1.2 - Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer, or string operations are found.

Compiler flags should be configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer, or string operations are found. These protections help prevent common security vulnerabilities such as buffer overflows and format string vulnerabilities.

### TASVS-CONF-1.3 - Verify that the application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion.

The application, configuration, and all dependencies should be able to be re-deployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion. This ensures that the application can be quickly restored in the event of a failure or disaster, reducing downtime and ensuring business continuity.

### TASVS-CONF-1.4 - Verify that all unneeded features, documentation, sample applications and configurations are removed.

Unneeded features, documentation, sample applications, and configurations should be removed from the application. This helps reduce the attack surface of the application, improve performance, and simplify maintenance. Removing unnecessary features also reduces the risk of security vulnerabilities and compliance issues.

### TASVS-CONF-1.5 - Verify that third party components come from pre-defined, trusted and continually maintained repositories.

Third-party components should come from pre-defined, trusted, and continually maintained repositories. This helps ensure that the components are secure, reliable, and up-to-date. Sourcing components from trusted repositories reduces the risk of introducing security vulnerabilities, malware, or other issues into the application.

### TASVS-CONF-1.6 - Verify that a Software Bill of Materials (SBOM) is maintained of all third party libraries in use.

A Software Bill of Materials (SBOM) should be maintained of all third-party libraries in use. An SBOM provides a detailed inventory of all software components used in the application, including third-party libraries, frameworks, and runtimes. This helps track dependencies, identify vulnerabilities, and ensure compliance with licensing requirements.


\newpage{}