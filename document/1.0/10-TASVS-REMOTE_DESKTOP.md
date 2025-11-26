# TASVS-REMOTE: Remote Desktop, VDI and Kiosk Security

## Control Objective

Ensure that remote desktop protocols, virtual desktop infrastructure, and kiosk mode implementations are configured and deployed securely to protect against unauthorized access, session hijacking, breakout attacks, and data leakage. This includes proper authentication mechanisms, network isolation, hardening configurations, and monitoring capabilities.


## Testing Checklist

| TASVS-ID         | Description                                                                                                                                                                  | L1 | L2 | L3 |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -- | -- | -- |
| TASVS-REMOTE-1   | Remote Desktop (RDP) Security                                                                                                                                                |    |    |    |
| TASVS-REMOTE-1.1 | Verify that RDP services are not exposed directly to the internet without VPN or gateway protection.                                                                         | X  | X  | X  |
| TASVS-REMOTE-1.2 | Verify that Network Level Authentication (NLA) is enabled to authenticate users before establishing a remote session.                                                        | X  | X  | X  |
| TASVS-REMOTE-1.3 | Verify that multi-factor authentication (MFA) is enforced for RDP access.                                                                                                    |    | X  | X  |
| TASVS-REMOTE-1.4 | Verify that account lockout policies are configured to prevent brute-force attacks.                                                                                          | X  | X  | X  |
| TASVS-REMOTE-1.5 | Verify that RDP access is restricted to specific user accounts or groups following the principle of least privilege.                                                         | X  | X  | X  |
| TASVS-REMOTE-1.6 | Verify that firewall rules restrict RDP connections to trusted IP addresses or networks only.                                                                                | X  | X  | X  |
| TASVS-REMOTE-1.7 | Verify that clipboard and drive redirection features are disabled unless specifically required and justified.                                                                | X  | X  | X  |
| TASVS-REMOTE-1.8 | Verify that printer and USB device redirection are disabled to prevent data exfiltration and malware transfer.                                                               |    | X  | X  |
| TASVS-REMOTE-1.9 | Verify that RDP traffic is encrypted using TLS with valid certificates.                                                                                                      | X  | X  | X  |
| TASVS-REMOTE-1.10| Verify that PowerShell execution is configured with constrained language mode or restricted to prevent unauthorized script execution.                                        |    | X  | X  |
| TASVS-REMOTE-1.11| Verify that RDP connection attempts, successful logins, and failures are logged and monitored.                                                                               | X  | X  | X  |
| TASVS-REMOTE-1.12| Verify that RDP services and underlying operating systems are regularly patched against known vulnerabilities.                                                               | X  | X  | X  |
| TASVS-REMOTE-1.13| Verify that RDP Gateway or Remote Desktop Gateway is used to centralize access control and enforce additional security policies.                                             |    | X  | X  |
| TASVS-REMOTE-1.14| Verify that RDP services are disabled or uninstalled when not required for business operations.                                                                              | X  | X  | X  |
| TASVS-REMOTE-2   | Virtual Desktop Infrastructure (VDI)                                                                                                                                         |    |    |    |
| TASVS-REMOTE-2.1 | Verify that VDI gateway services are not exposed directly to the internet without proper authentication and access controls.                                                 | X  | X  | X  |
| TASVS-REMOTE-2.2 | Verify that multi-factor authentication is enforced for all VDI access.                                                                                                      |    | X  | X  |
| TASVS-REMOTE-2.3 | Verify that hypervisors and VDI servers are hardened and regularly patched against known vulnerabilities.                                                                    | X  | X  | X  |
| TASVS-REMOTE-2.4 | Verify that golden images (base templates) are hardened, scanned for malware, and regularly updated.                                                                         | X  | X  | X  |
| TASVS-REMOTE-2.5 | Verify that network segmentation is implemented to isolate VDI environments from production networks and sensitive systems.                                                  |    | X  | X  |
| TASVS-REMOTE-2.6 | Verify that USB device, clipboard, and drive redirection are disabled unless specifically required and approved.                                                             | X  | X  | X  |
| TASVS-REMOTE-2.7 | Verify that VDI session activities, login attempts, and security events are logged and sent to a SIEM or centralized logging system.                                         |    | X  | X  |
| TASVS-REMOTE-2.8 | Verify that endpoint detection and response (EDR) or antivirus solutions are deployed within virtual desktop instances.                                                      | X  | X  | X  |
| TASVS-REMOTE-2.9 | Verify that VDI connection protocols (RDP, HDX, PCoIP, Blast) are configured to use encryption.                                                                              | X  | X  | X  |
| TASVS-REMOTE-2.10| Verify that session timeout and idle disconnect policies are configured to automatically terminate inactive sessions.                                                        |    | X  | X  |
| TASVS-REMOTE-3   | Kiosk Mode Security                                                                                                                                                          |    |    |    |
| TASVS-REMOTE-3.1 | Verify that kiosk systems are configured to run only approved applications using assigned access or single-app mode.                                                         | X  | X  | X  |
| TASVS-REMOTE-3.2 | Verify that keyboard shortcuts and hotkeys that could allow system access are disabled.                                                                                      | X  | X  | X  |
| TASVS-REMOTE-3.3 | Verify that USB ports and external storage devices are disabled or restricted to read-only mode.                                                                             | X  | X  | X  |
| TASVS-REMOTE-3.4 | Verify that kiosk systems are network segmented and restricted to only required application traffic.                                                                         |    | X  | X  |
| TASVS-REMOTE-3.5 | Verify that browser-based kiosks have developer tools, downloads, file uploads, and right-click functionality disabled.                                                      | X  | X  | X  |
| TASVS-REMOTE-3.6 | Verify that administrative access requires strong authentication and cannot be accessed from the kiosk interface.                                                            | X  | X  | X  |
| TASVS-REMOTE-3.7 | Verify that kiosk sessions automatically reset and clear all user data upon logout or after a period of inactivity.                                                          | X  | X  | X  |
| TASVS-REMOTE-3.8 | Verify that kiosk operating systems and applications are regularly patched and updated.                                                                                      | X  | X  | X  |
| TASVS-REMOTE-3.9 | Verify that kiosk breakout attempts are detected and logged for security monitoring.                                                                                         |    | X  | X  |
| TASVS-REMOTE-3.10| Verify that physical security controls are in place to prevent tampering with kiosk hardware and connections.                                                               |    | X  | X  |

## Control Group Definitions

### *TASVS-REMOTE-1 - Remote Desktop (RDP) Security*

Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft that allows users to connect to and control another computer remotely over a network connection. It is a system made by Microsoft that allows users to access and control another computer from far away, as if sitting in front of it. You see its screen on your computer, and you can use its mouse, keyboard, files, apps, etc. RDP operates on TCP port 3389 by default.

#### How RDP Works

RDP (Remote Desktop Protocol) allows you to control another computer over a network:

Step 1 - You open Remote Desktop Connection (mstsc.exe) on your computer.
Step 2 - You enter the IP address or hostname of the target computer.
Step 3 - Your device sends a connection request to port 3389 (default).
Step 4 - You login with a username and password (or domain credentials).
Step 5 - After authentication you see the remote computer's screen.
Step 6 - Everything you type or click is transferred to that remote machine.

#### RDP Security Risks

The following table outlines the primary security risks associated with RDP:

| No. | Risk                                   | Explanation                                                                    |
|-----|----------------------------------------|--------------------------------------------------------------------------------|
| 1   | Weak or Default Passwords              | Attackers can guess or brute-force easy passwords.                             |
| 2   | RDP Port 3389 Exposed to Internet      | Publicly reachable RDP is scanned and attacked by bots and hackers.            |
| 3   | No Multi-Factor Authentication (MFA)   | If password is leaked, attacker gets full access without needing OTP or 2FA.   |
| 4   | Brute-Force Attacks                    | Tools like Hydra or NLBrute try thousands of login attempts automatically.     |
| 5   | Credential Stuffing                    | Attackers use leaked username-password combos from data breaches.              |
| 6   | Unpatched RDP Vulnerabilities          | Exploits like BlueKeep (CVE-2019-0708) allow remote takeover if unpatched.     |
| 7   | Session Hijacking / MITM               | If traffic is not encrypted, attackers can intercept sessions or credentials.  |
| 8   | No Network Isolation                   | Once logged in via RDP, attacker can move to other internal systems.           |
| 9   | Clipboard & Drive Redirection Misuse   | Malware or sensitive files can be transferred through drive sharing.           |
| 10  | RDP Session Breakout                   | User may break out of remote session and access full host system.              |
| 11  | No Account Lockout Policy              | Unlimited wrong login attempts allow brute-force attacks easily.               |
| 12  | Stolen NTLM Hashes / Pass-the-Hash     | Tools like Mimikatz can steal password hashes and reuse them to login.         |
| 13  | Insider Misuse                         | Authorized employees can copy data or perform malicious actions.               |
| 14  | Lack of Logging or Monitoring          | No alerting means malicious logins or failures go unnoticed.                   |
| 15  | Unrestricted PowerShell or CMD         | Attackers can run scripts, malware, or commands freely once logged in.         |

#### RDP Security Controls

The following table outlines the security controls to mitigate RDP risks:

| No. | Control                                  | Explanation                                                                   |
|-----|------------------------------------------|-------------------------------------------------------------------------------|
| 1   | Use VPN or Bastion Host                  | Do not expose RDP to the Internet. Use VPN or jump server.                    |
| 2   | Enable Network Level Authentication (NLA)| Authenticates users before the remote session is created.                     |
| 3   | Strong Passwords + MFA/2FA               | Prevents brute-force, credential reuse and password attacks.                  |
| 4   | Account Lockout Policy                   | Locks account after 3-5 failed logins to stop brute-force.                    |
| 5   | Restrict RDP Users (Least Privilege)     | Only allow specific users/groups. Remove 'Everyone/Users'.                    |
| 6   | Firewall Whitelisting                    | Only allow RDP from trusted IPs (VPN, office network etc.).                   |
| 7   | Change Default Port (3389) [Optional]    | Not strong security, but reduces automated Internet scans.                    |
| 8   | Disable Clipboard & Drive Redirection    | Stops file copy/paste and drive sharing over RDP sessions.                    |
| 9   | Disable Printer / USB Redirection        | Prevents data theft or malware via redirected devices.                        |
| 10  | Enable RDP TLS Encryption                | Secure RDP traffic using SSL/TLS certificates.                                |
| 11  | PowerShell Constrained Language Mode     | Limits PowerShell misuse by restricting dangerous commands.                   |
| 12  | Enable Logging & Monitoring              | Log events 4624, 4625, 4778, 4779 and review regularly.                       |
| 13  | Patch Windows & RDP Regularly            | Updates fix critical exploits such as BlueKeep.                               |
| 14  | Use RDP Gateway / RD Gateway             | Centralized secure access; enforces MFA and audit logs.                       |
| 15  | Disable RDP When Not Required            | Turn off or uninstall RDP if it's not being used.                             |

### TASVS-REMOTE-1.1 - Verify that RDP services are not exposed directly to the internet without VPN or gateway protection.

RDP services should never be directly exposed to the internet without protection. Publicly accessible RDP endpoints are constantly scanned and attacked by automated tools and threat actors. Organizations should implement VPN access or use RDP Gateway/bastion hosts to provide an additional layer of authentication and access control before allowing RDP connections. This significantly reduces the attack surface and provides better visibility into remote access attempts.

### TASVS-REMOTE-1.2 - Verify that Network Level Authentication (NLA) is enabled to authenticate users before establishing a remote session.

Network Level Authentication (NLA) requires users to authenticate before a full RDP session is established. This prevents unauthenticated users from consuming server resources and provides protection against certain types of denial-of-service attacks. NLA also helps protect against vulnerabilities that may exist in the RDP protocol itself by requiring authentication before the vulnerable components are exposed.

### TASVS-REMOTE-1.3 - Verify that multi-factor authentication (MFA) is enforced for RDP access.

Multi-factor authentication adds a critical security layer beyond username and password authentication. Even if credentials are compromised through phishing, credential stuffing, or brute-force attacks, MFA prevents unauthorized access. MFA can be implemented through RDP Gateway, third-party solutions, or integrated authentication providers supporting protocols like RADIUS or SAML.

### TASVS-REMOTE-1.4 - Verify that account lockout policies are configured to prevent brute-force attacks.

Account lockout policies should be configured to temporarily lock accounts after a specified number of failed login attempts (typically 3-5 attempts). This prevents automated brute-force tools from continuously attempting to guess passwords. Organizations should balance security with usability, ensuring that legitimate users are not frequently locked out while still providing effective protection against credential guessing attacks.

### TASVS-REMOTE-1.5 - Verify that RDP access is restricted to specific user accounts or groups following the principle of least privilege.

Access to RDP should be limited to only those users who require it for their job functions. Default groups like "Everyone" or "Users" should be removed from RDP access permissions. Instead, create specific security groups for remote access and carefully manage membership. Regular access reviews should be conducted to ensure that permissions remain appropriate as roles change.

### TASVS-REMOTE-1.6 - Verify that firewall rules restrict RDP connections to trusted IP addresses or networks only.

Firewall rules should be configured to allow RDP connections only from known and trusted IP addresses or network ranges. This might include VPN address ranges, office networks, or specific administrator workstations. IP whitelisting significantly reduces exposure to internet-based attacks while still allowing legitimate remote access from approved locations.

### TASVS-REMOTE-1.7 - Verify that clipboard and drive redirection features are disabled unless specifically required and justified.

Clipboard and drive redirection allow users to copy and paste data or access local drives through an RDP session. While convenient, these features can be exploited to exfiltrate sensitive data or introduce malware into the environment. Unless there is a specific business requirement, these features should be disabled. When they must be enabled, their use should be logged and monitored.

### TASVS-REMOTE-1.8 - Verify that printer and USB device redirection are disabled to prevent data exfiltration and malware transfer.

Printer and USB redirection can be used to transfer files and data between the remote system and the client device. Attackers can leverage these features to steal sensitive information or introduce malicious software. Disabling these redirections reduces the risk of data leakage and malware infection while maintaining secure remote access capabilities.

### TASVS-REMOTE-1.9 - Verify that RDP traffic is encrypted using TLS with valid certificates.

RDP should be configured to use TLS encryption with properly signed certificates to protect session data in transit. This prevents man-in-the-middle attacks and eavesdropping on RDP sessions. Self-signed certificates should be avoided in production environments as they provide limited protection against sophisticated attacks. Certificate validation should be enforced on client systems.

### TASVS-REMOTE-1.10 - Verify that PowerShell execution is configured with constrained language mode or restricted to prevent unauthorized script execution.

PowerShell provides powerful system administration capabilities that attackers often abuse after gaining RDP access. Implementing PowerShell constrained language mode limits the ability to execute arbitrary scripts and access dangerous .NET APIs. Application whitelisting and script execution policies should also be enforced to prevent unauthorized PowerShell activity.

### TASVS-REMOTE-1.11 - Verify that RDP connection attempts, successful logins, and failures are logged and monitored.

Comprehensive logging is essential for detecting and responding to unauthorized access attempts. Windows Event IDs 4624 (successful logon), 4625 (failed logon), 4778 (session reconnected), and 4779 (session disconnected) should be collected and analyzed. Logs should be forwarded to a SIEM or centralized logging system for correlation and alerting on suspicious patterns such as repeated failed logins or logins from unusual locations.

### TASVS-REMOTE-1.12 - Verify that RDP services and underlying operating systems are regularly patched against known vulnerabilities.

RDP has been the target of numerous critical vulnerabilities, including BlueKeep (CVE-2019-0708), which allows unauthenticated remote code execution. Regular patching of both the RDP service and the underlying operating system is essential to protect against known exploits. Organizations should have a patch management process that prioritizes critical RDP-related vulnerabilities.

### TASVS-REMOTE-1.13 - Verify that RDP Gateway or Remote Desktop Gateway is used to centralize access control and enforce additional security policies.

RDP Gateway provides a centralized access point for remote desktop connections, allowing organizations to enforce consistent security policies, implement MFA, and maintain detailed audit logs. It enables RDP access over HTTPS (port 443), which is often less restrictive in firewall rules than the default RDP port. RDP Gateway also provides granular authorization controls and connection logging.

### TASVS-REMOTE-1.14 - Verify that RDP services are disabled or uninstalled when not required for business operations.

If RDP is not needed on a system, it should be completely disabled or the Remote Desktop Services role should be uninstalled. This eliminates the attack surface associated with RDP entirely. Even on systems where RDP might occasionally be needed, consider disabling the service and enabling it only when required, then disabling it again after use.

### *TASVS-REMOTE-2 - Virtual Desktop Infrastructure (VDI)*

Virtual Desktop Infrastructure (VDI) is a technology where desktop operating systems (like Windows or Linux) run inside virtual machines hosted in a data center or cloud. Users connect to these desktops remotely using clients such as VMware Horizon, Citrix Workspace, Microsoft AVD, etc.

#### How VDI Works (Basic Flow)

The following describes the basic VDI workflow:

Step 1 - User Device connects to the VDI environment.
Step 2 - Login to VDI Client / Portal (VMware / Citrix / AVD).
Step 3 - Gateway / Connection Broker Authenticates User.
Step 4 - Virtual Desktop (VM) is Assigned from Pool or Created.
Step 5 - Secure Protocol Established (RDP / HDX / PCoIP / Blast Protocol).
Step 6 - User Works on Remote Desktop (Data stays in Data Center/Cloud Server).

#### VDI Top Security Risks

The following table outlines the primary security risks associated with VDI:

| No. | Risk                                      | Explanation                                        |
|-----|-------------------------------------------|----------------------------------------------------|
| 1   | Weak Login / No MFA                       | Stolen passwords = easy access.                    |
| 2   | VDI Gateway Exposed to Internet           | Hackers scan & attack login ports.                 |
| 3   | Hypervisor / Server Compromise            | If host is hacked, all VMs at risk.                |
| 4   | Infected Base Image (Golden Image)        | Malware spreads to all VDI desktops.               |
| 5   | No Network Segmentation                   | Attackers move inside internal net.                |
| 6   | USB / Clipboard / Drive Redirection Misuse| Data theft or malware injection.                   |
| 7   | No Logging or Monitoring                  | Silent attacks go unnoticed.                       |
| 8   | Unpatched VDI Software                    | Old Citrix/VMware/AVD = vulnerable.                |

#### VDI Security Controls

The following table outlines the security controls to mitigate VDI risks:

| No. | Security Control                          | Explanation                                      |
|-----|-------------------------------------------|--------------------------------------------------|
| 1   | Enforce MFA for Login                     | Stops password-only attacks.                     |
| 2   | Use VPN / Secure Gateway                  | Do not expose VDI/RDP to internet.               |
| 3   | Patch VDI Servers & Hypervisors           | Fixes Citrix/VMware exploits.                    |
| 4   | Harden & Scan Golden Images               | Clean, malware-free VM templates.                |
| 5   | Network Segmentation (Zero Trust)         | VDI desktops cannot reach everything.            |
| 6   | Disable USB / Clipboard / Drive Sharing   | Prevents malware/data leakage.                   |
| 7   | Enable Logging + Send to SIEM             | Track logins, failures, sessions.                |
| 8   | Use EDR/Antivirus in Virtual Desktops     | Detect malware or suspicious behavior.           |

### TASVS-REMOTE-2.1 - Verify that VDI gateway services are not exposed directly to the internet without proper authentication and access controls.

VDI gateway servers (such as Citrix Gateway or VMware Unified Access Gateway) should be properly hardened and protected before being exposed to the internet. These gateways should require authentication before granting any access to the VDI environment. Consider implementing pre-authentication checks, such as device posture assessment, before allowing connections. Additional protections like rate limiting and geographic restrictions can help prevent automated attacks.

### TASVS-REMOTE-2.2 - Verify that multi-factor authentication is enforced for all VDI access.

MFA is critical for VDI environments as they often provide access to sensitive corporate resources and data. MFA should be enforced at the gateway level before users can authenticate to their virtual desktops. This protects against credential theft, phishing attacks, and password reuse from data breaches. MFA solutions should support modern authentication methods and provide a good user experience to encourage adoption.

### TASVS-REMOTE-2.3 - Verify that hypervisors and VDI servers are hardened and regularly patched against known vulnerabilities.

The hypervisor and VDI infrastructure servers represent a single point of compromise that could affect all virtual desktops. These systems must be hardened according to vendor best practices and security benchmarks (such as CIS benchmarks). Regular patching is essential, as vulnerabilities in these components can allow attackers to escape virtual machines, access other desktops, or compromise the entire infrastructure.

### TASVS-REMOTE-2.4 - Verify that golden images (base templates) are hardened, scanned for malware, and regularly updated.

Golden images serve as the template for virtual desktop instances. If a golden image is compromised or misconfigured, the security issues will propagate to all desktops created from that image. Golden images should be built using hardened configurations, scanned for malware, and regularly updated with security patches. A formal change management process should govern modifications to golden images.

### TASVS-REMOTE-2.5 - Verify that network segmentation is implemented to isolate VDI environments from production networks and sensitive systems.

VDI environments should be segmented from production networks using VLANs, firewalls, or other network security controls. Virtual desktops should not have unrestricted access to internal networks and sensitive systems. Network access should be granted based on the principle of least privilege, with specific firewall rules defining what resources virtual desktops can access. This limits the potential for lateral movement if a virtual desktop is compromised.

### TASVS-REMOTE-2.6 - Verify that USB device, clipboard, and drive redirection are disabled unless specifically required and approved.

Redirection features that allow file transfer between the client endpoint and the virtual desktop create opportunities for data exfiltration and malware introduction. These features should be disabled by default and only enabled for specific users or use cases where there is a documented business justification. When enabled, file transfers should be logged and potentially scanned for malware.

### TASVS-REMOTE-2.7 - Verify that VDI session activities, login attempts, and security events are logged and sent to a SIEM or centralized logging system.

Comprehensive logging is essential for detecting security incidents in VDI environments. Logs should capture user authentication events, session connections and disconnections, resource access, policy violations, and security-relevant events. These logs should be forwarded to a SIEM or centralized logging platform for correlation, analysis, and long-term retention. Alerts should be configured for suspicious activities.

### TASVS-REMOTE-2.8 - Verify that endpoint detection and response (EDR) or antivirus solutions are deployed within virtual desktop instances.

Virtual desktops require the same endpoint security protections as physical workstations. EDR or antivirus solutions should be deployed and actively maintained within each virtual desktop instance. These security tools should be configured for virtual environments to avoid performance issues and should be able to detect and respond to malware, suspicious behaviors, and other security threats.

### TASVS-REMOTE-2.9 - Verify that VDI connection protocols (RDP, HDX, PCoIP, Blast) are configured to use encryption.

All VDI connection protocols should be configured to encrypt session traffic to protect data in transit. This prevents eavesdropping and man-in-the-middle attacks. Encryption should be enforced and not optional. The encryption strength should meet current cryptographic standards, and certificate validation should be properly configured to prevent attacks using forged certificates.

### TASVS-REMOTE-2.10 - Verify that session timeout and idle disconnect policies are configured to automatically terminate inactive sessions.

Idle session policies help prevent unauthorized access to unattended virtual desktops. Sessions should be locked after a period of inactivity and fully disconnected after an extended idle period. The specific timeout values should be determined based on the sensitivity of the data accessed and organizational security requirements. Disconnected sessions should release resources to optimize infrastructure utilization.

### *TASVS-REMOTE-3 - Kiosk Mode Security*

Kiosk Mode is a restricted environment where a computer or device is locked to run only one application or a limited set of functions. Users cannot access the desktop, other apps, settings, file explorer, task manager, or system functions.

Common examples include:
1. ATMs
2. Airport check-in systems
3. School exam systems
4. Self-service ticket machines
5. Study-only laptops
6. POS (Point of Sale) billing computers
7. Digital signboards / menu screens

#### How Kiosk Mode Works

The following describes how kiosk mode is typically implemented:

Step 1 - Install Windows / Linux / ChromeOS normally.
Step 2 - Admin enables Kiosk Mode / Assigned Access.
Step 3 - Admin selects one allowed app (Browser / POS / Learning App).
Step 4 - System hides desktop, taskbar, start menu, settings, and file explorer.
Step 5 - User can only access that single application, nothing else.
Step 6 - Keyboard shortcuts (Alt+Tab, Ctrl+Esc, Win+R, Ctrl+Alt+Del) are blocked.
Step 7 - After logout or restart, session resets automatically.

#### Kiosk Security Risks

The following table outlines the primary security risks associated with Kiosk Mode:

| No. | Risk                                | Explanation                                                     |
|-----|-------------------------------------|-----------------------------------------------------------------|
| 1   | Kiosk Breakout / Escape             | User escapes kiosk app to desktop/OS.                           |
| 2   | Keyboard Shortcut Abuse             | Ctrl+Alt+Del, Alt+Tab, etc. give access to system functions.    |
| 3   | USB / External Device Attack        | Malware or data theft via USB or phone connections.             |
| 4   | Browser or DevTools Exploit         | Use of Inspect Element, downloads, or file upload to bypass restrictions. |
| 5   | No Network Isolation                | Kiosk can connect to internal sensitive servers or networks.    |
| 6   | Weak or Default Admin Passwords     | Users can exit kiosk or change system settings.                 |
| 7   | Unpatched OS / App Vulnerabilities  | Allows privilege escalation or remote attack.                   |
| 8   | No Session Reset / Data Leakage     | Previous user's history or data remains available.              |

#### Kiosk Security Controls

The following table outlines the security controls to mitigate Kiosk Mode risks:

| No. | Control                              | Explanation                                                     |
|-----|--------------------------------------|-----------------------------------------------------------------|
| 1   | Enable Single-App / Assigned Access  | Lock system to only one application.                            |
| 2   | Disable Shortcut Keys & Hotkeys      | Block Alt+Tab, Ctrl+Esc, Win+R, Ctrl+Alt+Del.                   |
| 3   | Block USB & External Drives          | Disable ports or enforce read-only to prevent malware/data theft. |
| 4   | Network Segmentation / Firewall      | Allow only required internet/app traffic; block internal network. |
| 5   | App / Browser Hardening              | Disable right-click, downloads, developer tools, file uploads.  |
| 6   | Strong Admin Passwords / No Local Admin Accounts | Prevent exiting kiosk or modifying system settings. |
| 7   | Auto Session Reset & Cache Clear     | Clear history, cookies, and user data on logout or idle timeout. |
| 8   | Regular Patching & Updates           | Keep OS/app up to date to prevent exploit attacks.              |

### TASVS-REMOTE-3.1 - Verify that kiosk systems are configured to run only approved applications using assigned access or single-app mode.

Kiosk systems should be configured using assigned access features (such as Windows 10/11 Kiosk Mode, Android's Lock Task Mode, or similar) that restrict the device to running only approved applications. The operating system should prevent access to the desktop, start menu, file explorer, settings, and other system functions. Multi-app kiosks should carefully define which applications are accessible and prevent users from switching to unapproved applications.

### TASVS-REMOTE-3.2 - Verify that keyboard shortcuts and hotkeys that could allow system access are disabled.

Keyboard shortcuts such as Alt+Tab, Ctrl+Esc, Win+R, Ctrl+Alt+Del, Alt+F4, and others should be disabled to prevent users from escaping the kiosk environment. Attackers and curious users often attempt to use these shortcuts to access system functions or break out of the restricted environment. The kiosk software should intercept and block these key combinations at a low level to prevent bypass.

### TASVS-REMOTE-3.3 - Verify that USB ports and external storage devices are disabled or restricted to read-only mode.

USB ports can be used to introduce malware, execute unauthorized software, or exfiltrate data from kiosk systems. USB ports should be physically disabled, blocked through BIOS settings, or restricted through operating system policies. If USB functionality is required for specific devices (such as card readers or barcode scanners), only those specific device types should be allowed while blocking storage devices and other potentially dangerous peripherals.

### TASVS-REMOTE-3.4 - Verify that kiosk systems are network segmented and restricted to only required application traffic.

Kiosk systems should be placed on isolated network segments with strict firewall rules that allow only necessary traffic. Kiosks should not have access to internal corporate networks, file shares, or administrative systems. Network access should be limited to specific application servers, cloud services, or internet resources required for kiosk functionality. This prevents compromised kiosks from being used as pivot points for network attacks.

### TASVS-REMOTE-3.5 - Verify that browser-based kiosks have developer tools, downloads, file uploads, and right-click functionality disabled.

Browser-based kiosks should run in a highly restricted mode with all potentially dangerous features disabled. Developer tools (F12, Inspect Element) can be used to manipulate the page or execute arbitrary JavaScript. Download and file upload capabilities can introduce malware or exfiltrate data. Right-click menus may provide access to browser functions that could allow escape. Modern kiosk browsers should enforce these restrictions programmatically rather than relying on client-side controls.

### TASVS-REMOTE-3.6 - Verify that administrative access requires strong authentication and cannot be accessed from the kiosk interface.

Administrative functions should be completely separated from the kiosk user interface. Administrators should not be able to exit kiosk mode or access administrative functions using passwords, PINs, or key combinations that could be observed or guessed. Administrative access should require physical access to the device, external authentication devices, or remote management tools. Default administrative credentials should be changed before deployment.

### TASVS-REMOTE-3.7 - Verify that kiosk sessions automatically reset and clear all user data upon logout or after a period of inactivity.

Kiosk sessions should automatically clear all user data, browsing history, cookies, cached files, and temporary data when a user logs out or after a configured period of inactivity. This prevents the next user from accessing the previous user's information and protects privacy. The kiosk should return to its initial state with no persistent data from the previous session.

### TASVS-REMOTE-3.8 - Verify that kiosk operating systems and applications are regularly patched and updated.

Kiosk systems require the same patch management attention as other computing devices. Operating systems and applications should be regularly updated to address security vulnerabilities. Because kiosks are often in public or semi-public locations, they may be more vulnerable to physical and network-based attacks. A centralized patch management system should be used to ensure all kiosk devices remain current with security updates.

### TASVS-REMOTE-3.9 - Verify that kiosk breakout attempts are detected and logged for security monitoring.

Security monitoring should be implemented to detect and log kiosk breakout attempts. This includes monitoring for attempts to access restricted functions, use of blocked keyboard shortcuts, insertion of unauthorized USB devices, or other suspicious activities. Logs should be forwarded to a centralized security monitoring system. Repeated breakout attempts from specific kiosks may indicate physical tampering or targeted attacks.

### TASVS-REMOTE-3.10 - Verify that physical security controls are in place to prevent tampering with kiosk hardware and connections.

Kiosk hardware should be physically secured to prevent tampering, theft, or unauthorized access to internal components. This includes using locked enclosures, securing cables and connections, disabling physical ports, and placing kiosks in monitored locations when possible. Physical access to ports, boot devices, or system internals can allow attackers to bypass software security controls entirely. Consider using tamper-evident seals and regular physical inspections.

\newpage{}
