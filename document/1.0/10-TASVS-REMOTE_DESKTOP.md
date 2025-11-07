10.1
What is RDP? 
RDP = Remote Desktop Protocol
It is a system made by Microsoft.
It allows user to access and control another computer from far away — like you're sitting in front of it.
You see its screen on your computer, and you can use its mouse, keyboard, files, apps, etc.
It’s port number is 3389

+------------------------------------------------------------------------------+
| 10.1.2) How RDP Works?                                                       |
| RDP (Remote Desktop Protocol) allows you to control another computer over a  |
| network.                                                                     |
|                                                                              |
| Step 1  - You open Remote Desktop Connection (mstsc.exe) on your computer.   |
| Step 2  - You enter the IP address or hostname of the target computer.       |
| Step 3  - Your device sends a connection request to port 3389 (default).     |
| Step 4  - You login with a username + password (or domain credentials).      |
| Step 5  - After authentication → You see the remote computer's screen.       |
| Step 6  - Everything you type/click is transferred to that remote machine.   |
+------------------------------------------------------------------------------+


 10.1.3) RDP Security Risks

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

10.1.4)
+---------------------------------------------------------------------------------------------------------------+
|                                   RDP SECURITY CONTROLS                                                       |
|---------------------------------------------------------------------------------------------------------------|
| No. |           Control                        |            Explanation                                       |
|-----|------------------------------------------|--------------------------------------------------------------|
| 1   | Use VPN or Bastion Host                  | Do not expose RDP to the Internet. Use VPN or jump server.   |
| 2   | Enable Network Level Authentication (NLA)| Authenticates users before the remote session is created.    |
| 3   | Strong Passwords + MFA/2FA               | Prevents brute-force, credential reuse and password attacks. |
| 4   | Account Lockout Policy                   | Locks account after 3–5 failed logins to stop brute-force.   |
| 5   | Restrict RDP Users (Least Privilege)     | Only allow specific users/groups. Remove 'Everyone/Users'.   |
| 6   | Firewall Whitelisting                    | Only allow RDP from trusted IPs (VPN, office network etc.).  |
| 7   | Change Default Port (3389) [Optional]    | Not strong security, but reduces automated Internet scans.   |
| 8   | Disable Clipboard & Drive Redirection    | Stops file copy/paste and drive sharing over RDP sessions.   |
| 9   | Disable Printer / USB Redirection        | Prevents data theft or malware via redirected devices.       |
| 10  | Enable RDP TLS Encryption                | Secure RDP traffic using SSL/TLS certificates.               |
| 11  | PowerShell Constrained Language Mode     | Limits PowerShell misuse by restricting dangerous commands.  |
| 12  | Enable Logging & Monitoring              | Log events 4624, 4625, 4778, 4779 and review regularly.      |
| 13  | Patch Windows & RDP Regularly            | Updates fix critical exploits such as BlueKeep.              |
| 14  | Use RDP Gateway / RD Gateway             | Centralized secure access; enforces MFA and audit logs.      |
| 15  | Disable RDP When Not Required            | Turn off or uninstall RDP if it’s not being used.            |
+---------------------------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+


10.2) Virtual Desktop Infrastructure (VDI) Security
10.2.1 )
What is VDI? 
VDI (Virtual Desktop Infrastructure) is a technology where desktop operating systems (like Windows or Linux) run inside 
virtual machines hosted in a data center or cloud.
Users connect to these desktops remotely using clients such as VMware Horizon, Citrix Workspace, Microsoft AVD, etc.


+----------------------------------------------------------------------------------+
|                                                                                  |
|                     10.2.2  HOW VDI WORKS (Basic Flow)                           |
|                                                                                  |
|                               User Device                                        |
|                                      ↓                                           |
|                 Login to VDI Client / Portal (VMware / Citrix / AVD)             |
|                                      ↓                                           |
|                   Gateway / Connection Broker Authenticates User                 |
|                                      ↓                                           |
|               Virtual Desktop (VM) is Assigned from Pool or Created              |
|                                      ↓                                           |
|         Secure Protocol Established (RDP / HDX / PCoIP / Blast Protocol)         |
|                                      ↓                                           |
|        User Works on Remote Desktop (Data stays in Data Center/Cloud Server)     |
|                                                                                  |
+----------------------------------------------------------------------------------+


+--------------------------------------------------------------------------------------+
|                       [ 10.2.3  VDI – TOP SECURITY RISKS ]                           |
+--------------------------------------------------------------------------------------+
| No. | Risk                                      | Explanation                        |
|-----|-------------------------------------------|------------------------------------|
| 1   | Weak Login / No MFA                       | Stolen passwords = easy access.    |
| 2   | VDI Gateway Exposed to Internet           | Hackers scan & attack login ports. |
| 3   | Hypervisor / Server Compromise            | If host is hacked → all VMs at risk|
| 4   | Infected Base Image (Golden Image)        | Malware spreads to all VDI desktops|
| 5   | No Network Segmentation                   | Attackers move inside internal net.|
| 6   | USB / Clipboard / Drive Redirection Misuse| Data theft or malware injection.   |
| 7   | No Logging or Monitoring                  | Silent attacks go unnoticed.       |
| 8   | Unpatched VDI Software                    | Old Citrix/VMware/AVD = vulnerable.|
+--------------------------------------------------------------------------------------+

+----------------------------------------------------------------------------------------+
|                      [ 10.2.4  VDI – SECURITY CONTROLS ]                               |
+----------------------------------------------------------------------------------------+
| No. | Security Control                          | Explanation                          |
|-----|-------------------------------------------|------------------------------------- |
| 1   | Enforce MFA for Login                     | Stops password-only attacks.         |
| 2   | Use VPN / Secure Gateway                  | Do not expose VDI/RDP to internet.   |
| 3   | Patch VDI Servers & Hypervisors           | Fixes Citrix/VMware exploits.        |
| 4   | Harden & Scan Golden Images               | Clean, malware-free VM templates.    |
| 5   | Network Segmentation (Zero Trust)         | VDI desktops cannot reach everything |
| 6   | Disable USB / Clipboard / Drive Sharing   | Prevents malware/data leakage.       |
| 7   | Enable Logging + Send to SIEM             | Track logins, failures, sessions.    |
| 8   | Use EDR/Antivirus in Virtual Desktops     | Detect malware or suspicious behavior|
+----------------------------------------------------------------------------------------+



+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
+-----------------------------------------------------------------------------------------------------------------------------------------------------------+

10.3.1 
What is Kiosk Mode?
Kiosk Mode is a restricted environment where a computer or device is locked to run only one application or a limited set of functions.
Users cannot access the desktop, other apps, settings, file explorer, task manager, or system functions.

Common examples:
1)ATMs
2)Airport check-in systems
3)School exam systems
4)Self-service ticket machines
5)Study-only laptops
6)POS (Point of Sale) billing computers
7)Digital signboards / menu screens

+--------------------------------------------------------------------------------+
|                       10.3.2  HOW KIOSK MODE WORKS                             |
+--------------------------------------------------------------------------------+
|                Install Windows / Linux / ChromeOS normally.                    |
|                                       ↓                                        |
|                 Admin enables Kiosk Mode / Assigned Access.                    |  
|                                       ↓                                        |
|        Admin selects one allowed app (Browser / POS / Learning App).           |
|                                       ↓                                        |
|   System hides desktop, taskbar, start menu, settings, and file explorer.      |
|                                       ↓                                        |
|         User can only access that single application — nothing else.           |
|                                       ↓                                        |
|     Keyboard shortcuts (Alt+Tab, Ctrl+Esc, Win+R, Ctrl+Alt+Del) are blocked.   |
|                                       ↓                                        |
|            After logout or restart → session resets automatically.             |
+--------------------------------------------------------------------------------+

+=====================================================================================+
|                     ⚠  10.3.3  KIOSK SECURITY RISKS  ⚠                             |
+=====================================================================================+
| No. | Risk                                | Explanation                             |
|-----|-------------------------------------|-----------------------------------------|
| 1   | Kiosk Breakout / Escape             | User escapes kiosk app to desktop/OS.   |
|-------------------------------------------------------------------------------------|
| 2   | Keyboard Shortcut Abuse             | Ctrl+Alt+Del, Alt+Tab, etc. give        |
|     |                                     | access to system functions.             |
|-------------------------------------------------------------------------------------|
| 3   | USB / External Device Attack        | Malware or data theft via USB or        |
|     |                                     | phone connections.                      |
|-------------------------------------------------------------------------------------|
| 4   | Browser or DevTools Exploit         | Use of Inspect Element, downloads,      |
|     |                                     | or file upload to bypass restrictions.  |
|-------------------------------------------------------------------------------------|
| 5   | No Network Isolation                | Kiosk can connect to internal           |
|     |                                     | sensitive servers or networks.          |
|-------------------------------------------------------------------------------------|
| 6   | Weak or Default Admin Passwords     | Users can exit kiosk or change          |
|     |                                     | system settings.                        |
|-------------------------------------------------------------------------------------|
| 7   | Unpatched OS / App Vulnerabilities  | Allows privilege escalation or          |
|     |                                     | remote attack.                          |
|-------------------------------------------------------------------------------------|
| 8   | No Session Reset / Data Leakage     | Previous user's history or data         |
|     |                                     | remains available.                      |
+=====================================================================================+


+==================================================================================+
|                     10.3.4  KIOSK SECURITY CONTROLS                              |
+==================================================================================+
| No. | Control                              | Explanation                         |
|-----|--------------------------------------|------------------------------------ |
| 1   | Enable Single-App / Assigned Access  | Lock system to only one application |
|     |                                      |                                     |
|----------------------------------------------------------------------------------|
| 2   | Disable Shortcut Keys & Hotkeys      | Block Alt+Tab, Ctrl+Esc, Win+R,     |
|     |                                      | Ctrl+Alt+Del.                       |
|----------------------------------------------------------------------------------|
| 3   | Block USB & External Drives          | Disable ports or enforce read-only  |
|     |                                      | to prevent malware/data theft.      |
|----------------------------------------------------------------------------------|
| 4   | Network Segmentation / Firewall      | Allow only required internet/app    |
|     |                                      | traffic; block internal network.    |
|----------------------------------------------------------------------------------|
| 5   | App / Browser Hardening              | Disable right-click, downloads,     |
|     |                                      | developer tools, file uploads.      |
|----------------------------------------------------------------------------------|
| 6   | Strong Admin Passwords /             | Prevent exiting kiosk or modifying  |
|     | No Local Admin Accounts              | system settings.                    |
|----------------------------------------------------------------------------------|
| 7   | Auto Session Reset & Cache Clear     | Clear history, cookies, and user    |
|     |                                      | data on logout or idle timeout.     |
|----------------------------------------------------------------------------------|
| 8   | Regular Patching & Updates           | Keep OS/app up to date to prevent   |
|     |                                      | exploit attacks.                    |
+==================================================================================+

