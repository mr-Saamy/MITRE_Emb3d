import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json, csv, uuid, os
from datetime import datetime

DEVICE_TYPES = [
    "Wayside Object Controller (WOC)", "Onboard Train Control (TCMS/EVC)",
    "CBTC Radio Unit", "Passenger Information System (PIS)",
    "Train Door Controller", "Datalogger / Event Recorder",
    "PLC / RTU / Gateway", "Safety Computer (SIL-rated)",
    "SCADA / HMI Server", "Maintenance Laptop / Eng. Tool", "Custom / Other",
]
OS_TYPES    = ["Bare Metal / RTOS","Linux (Hardened)","Linux (Generic)","Windows Embedded","VxWorks","QNX","Other"]
LOCATIONS   = ["Trackside / Wayside","Onboard / Vehicle","Control Centre","Passenger-Facing","Maintenance Workshop"]
CRITICALITY = ["Safety-Critical (SIL 2/3/4)","Mission-Critical","Operational","Non-Critical (Info)"]
ZONES       = ["Zone 0 – Safety / Control","Zone 1 – Supervisory","Zone 2 – Enterprise / DMZ","Zone 3 – Untrusted"]
SL_OPTIONS  = [
    "SL 1 – Protection against casual / unintentional violation",
    "SL 2 – Protection against intentional violation (generic hacker)",
    "SL 3 – Protection against sophisticated means (hacktivist / insider)",
    "SL 4 – Protection against nation-state / APT",
]

# (prop_id, display_label, category, tooltip)
PROPERTIES = [
    ("HP-1","Physical Ports Present (USB, SD, Serial)","Hardware",
     "Accessible physical I/O ports usable to attach malicious devices or extract data."),
    ("HP-2","Exposed Debug Interface (JTAG / UART / SWD)","Hardware",
     "Debug interfaces active in production allow low-level hardware access with no auth."),
    ("HP-3","Untrusted External Storage (SD Card / Removable Flash)","Hardware",
     "Device accepts removable storage from potentially untrusted sources."),
    ("HP-4","DMA-capable Peripheral Bus (PCIe / FireWire)","Hardware",
     "DMA-capable interfaces allow bypassing CPU memory protections."),
    ("HP-5","Physically Accessible (Public / Unsecured Location)","Hardware",
     "Device installed where passengers or non-authorised personnel can physically reach it."),
    ("HP-6","No Anti-tamper / Tamper Detection Mechanism","Hardware",
     "No tamper-evident seals, intrusion switches, or active key zeroization."),
    ("HP-7","Shared Power Bus with Other Devices","Hardware",
     "Shared power rail enables power-analysis attacks or fault injection."),
    ("HP-8","No EMI / RF Shielding (Side-Channel Susceptible)","Hardware",
     "Crypto hardware unshielded; susceptible to EM side-channel measurement."),
    ("SS-1","Runs General-Purpose OS (Linux / Windows)","System Software",
     "General-purpose OS increases attack surface via unused services and kernel modules."),
    ("SS-2","Bootloader Without Secure Boot (GRUB / U-Boot)","System Software",
     "Bootloader does not verify kernel signature; unsigned OS images can be loaded."),
    ("SS-3","Supports OTA / Remote Firmware Updates","System Software",
     "Device accepts firmware updates over network interfaces."),
    ("SS-4","Virtualization or Container Support","System Software",
     "Containers / VMs increase attack surface via escape vulnerabilities."),
    ("SS-5","Third-Party / Open-Source Kernel Modules","System Software",
     "Unvetted third-party kernel code introduces unknown vulnerability exposure."),
    ("SS-6","No Hardware Root of Trust / Attestation","System Software",
     "No TPM, Secure Enclave, or hardware-backed firmware identity / attestation."),
    ("SS-7","Firmware Rollback Allowed","System Software",
     "Device can be downgraded to older firmware with known unpatched vulnerabilities."),
    ("SS-8","Interactive Shell / Console Accessible","System Software",
     "Command shell (serial console, SSH, Telnet) reachable at runtime without extra auth."),
    ("AS-1","Web-Based Management Interface (HTTP / HTTPS)","Application Software",
     "Embedded web server for configuration exposes HTTP-based attack surface."),
    ("AS-2","Uses a Database (SQL / SQLite)","Application Software",
     "SQL or embedded database susceptible to injection attacks if input unsanitised."),
    ("AS-3","Accepts Inputs from Untrusted Sources","Application Software",
     "Application parses external network data or files without strict validation."),
    ("AS-4","Written in Memory-Unsafe Language (C / C++)","Application Software",
     "C/C++ firmware susceptible to buffer overflows, use-after-free, format string bugs."),
    ("AS-5","No Code Signing / Binary Integrity Verification","Application Software",
     "Executables unsigned; modified binaries cannot be detected at load time."),
    ("AS-6","Default or Hardcoded Credentials Present","Application Software",
     "Device ships with default passwords or credentials embedded in firmware image."),
    ("AS-7","Relies on Unvetted Third-Party Libraries","Application Software",
     "OpenSSL, libmodbus, etc. with known CVEs present without active patching cadence."),
    ("AS-8","Logs Sensitive Data / No Log Integrity","Application Software",
     "Logs may contain credentials or keys; logs can be tampered to hide intrusion."),
    ("NP-1","IP Network Interface (Ethernet / Wi-Fi / LTE)","Networking",
     "IP connectivity enables remote access and all network-based attack categories."),
    ("NP-2","Legacy / Insecure Protocols (Telnet, FTP, HTTP, SNMPv1)","Networking",
     "Cleartext or unauthenticated protocols expose credentials and control data."),
    ("NP-3","Exposes Unauthenticated Network Services","Networking",
     "Open TCP/UDP ports accessible without any authentication."),
    ("NP-4","Serial / Fieldbus Interface (MVB, CAN, Modbus, IEC 61375)","Networking",
     "Train fieldbus protocols typically lack authentication and encryption."),
    ("NP-5","Wireless Interface (Wi-Fi, BT, ZigBee, LTE / 5G)","Networking",
     "Wireless extends physical attack surface beyond locked equipment rooms."),
    ("NP-6","No Network Segmentation / Directly Routable","Networking",
     "Device not behind firewall; directly reachable from untrusted network segments."),
    ("NP-7","Accepts Broadcast / Multicast Messages","Networking",
     "Processing broadcast traffic from any source enables spoofing or DoS."),
    ("NP-8","No TLS / Communicates in Cleartext","Networking",
     "Transmissions unencrypted and unauthenticated; enables eavesdropping and MITM."),
]

# Threat tuple fields:
# (tid, name, category, [triggering_props], attack_vector,
#  likelihood, consequence, iec42_refs, nist_ctrl, cra_ref, mitigation, priority)
THREATS = [
    # ── Hardware ──────────────────────────────────────────────────────────
    ("TID-101","Power/EM Side-Channel Analysis","Hardware",["HP-7","HP-8"],
     "Attacker measures power or EM emissions of crypto ops on wayside/onboard ECUs to extract private keys non-invasively.",
     "Low","Critical","FR 3 (CR 3.4 SW & Info Integrity)","SC-28, SI-7","Annex I(1)(e)",
     "Use crypto HW with DPA countermeasures. Apply EMI shielding to PCB. Use constant-time crypto implementations. Validate with FIPS 140-3.","High"),
    ("TID-105","Hardware Fault Injection – Control Flow","Hardware",["HP-7","HP-5"],
     "Voltage/clock glitching on SoC to bypass bootloader signature checks or skip authentication on safety computers.",
     "Low","Critical","FR 3 (CR 3.4), FR 2 (CR 2.4)","SI-7, AC-3","Annex I(1)(g)",
     "Use SoC glitch-detection sensors (brownout detectors). Apply tamper mesh enclosure. Store firmware in read-only flash segments.","High"),
    ("TID-106","Data Bus / DMA Interception","Hardware",["HP-4","HP-6"],
     "Rogue PCIe device inserted into gateway or SCADA server reads all host memory including crypto keys and ATC process data.",
     "Medium","Critical","FR 4 (CR 4.1 Info Confidentiality)","SC-8, AC-3","Annex I(1)(d)",
     "Enable IOMMU/VT-d to restrict DMA access. Disable unused PCIe/DMA slots. Deploy physical locks on expansion bays.","Critical"),
    ("TID-108","ROM/NVRAM Data Extraction","Hardware",["HP-2","HP-5"],
     "Chip-off or JTAG readout of NVRAM containing device keys, safety params, or credentials from trackside equipment.",
     "Medium","Critical","FR 4 (CR 4.1)","SC-28, MP-4","Annex I(1)(e)",
     "Encrypt all NVRAM with hardware-unique key (PUF/eFuse). Require authenticated challenge-response for readout. Log all debug-port access.","Critical"),
    ("TID-111","Untrusted External Storage Execution","Hardware",["HP-3"],
     "Malicious SD card injected into train datalogger auto-executes payload, installing backdoor or wiping safety event logs.",
     "High","High","FR 2 (CR 2.4), FR 3 (CR 3.4)","CM-7, SI-3","Annex I(1)(b)",
     "Disable auto-run/auto-mount. Require cryptographic signature on all media content. Restrict executable permissions on mount points.","High"),
    ("TID-113","Unverified Peripheral Firmware","Hardware",["HP-1","HP-3"],
     "Malicious firmware injected into a connected peripheral (modem, radio) which pivots into the main CBTC processor.",
     "Medium","High","FR 3 (CR 3.4)","SI-7, CM-5","Annex I(1)(c)",
     "Maintain whitelist of allowed peripheral firmware hashes. Verify peripheral firmware signature before enabling communication.","High"),
    ("TID-115","Firmware Extraction via HW Interface","Hardware",["HP-2"],
     "Full firmware extracted via JTAG/SPI enabling offline key extraction and targeted exploit development for fleet-wide attack.",
     "High","High","FR 4 (CR 4.1), FR 2 (CR 2.4)","MP-4, SC-28","Annex I(1)(e)",
     "Encrypt firmware at rest with device-unique key. Disable JTAG via eFuse blow in production. Apply conformal coating to PCB.","High"),
    ("TID-119","Latent Hardware Debug Port","Hardware",["HP-2"],
     "Production trackside device retains active JTAG/UART console allowing root shell or direct memory write without authentication.",
     "High","Critical","FR 2 (CR 2.4)","AC-3, CM-7","Annex I(1)(b)",
     "Mandatory eFuse/OTP blow of all debug interfaces before production. UART must require auth and log all sessions. Verify in FAT.","Critical"),
    # ── System Software ───────────────────────────────────────────────────
    ("TID-201","Inadequate Bootloader Verification","System Software",["SS-2","SS-6"],
     "U-Boot/GRUB without signature verification; attacker replaces kernel with malicious image achieving persistent root on train gateway.",
     "High","Critical","FR 3 (CR 3.4 SW Integrity)","SI-7, CM-3","Annex I(1)(g)",
     "Enable U-Boot verified boot with hardware-backed signing keys. Chain of trust: ROM→bootloader→kernel→rootfs. Enforce immutable SoC ROM.","Critical"),
    ("TID-202","Exploitable Network Stack CVEs","System Software",["SS-1","NP-1"],
     "Known Linux TCP/IP CVEs (TCP SACK Panic, etc.) exploited remotely against a connected wayside gateway causing DoS or privilege escalation.",
     "High","High","FR 7 (CR 7.1), FR 3","SI-2, SI-3","Annex I(1)(a)",
     "Maintain SBOM. Apply OS security patches per defined SLA. Harden sysctl (tcp_syncookies=1, icmp_echo_ignore_broadcasts=1).","High"),
    ("TID-203","Malicious Kernel Module Installed","System Software",["SS-1","SS-5"],
     "Attacker with foothold loads malicious LKM rootkit on SCADA Linux host, hiding processes and establishing covert C2 channel.",
     "Medium","Critical","FR 3 (CR 3.4)","SI-7, CM-5","Annex I(1)(g)",
     "Enable kernel module signing (CONFIG_MODULE_SIG_FORCE). Use IMA/EVM for integrity measurement. Restrict kprobes and /dev/mem access.","Critical"),
    ("TID-204","OS Privilege Escalation via Kernel","System Software",["SS-1"],
     "Unprivileged process escalates to ring-0 via kernel exploit (Dirty COW, etc.) on onboard Linux gaining full safety I/O driver access.",
     "Medium","Critical","FR 3, FR 2 (CR 2.1)","SI-7, AC-6","Annex I(1)(a)",
     "Apply grsecurity / SELinux MAC. Restrict ptrace (Yama). Drop unnecessary Linux capabilities. Enforce kernel CVE patch SLA.","Critical"),
    ("TID-210","Device Vulnerabilities Unpatchable","System Software",["SS-1","SS-6"],
     "EOL embedded OS with known CVEs cannot receive patches; CBTC wayside equipment permanently vulnerable with no compensating controls.",
     "High","High","FR 3, FR 7","SA-22, MA-2","Annex I(2)(a)",
     "Define and disclose EoS date. Implement OTA update from Day 1. Maintain SBOM. Apply network isolation as compensating control for EOL devices.","High"),
    ("TID-211","Unauthenticated Firmware Installation","System Software",["SS-3"],
     "Update interface accepts unsigned firmware over TFTP/HTTP; attacker on CBTC subnet flashes malicious code to any reachable device.",
     "High","Critical","FR 3 (CR 3.4)","SI-7, CM-3","Annex I(2)(b)",
     "Enforce cryptographic signature verification (RSA-4096 or ECC P-384) for all FW images. Require authenticated session. Log all update events.","Critical"),
    ("TID-213","Faulty Firmware Integrity Verification","System Software",["SS-3"],
     "Update verification uses MD5/CRC only; MitM attacker modifies firmware package without triggering any rejection at device.",
     "Medium","High","FR 3 (CR 3.4)","SI-7","Annex I(2)(b)",
     "Replace checksum-only with ECDSA/RSA signature over the entire firmware image. Store signing key in an offline HSM.","High"),
    ("TID-215","Unencrypted Firmware Updates","System Software",["SS-3","NP-8"],
     "Firmware packages transmitted in cleartext over maintenance network expose internals and allow repackaging with malicious payload.",
     "Medium","High","FR 4 (CR 4.1), FR 3","SC-8, SC-28","Annex I(1)(d)",
     "Encrypt firmware packages with AES-256-GCM in transit and at rest. Use TLS 1.2+ for update transport channel.","High"),
    ("TID-216","Firmware Update Rollback","System Software",["SS-3","SS-7"],
     "Attacker downgrades onboard computer to patched-away vulnerable firmware version, re-enabling a previously fixed RCE vulnerability.",
     "Medium","High","FR 3 (CR 3.4)","SI-7, CM-5","Annex I(2)(c)",
     "Implement anti-rollback monotonic counter in secure storage (eFuse or TPM). Reject firmware with version below counter value.","High"),
    ("TID-218","OS Susceptible to Rootkit","System Software",["SS-1","SS-5"],
     "Persistent rootkit on SCADA or onboard Linux survives reboots via compromised init scripts, hiding attacker presence during IR.",
     "Medium","Critical","FR 3 (CR 3.4)","SI-7, IR-5","Annex I(1)(g)",
     "Implement measured boot with TPM PCR validation. Deploy FIM (AIDE/Tripwire). Use read-only overlayFS for system partitions.","Critical"),
    ("TID-219","OS/Kernel Privilege Escalation","System Software",["SS-1"],
     "Local process exploits kernel CVE to gain root on onboard embedded Linux, gaining full control of safety-critical driver functions.",
     "High","Critical","FR 3, FR 2 (CR 2.1)","SI-2, AC-6","Annex I(1)(a)",
     "Apply all critical kernel CVE patches within 30 days. Enable SMEP, SMAP, KASLR. Apply seccomp-bpf profiles per service.","Critical"),
    ("TID-221","Authentication Bypass via Message Replay","System Software",["SS-3","NP-8"],
     "Captured legitimate firmware or authentication response replayed to bypass device authentication and gain unauthorized access.",
     "Medium","High","FR 1 (CR 1.3 Authenticator Mgmt)","IA-3, SC-8","Annex I(1)(d)",
     "Implement challenge-response authentication with nonces. Use timestamps and sequence numbers. Apply strict anti-replay window logic.","High"),
    ("TID-224","Excessive Access via Diagnostic Features","System Software",["SS-8"],
     "Software diagnostic interface left active in production grants low-privilege operators elevated access to device internals.",
     "High","High","FR 2 (CR 2.4), FR 1","AC-3, CM-7","Annex I(1)(b)",
     "Disable or remove all diagnostic endpoints in production builds. Require authenticated + time-limited debug sessions with full audit trail.","High"),
    ("TID-225","Log Manipulation / Erasure","System Software",["SS-8","AS-8"],
     "Attacker with foothold clears or falsifies syslog on wayside controller to hide intrusion evidence and prolong dwell time before detection.",
     "High","High","FR 6 (CR 6.1 Audit Log)","AU-9, AU-10","Annex I(1)(h)",
     "Forward logs in real-time to an immutable remote syslog server over TLS. Apply WORM policy to local logs. Monitor log pipeline integrity.","High"),
    # ── Application Software ──────────────────────────────────────────────
    ("TID-301","Application Binary Modification","Application Software",["AS-4","AS-5"],
     "Attacker replaces unsigned application binary with trojanized version after gaining file-system write access via another vulnerability.",
     "Medium","High","FR 3 (CR 3.4), FR 2","SI-7, CM-5","Annex I(1)(g)",
     "Enable code signing for all binaries. Implement dm-verity or IMA/EVM on embedded Linux. Run integrity checks at startup and via cron.","High"),
    ("TID-302","Untrusted Application Installation","Application Software",["AS-5","SS-1"],
     "Maintenance staff install an unapproved diagnostic app on onboard device that exfiltrates telemetry or opens a reverse shell via LTE.",
     "High","High","FR 2 (CR 2.4), FR 3","CM-7, CM-11","Annex I(1)(b)",
     "Implement application whitelisting. Block package installation from sources other than the signed OEM repository. Audit installed packages regularly.","High"),
    ("TID-304","Runtime Environment Manipulation","Application Software",["AS-3"],
     "Attacker manipulates env vars, shared libs (LD_PRELOAD), or config files at runtime to alter safety-critical application behaviour on train units.",
     "Medium","High","FR 3 (CR 3.4)","SI-7, CM-5","Annex I(1)(g)",
     "Mount application dirs read-only. Use secure path lookups. Audit library load paths. Apply AppArmor/SELinux profiles per process.","High"),
    ("TID-310","Unauthenticated Network Service","Application Software",["AS-6","NP-3"],
     "Open TCP service (Modbus/502, DNP3/20000, config port) accessible without credentials allows any subnet device to reconfigure safety targets.",
     "High","Critical","FR 1 (CR 1.1), FR 5","IA-2, AC-17","Annex I(1)(f)",
     "Remove or firewall all unauthenticated services. Require mutual auth on all remote management interfaces. Conduct port-scan audit in FAT/SAT.","Critical"),
    ("TID-311","Default Credentials","Application Software",["AS-6"],
     "Device ships with known default credentials (admin/admin, root/root) found in public manuals; not changed at commissioning in depot.",
     "High","Critical","FR 1 (CR 1.5 Authenticator Mgmt)","IA-5, IA-2","Annex I(1)(f)",
     "Generate unique per-device credentials at manufacturing. Force password change on first login. EU CRA mandates no default credentials.","Critical"),
    ("TID-314","Brute-Force Password Attack","Application Software",["AS-6"],
     "Automated credential stuffing against web/SSH management port of trackside device eventually gains access due to no lockout policy.",
     "High","High","FR 1 (CR 1.11 Unsuccessful Logins)","AC-7, IA-5","Annex I(1)(f)",
     "Account lockout after ≤5 failed attempts. Rate limiting and IP blocking. Require MFA for remote admin. Minimum 12-char complex passwords.","High"),
    ("TID-316","Certificate Verification Bypass","Application Software",["NP-1","AS-6"],
     "Embedded app accepts self-signed/expired TLS certs without validation; MitM decrypts and intercepts credentials and ATC control commands.",
     "Medium","High","FR 1 (CR 1.9 PKI Auth)","IA-3, SC-8","Annex I(1)(d)",
     "Enforce strict certificate chain validation. Pin CAs for critical endpoints. Reject expired/revoked certs. Maintain CRL/OCSP checking.","High"),
    ("TID-317","Predictable Cryptographic Key","Application Software",["AS-4"],
     "AES/RSA keys generated from predictable seed (timestamp, device ID) in C code during first boot; keys guessable from provisioning metadata.",
     "Medium","Critical","FR 4 (CR 4.3 Cryptography)","SC-12, SC-13","Annex I(1)(e)",
     "Use hardware TRNG for all key generation. Validate entropy quality (NIST SP 800-90B). Derive keys from hardware PUF where available.","Critical"),
    ("TID-318","Insecure Cryptographic Implementation","Application Software",["AS-4"],
     "Firmware uses ECB-mode AES, 1024-bit RSA, or custom crypto for safety messages; provides no semantic security against passive observers.",
     "High","High","FR 4 (CR 4.3)","SC-13, SC-8","Annex I(1)(e)",
     "Use only NIST-approved algorithms: AES-256-GCM, ECDH P-384, SHA-384+. Mandate crypto agility for future upgrades. Conduct external cryptographic audit.","High"),
    ("TID-319","Cross-Site Scripting (XSS)","Application Software",["AS-1","AS-3"],
     "Reflected XSS in embedded web management of PIS or gateway steals session cookies and hijacks authenticated maintainer's admin session.",
     "Medium","Medium","FR 1, FR 2 (CR 2.1)","SI-10, SC-18","Annex I(1)(c)",
     "Implement Content-Security-Policy headers. Use output encoding. Validate all server-side inputs. Use templating engine with auto-escaping.","Medium"),
    ("TID-320","SQL Injection","Application Software",["AS-2","AS-3"],
     "SQL injection in event log query of train datalogger dumps entire database including maintenance credentials and safety fault history.",
     "Medium","High","FR 4 (CR 4.1), FR 1","SI-10","Annex I(1)(c)",
     "Use parameterised queries exclusively. Apply least-privilege DB user permissions. Validate all user-supplied input strictly.","High"),
    ("TID-321","HTTP Session Hijacking","Application Software",["AS-1","NP-2"],
     "Session tokens sent over HTTP or without Secure/HttpOnly flags stolen via network sniffing on unencrypted CBTC maintenance network.",
     "High","High","FR 1 (CR 1.1), FR 4","SC-8, AC-12","Annex I(1)(d)",
     "Enforce HTTPS-only (HSTS). Set Secure, HttpOnly, SameSite=Strict on session cookies. Rotate tokens on privilege change. 15-min idle timeout.","High"),
    ("TID-322","Cross-Site Request Forgery (CSRF)","Application Software",["AS-1"],
     "Malicious page forces authenticated admin browser to issue unauthorised config change to device web interface such as ATC zone boundary changes.",
     "Medium","High","FR 2 (CR 2.1)","SC-8, SI-10","Annex I(1)(c)",
     "Implement CSRF tokens (Synchroniser Token Pattern) on all state-changing endpoints. Validate Origin/Referer headers. Use SameSite cookies.","Medium"),
    ("TID-327","Out-of-Bounds Memory Access","Application Software",["AS-4"],
     "Buffer overflow in C/C++ firmware parsing Modbus, IEC 61850, or MVB frames leads to arbitrary code execution on safety-critical processors.",
     "High","Critical","FR 7 (CR 7.1), FR 3 (CR 3.4)","SI-16, SI-2","Annex I(1)(a)",
     "Enable stack canaries, ASLR, NX/DEP, SafeStack. Apply MISRA C / CERT C rules. Fuzz-test all protocol parsers. Consider Rust for new code.","Critical"),
    ("TID-328","Hardcoded Credentials in Firmware","Application Software",["AS-6"],
     "Hard-coded password/API key found in CBTC radio firmware via reverse engineering; provides backdoor access to entire radio subsystem network.",
     "High","Critical","FR 1 (CR 1.5)","IA-5, CM-5","Annex I(1)(f)",
     "Audit codebase for hardcoded secrets (truffleHog, semgrep). Store credentials in secure provisioning store. Use per-device certificates only.","Critical"),
    ("TID-329","Improper Password Storage","Application Software",["AS-6"],
     "Passwords stored as MD5 hashes or plaintext in config files on embedded gateway; a single file-read vulnerability exposes all credentials.",
     "Medium","High","FR 1 (CR 1.5)","IA-5","Annex I(1)(f)",
     "Store passwords using bcrypt/scrypt/Argon2 with per-user salts. Never store plaintext. chmod 0600 credential files. Prefer certificate-based auth.","High"),
    # ── Networking ────────────────────────────────────────────────────────
    ("TID-401","Undocumented Protocol Feature","Networking",["NP-4","NP-2"],
     "Hidden diagnostic mode in MVB/CAN/IEC 61375 implementation activated by undocumented frame gives unauthenticated control over train functions.",
     "Medium","Critical","FR 5 (CR 5.1), FR 1","AC-4, CM-7","Annex I(1)(c)",
     "Document and audit all protocol message types including vendor extensions. Implement strict message whitelisting in train comms gateway.","Critical"),
    ("TID-404","Remote-Triggered DoS / Deadlock","Networking",["NP-1","NP-3"],
     "Crafted packet or flood causes CBTC wayside controller to freeze requiring manual restart, halting train operations across affected segment.",
     "High","Critical","FR 7 (CR 7.1 DoS Protection)","SC-5, CP-10","Annex I(1)(h)",
     "Implement rate limiting and connection throttling. Watchdog timer for process health. Fail-safe state on loss of communication. Load test in FAT.","Critical"),
    ("TID-405","Network Resource Exhaustion","Networking",["NP-6"],
     "SYN/UDP flood from compromised device on CBTC IP network exhausts memory/CPU on wayside controllers triggering fleet-wide fail-safe stop.",
     "High","Critical","FR 7 (CR 7.1)","SC-5, CP-7","Annex I(1)(h)",
     "Deploy OT-zone firewalls and IDS/IPS. Implement TCP SYN cookies. Apply ingress filtering. QoS policies to prioritise safety-critical traffic.","Critical"),
    ("TID-406","Spoofed Bus Control Messages","Networking",["NP-4","NP-7"],
     "Attacker injects spoofed MVB or IEC 61375 movement authority telegrams on train bus causing erroneous speed or door open/close commands.",
     "Medium","Critical","FR 1 (CR 1.3), FR 3","IA-3, SC-8","Annex I(1)(d)",
     "Implement HMAC-based message auth on all safety-critical bus telegrams. Source-address validation and sequence numbering. OT IDS for bus anomalies.","Critical"),
    ("TID-407","Message Replay Attack","Networking",["NP-4","NP-8"],
     "Captured MVB/Modbus command replayed causing unsafe re-execution (e.g., door-open command while train moving) on critical subsystems.",
     "Medium","Critical","FR 1 (CR 1.3), FR 3 (CR 3.7)","SC-8, IA-3","Annex I(1)(d)",
     "Include monotonically increasing sequence numbers and timestamps in all safety messages. Reject messages outside an acceptable anti-replay window.","Critical"),
    ("TID-408","Unencrypted Data in Transit","Networking",["NP-8"],
     "Maintenance credentials, location data, ATC parameters, or CCTV feeds transmitted in cleartext over Wi-Fi/Ethernet; captured by passive observer.",
     "High","High","FR 4 (CR 4.1)","SC-8, SC-28","Annex I(1)(d)",
     "Mandate TLS 1.2+ or IPsec for all IP comms. Use DTLS for UDP protocols. Prohibit Telnet, FTP, SNMPv1/v2c on any management interface.","High"),
    ("TID-411","Weak Cryptographic Protocol","Networking",["NP-8","NP-2"],
     "Device uses SSL 3.0, TLS 1.0, or RC4/3DES cipher suites; POODLE/BEAST attacks decrypt CBTC or maintenance session traffic.",
     "High","High","FR 4 (CR 4.3)","SC-8, SC-13","Annex I(1)(e)",
     "Disable TLS < 1.2. Allow only strong cipher suites (AES-GCM, CHACHA20-POLY1305). Enable PFS (ECDHE). Validate with TLS scanner in SAT.","High"),
    ("TID-412","Wireless Routing Abuse / Rogue AP","Networking",["NP-5","NP-6"],
     "Attacker deploys rogue AP in station that wins association from CBTC radio units or passenger Wi-Fi, routing all traffic through attacker node.",
     "Medium","High","FR 5 (CR 5.1), FR 1","AC-4, IA-3","Annex I(1)(b)",
     "Use 802.1X/EAP-TLS for all Wi-Fi authentication. Deploy WIDS. Pin BSSID/SSID of authorised APs. Use VPN tunnel over all wireless links.","High"),
    # ── Additional Hardware Threats ───────────────────────────────────────
    ("TID-102","Electromagnetic Analysis Side Channel","Hardware",["HP-7","HP-8"],
     "Attacker captures EM radiation from GPIO toggling or bus activity on wayside embedded CPUs during cryptographic operations to recover secret key material.",
     "Low","High","FR 3 (CR 3.4), FR 4 (CR 4.3)","SC-28, SI-7","Annex I(1)(e)",
     "Apply EM shielding (copper/aluminium enclosure, ferrite beads). Use randomised clock jitter in crypto execution. Separate crypto HW from high-frequency I/O lines.","High"),
    ("TID-103","Microarchitectural Side Channels","Hardware",["HP-7","HP-8"],
     "Spectre/Meltdown-class CPU vulnerabilities exploited on embedded SoC or server-grade CPUs in SCADA/CBTC gateways to leak cross-process memory including keys or PII.",
     "Low","Critical","FR 4 (CR 4.1), FR 3","SI-2, SC-28","Annex I(1)(a)",
     "Apply CPU microcode/firmware updates for Spectre/Meltdown mitigations. Enable kernel page-table isolation (KPTI). Isolate safety-critical processes to dedicated cores.","Critical"),
    ("TID-109","RAM Chip Contents Readout","Hardware",["HP-2","HP-5","HP-6"],
     "Attacker with physical access freezes DRAM module (cold-boot attack) and reads volatile memory contents including encryption keys, session tokens, and process state from onboard computers.",
     "Low","Critical","FR 4 (CR 4.1)","SC-28, MP-4","Annex I(1)(e)",
     "Use DRAM with built-in encryption (e.g., AMD SME/SEV). Implement memory scrubbing at shutdown. Restrict physical access to DRAM slots. Use SoCs with integrated encrypted RAM.","High"),
    ("TID-110","Hardware Fault Injection – Data Manipulation","Hardware",["HP-7","HP-5"],
     "Targeted voltage glitching on data paths causes specific bit-flips in safety-parameter memory (speed limits, zone boundaries) without triggering software detection.",
     "Low","Critical","FR 3 (CR 3.4)","SI-7, SI-16","Annex I(1)(g)",
     "Store safety-critical parameters with redundancy and CRC integrity checks. Use ECC RAM. Implement cross-check between primary and shadow copies. Apply tamper-detection sensors.","Critical"),
    ("TID-116","Latent Privileged Access Port","Hardware",["HP-2"],
     "A secondary, undocumented JTAG or proprietary access port present alongside the disabled primary debug interface allows direct device control, bypassing standard security controls.",
     "Medium","Critical","FR 2 (CR 2.4)","AC-3, CM-7","Annex I(1)(b)",
     "Audit PCB schematic for all test points and access ports. Disable, encapsulate, or remove all debug headers in production board variants. Validate in factory acceptance test.","Critical"),
    # ── Additional System Software Threats ────────────────────────────────
    ("TID-205","Existing OS Tools Abused (Living off the Land)","System Software",["SS-1","SS-8"],
     "Attacker with foothold on onboard Linux leverages native tools (bash, netcat, dd, python3) for lateral movement, data exfiltration, and persistence without deploying custom malware.",
     "High","High","FR 2 (CR 2.4), FR 3","CM-7, CM-11","Annex I(1)(g)",
     "Apply application whitelisting (AppArmor exec profiles). Restrict bash, python, netcat to maintenance accounts only. Remove unnecessary interpreters from production OS image.","High"),
    ("TID-206","Memory Management Protections Subverted","System Software",["SS-1","AS-4"],
     "Exploit bypasses ASLR, stack canaries, or NX by exploiting information leaks or heap-spray techniques to gain reliable code execution on embedded Linux gateway.",
     "Medium","Critical","FR 3 (CR 3.4), FR 7","SI-16, SI-2","Annex I(1)(a)",
     "Enable all available mitigations: ASLR, PIE, stack canaries, RELRO, SafeStack. Use CFI (Control Flow Integrity) on critical binaries. Enforce seccomp-bpf syscall filters.","Critical"),
    ("TID-207","Container Escape","System Software",["SS-4"],
     "Attacker compromises a containerised CBTC microservice and exploits a container runtime CVE (runc, containerd) to escape to the host kernel of a safety gateway.",
     "Medium","Critical","FR 3 (CR 3.4)","SI-7, CM-6","Annex I(1)(a)",
     "Use rootless containers. Apply kernel seccomp and AppArmor profiles to containers. Avoid privileged containers. Keep container runtime up-to-date with CVE patches. Use gVisor/Kata.","Critical"),
    ("TID-212","FW Update Integrity Secret Extraction","System Software",["SS-3","SS-6"],
     "Shared symmetric key used to verify firmware update packages extracted from one device and reused to sign and push malicious firmware to every device on the fleet.",
     "Medium","Critical","FR 3 (CR 3.4)","SC-12, SI-7","Annex I(2)(b)",
     "Use asymmetric signing (private key never leaves HSM). Never embed verification keys with write or update privileges. Use per-device or per-batch signatures.","Critical"),
    ("TID-214","Secrets Extracted from HW Root of Trust","System Software",["SS-6"],
     "Side-channel or fault-injection attack against TPM or Secure Enclave extracts the device identity key, allowing impersonation of any fleet device in the CBTC back-office.",
     "Low","Critical","FR 4 (CR 4.3), FR 3","SC-12, IA-3","Annex I(1)(e)",
     "Use FIPS 140-3 Level 3+ certified TPM. Enable TPM dictionary attack protection. Monitor for PCR value anomalies. Apply device attestation verification at server side.","Critical"),
    ("TID-217","Remote Update Initiation Causes DoS","System Software",["SS-3","NP-1"],
     "Attacker repeatedly triggers the OTA update process on a wayside controller causing repeated restarts and unavailability of safety-critical signalling functions during update windows.",
     "High","High","FR 7 (CR 7.1), FR 3","CP-10, SC-5","Annex I(2)(a)",
     "Authenticate and rate-limit all update initiation requests. Implement update scheduling during maintenance windows only. Enforce minimum interval between update attempts.","High"),
    ("TID-222","Critical System Service Disabled","System Software",["SS-1","SS-8"],
     "Attacker disables a critical system service (firewall daemon, integrity monitor, logging agent) via systemctl or kill, removing a key security control silently.",
     "High","High","FR 7 (CR 7.1), FR 6 (CR 6.1)","CP-10, AU-9","Annex I(1)(h)",
     "Configure critical services as non-killable (systemd ProtectSystem/ProtectKernelModules). Use watchdog processes that restart security services. Alert on unexpected service stops.","High"),
    ("TID-223","System Susceptible to RAM Scraping","System Software",["SS-1"],
     "Malicious process or kernel module scrapes process memory of safety-critical applications to extract keys, tokens, or ATC parameters without triggering file-system-based detections.",
     "Medium","High","FR 4 (CR 4.1), FR 3","SC-28, SI-7","Annex I(1)(e)",
     "Enable Yama ptrace scope (kernel.yama.ptrace_scope=2). Use memory-safe key storage (kernel keyring). Encrypt sensitive in-memory data. Apply process isolation with namespaces.","High"),
    ("TID-226","Device Leaks Security Info in Logs","System Software",["SS-8","AS-8"],
     "Device logs contain authentication tokens, private key material, raw ATC commands, or operator passwords in plaintext, readable by any process with log access on a compromised device.",
     "High","High","FR 4 (CR 4.1), FR 6","AU-3, AU-9","Annex I(1)(h)",
     "Implement log sanitisation to redact secrets before writing. Never log raw cryptographic material. Apply structured logging with scrubbing middleware. Regularly audit log content in CI.","High"),
    # ── Additional Application Software Threats ───────────────────────────
    ("TID-303","Excessive Trust in Offboard Management Software","Application Software",["AS-5","SS-1"],
     "Engineering workstation or IDE tool trusted unconditionally by the embedded device; attacker compromises the tool to push malicious configurations or backdoored code to the entire fleet.",
     "Medium","Critical","FR 3 (CR 3.4), FR 2 (CR 2.4)","SI-7, CM-3","Annex I(1)(g)",
     "Authenticate management tools with device-side certificate verification. Require dual-person integrity for fleet-wide configuration pushes. Sign all configuration files.","Critical"),
    ("TID-305","Dangerous System Calls from Application","Application Software",["AS-4","SS-1"],
     "Application firmware executes dangerous system calls (execve, ptrace, mmap with RWX) that could be abused by an attacker with partial code control to escalate privileges.",
     "High","High","FR 2 (CR 2.4), FR 3","CM-7, SI-2","Annex I(1)(a)",
     "Apply seccomp-bpf profiles to whitelist only necessary syscalls. Use static analysis tools to detect dangerous syscall usage. Enforce least-privilege execution contexts.","High"),
    ("TID-306","Sandboxed Environment Escape","Application Software",["SS-4","AS-4"],
     "Application breaks out of a chroot jail, seccomp sandbox, or namespace boundary on an embedded Linux gateway, gaining access to the host filesystem and system calls.",
     "Medium","Critical","FR 3 (CR 3.4), FR 2","SI-7, CM-7","Annex I(1)(g)",
     "Use multiple defence-in-depth confinement layers: namespaces + seccomp + AppArmor. Avoid chroot as sole confinement. Audit sandbox configuration against escape techniques.","Critical"),
    ("TID-309","Device Exploits Engineering Workstation","Application Software",["AS-3","NP-1"],
     "Compromised embedded device (e.g., train datalogger) sends crafted data over the maintenance interface that triggers a vulnerability in the engineering PC's parsing software.",
     "Medium","High","FR 3 (CR 3.4), FR 5","SI-7, SI-10","Annex I(1)(c)",
     "Harden engineering workstations with endpoint protection. Validate and sanitise all device-originated data before parsing. Use isolated maintenance network (air-gap or VPN-only).","High"),
    ("TID-312","Credential Change Mechanism Abused","Application Software",["AS-6","NP-3"],
     "Password-change API or web form accessible without re-authentication allows any authenticated low-privilege user (or unauthenticated attacker) to change admin credentials on the device.",
     "High","Critical","FR 1 (CR 1.5), FR 2","IA-5, AC-3","Annex I(1)(f)",
     "Require current password or step-up MFA for all credential change operations. Rate-limit and log all credential change requests. Apply CSRF protection on change endpoints.","Critical"),
    ("TID-315","Password Retrieval Mechanism Abused","Application Software",["AS-6","AS-1"],
     "'Forgot password' or recovery mechanism on embedded web interface exploited via predictable token, unauthenticated endpoint, or email interception to reset admin credentials.",
     "Medium","High","FR 1 (CR 1.5), FR 1 (CR 1.11)","IA-5","Annex I(1)(f)",
     "Implement time-limited (15 min), cryptographically random recovery tokens. Restrict recovery to registered out-of-band channel. Notify account owner of recovery attempts. Log all events.","High"),
    ("TID-323","Path Traversal","Application Software",["AS-1","AS-3"],
     "Path traversal (../../etc/passwd) in embedded web server's file download or log-view endpoint allows an attacker to read arbitrary files including credentials or private keys.",
     "Medium","High","FR 4 (CR 4.1), FR 2","SI-10, AC-3","Annex I(1)(c)",
     "Canonicalise and validate all file paths server-side. Jail file operations to designated directories (chdir + open). Block path components containing '..' before processing.","High"),
    ("TID-326","Insecure Deserialization","Application Software",["AS-3","AS-4"],
     "Device deserialises untrusted data (JSON, Protobuf, XML) from a CBTC back-office message bus without integrity checking, leading to object injection or remote code execution.",
     "Medium","Critical","FR 3 (CR 3.4), FR 7","SI-10, SI-16","Annex I(1)(a)",
     "Validate and sanitise all serialised input before deserialisation. Prefer simple data formats (JSON with schema validation) over complex binary serialisers. Use integrity-checked channels.","Critical"),
    ("TID-330","Cryptographic Timing Side-Channel","Application Software",["AS-4"],
     "Non-constant-time comparison of HMACs or password hashes in embedded authentication code allows a remote attacker to recover secrets via timing oracle over the CBTC IP network.",
     "Medium","High","FR 4 (CR 4.3), FR 1","SC-13, IA-5","Annex I(1)(e)",
     "Use constant-time comparison functions (CRYPTO_memcmp, hmac_equal). Never use standard == for comparing secrets. Verify with timing-analysis tools in automated test suite.","High"),
    # ── Additional Networking Threats ─────────────────────────────────────
    ("TID-410","Cryptographic Protocol Side Channel","Networking",["NP-8","NP-1"],
     "Lucky-13 or BEAST-style timing attack against TLS implementation on CBTC back-office server allows decryption of session data from a passive network observer position.",
     "Low","High","FR 4 (CR 4.3)","SC-8, SC-13","Annex I(1)(e)",
     "Disable CBC-mode cipher suites vulnerable to Lucky-13. Use AEAD-only cipher suites (AES-GCM, CHACHA20-POLY1305). Enable TLS 1.3 which eliminates these attacks by design.","High"),
    # ── Final 10 Missing EMB3D Threats ──────────────────────────────────────
    # Hardware
    ("TID-107","Unauthorized Direct Memory Access (DMA)","Hardware",["HP-4"],
     "Malicious device or rogue PCIe card performs DMA to read/write host memory without CPU involvement, extracting safety parameter tables or injecting code on the CBTC gateway.",
     "Medium","Critical","FR 4 (CR 4.1), FR 2 (CR 2.4)","AC-3, SC-28","Annex I(1)(d)",
     "Enable IOMMU (Intel VT-d / ARM SMMU) to restrict DMA regions per device. Disable hot-plug on unused PCIe slots. Apply physical port locks on production boards.","Critical"),
    ("TID-114","Peripheral Data Bus Interception","Hardware",["HP-4","HP-1"],
     "Attacker taps into SPI, I²C, or internal parallel bus between SoC and peripherals (crypto chip, EEPROM) on exposed PCB to sniff keys, configs, or safety parameters.",
     "Medium","High","FR 4 (CR 4.1)","SC-8, SC-28","Annex I(1)(d)",
     "Encrypt all inter-chip buses (encrypted SPI, secure I²C). Apply conformal PCB coating. Use BGA packages to restrict probe access. Place critical buses on internal PCB layers.","High"),
    ("TID-118","Weak Peripheral Port Electrical Damage Protection","Hardware",["HP-1","HP-5"],
     "Intentional overvoltage or ESD injection on exposed USB, serial, or Ethernet ports destroys I/O circuitry or causes latchup, rendering a wayside controller permanently inoperable.",
     "Medium","High","FR 7 (CR 7.1), FR 3","PE-18, SC-5","Annex I(1)(h)",
     "Apply TVS diodes and ESD protection on all external-facing ports to IEC 61000-4-5 / EN 50155 levels. Galvanic isolation on serial and Ethernet. Fuse protection on USB power lines.","High"),
    # System Software
    ("TID-208","Virtual Machine Escape","System Software",["SS-4"],
     "Attacker compromises a guest VM running a non-critical service on a CBTC server and exploits a hypervisor vulnerability (QEMU, KVM) to escape into the host or adjacent safety-critical VMs.",
     "Low","Critical","FR 3 (CR 3.4), FR 2","SI-7, CM-6","Annex I(1)(a)",
     "Apply all hypervisor security patches. Use Type-1 hypervisors with minimal attack surface. Apply VM isolation with IOMMU passthrough. Disable unnecessary virtual devices per guest.","Critical"),
    ("TID-209","Host Can Manipulate Guest Virtual Machines","System Software",["SS-4"],
     "Compromised hypervisor host modifies memory or storage of guest safety VMs, injecting malicious code or altering safety parameters without guest-side detection.",
     "Medium","Critical","FR 3 (CR 3.4), FR 4","SI-7, AC-6","Annex I(1)(g)",
     "Use measured/trusted boot for hypervisor. Apply integrity monitoring on guest disk images. Consider confidential computing (AMD SEV, Intel TDX) for safety VMs. Restrict host admin access.","Critical"),
    ("TID-220","Unpatchable Hardware Root of Trust","System Software",["SS-6"],
     "A vulnerability discovered in a non-updatable hardware root of trust (ROM bootloader, eFuse-locked firmware) cannot be patched, leaving the device permanently vulnerable to bypass.",
     "Low","Critical","FR 3 (CR 3.4), FR 7","SA-22, SI-7","Annex I(2)(a)",
     "Design ROM bootloader as minimal and formally verifiable. Implement a secondary updatable bootloader stage. Document mitigations for irrecoverable ROM vulnerabilities in SBOM.","Critical"),
    # Application Software
    ("TID-307","Device Code Representations Inconsistent","Application Software",["AS-5","AS-4"],
     "Compiled binary on the embedded device does not match the source code in version control; undetected supply-chain tampering during build introduces backdoored libraries.",
     "Medium","High","FR 3 (CR 3.4)","SI-7, CM-3","Annex I(1)(g)",
     "Implement reproducible builds. Verify binary hash after compilation against deterministic build. Use CI/CD with SLSA Level 3+ provenance. Sign build artefacts with an offline HSM.","High"),
    ("TID-308","Code Overwritten to Avoid Detection","Application Software",["AS-4","AS-5"],
     "Malware on an embedded device overwrites or modifies its own code in flash after execution to remove artefacts, preventing forensic analysis and evading integrity-verification scans.",
     "Medium","High","FR 3 (CR 3.4), FR 6","SI-7, IR-4","Annex I(1)(g)",
     "Mount code partitions as read-only (overlayFS). Enable dm-verity for block-level integrity. Capture pre-boot hashes in TPM PCR. Implement remote attestation to detect any deviation.","High"),
    ("TID-313","Unauthenticated Session Changes Credential","Application Software",["AS-6","NP-3"],
     "An unauthenticated or session-hijacked request to the embedded web or API interface changes the device admin password, locking out legitimate operators and giving the attacker full control.",
     "High","Critical","FR 1 (CR 1.5), FR 2 (CR 2.1)","IA-5, AC-3","Annex I(1)(f)",
     "Require current valid credentials for any password/credential change. Enforce session binding with anti-CSRF tokens. Rate-limit credential operations. Alert on all credential changes.","Critical"),
    ("TID-324","HTTP Direct Object Reference (IDOR)","Application Software",["AS-1","AS-3"],
     "Embedded web interface uses predictable resource identifiers (e.g., /api/device/1, /log/2) without access control; attacker enumerates and accesses other users' data or device configs.",
     "Medium","High","FR 2 (CR 2.1), FR 4","AC-3, SI-10","Annex I(1)(c)",
     "Implement object-level access control checks on every request. Use non-guessable identifiers (UUIDs). Apply role-based authorisation at API layer. Log and alert on enumeration patterns.","High"),
]

# IEC 62443-4-2 Fundamental Requirements


FR_MAP = {
    "FR 1": {"name": "Identification & Authentication Control", "cr": "CR 1.1–1.14",
             "sl1": "Human user ID + password",          "sl2": "MFA for all remote access",
             "sl3": "Hardware token / PKI certificates", "sl4": "Biometric + HW token + PAW"},
    "FR 2": {"name": "Use Control", "cr": "CR 2.1–2.13",
             "sl1": "Role-based access + audit logs",        "sl2": "Dual approval for critical ops",
             "sl3": "Mandatory Access Control (SELinux/MAC)", "sl4": "Privileged Access Workstation + review"},
    "FR 3": {"name": "System Integrity", "cr": "CR 3.1–3.14",
             "sl1": "Software updates available",             "sl2": "Code signing for all FW/SW",
             "sl3": "Verified boot + runtime integrity",      "sl4": "HW-rooted integrity measurement (TPM)"},
    "FR 4": {"name": "Data Confidentiality", "cr": "CR 4.1–4.3",
             "sl1": "Encryption of data at rest",             "sl2": "TLS for data in transit",
             "sl3": "End-to-end encryption + key management", "sl4": "Classified data handling + HSM"},
    "FR 5": {"name": "Restricted Data Flow", "cr": "CR 5.1–5.4",
             "sl1": "Network segmentation defined",           "sl2": "Conduit firewalls deployed",
             "sl3": "Unidirectional gateways for OT zones",  "sl4": "Verified data diode for safety networks"},
    "FR 6": {"name": "Timely Response to Events", "cr": "CR 6.1–6.2",
             "sl1": "Logging enabled on device",             "sl2": "SIEM alerts configured",
             "sl3": "24/7 SOC monitoring + alerting",        "sl4": "Automated response + threat intel feeds"},
    "FR 7": {"name": "Resource Availability", "cr": "CR 7.1–7.8",
             "sl1": "Basic redundancy defined",              "sl2": "DoS protection mechanisms in place",
             "sl3": "Tested failover + recovery procedures", "sl4": "N+2 redundancy + DDoS mitigation"},
}

CATALOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_catalog.json")


class ThreatModelApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Rail & Transit EMB3D TARA Tool  |  MITRE EMB3D™ · IEC 62443 · NIST 800-82 · EU CRA")
        self.root.geometry("1300x820")
        self.root.minsize(1100, 700)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook.Tab",  padding=[14, 6], font=("Segoe UI", 9, "bold"))
        style.configure("Hdr.TLabel",     font=("Segoe UI", 9, "bold"))
        style.configure("Title.TLabel",   font=("Segoe UI", 11, "bold"), foreground="#003366")
        style.configure("Critical.TLabel",foreground="#cc0000", font=("Segoe UI", 9, "bold"))
        style.configure("High.TLabel",    foreground="#cc5500", font=("Segoe UI", 9, "bold"))
        style.configure("Medium.TLabel",  foreground="#998800", font=("Segoe UI", 9, "bold"))
        style.configure("Low.TLabel",     foreground="#006600", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1a5276")])
        # State
        self.prop_vars    = {}   # prop_id -> BooleanVar
        self.impl_vars    = {}   # tid     -> BooleanVar (mitigation implemented?)
        self.active_threats = [] # List of threat tuples after analysis
        self.catalog      = self._load_catalog()
        # Notebook
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=6, pady=(6, 0))
        # Status bar
        self.status_var = tk.StringVar(value="Ready.  Fill in System Mapper → select Properties → Generate TARA Analysis.")
        ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w",
                  padding=(6, 2)).pack(fill="x", side="bottom")
        self._build_tab1()
        self._build_tab2()
        self._build_tab3()
        self._build_tab4()
        self._build_tab5()
        self._build_tab6()

    # ── Helpers ────────────────────────────────────────────────────────────
    def _scrolled(self, parent):
        c  = tk.Canvas(parent, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=c.yview)
        c.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        c.pack(side="left", fill="both", expand=True)
        inner = ttk.Frame(c)
        win   = c.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: c.configure(scrollregion=c.bbox("all")))
        c.bind("<Configure>",     lambda e: c.itemconfig(win, width=e.width))
        return inner

    def _show_tip(self, t): self.tip_lbl.config(text=f"ℹ  {t}", foreground="#005a8e")
    def _clear_tip(self):   self.tip_lbl.config(text="Hover over a property for its description.", foreground="gray")
    def _sl_int(self, s):   return int(s[3]) if len(s) > 3 and s[3].isdigit() else 2

    def _treeview(self, parent, cols, widths, height=14):
        frm = ttk.Frame(parent)
        frm.pack(fill="both", expand=True, padx=4, pady=4)
        tv  = ttk.Treeview(frm, columns=cols, show="headings", height=height)
        vsb = ttk.Scrollbar(frm, orient="vertical",   command=tv.yview)
        hsb = ttk.Scrollbar(frm, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        for col, w in zip(cols, widths):
            tv.heading(col, text=col, anchor="w")
            tv.column(col, width=w, anchor="w", stretch=False)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        return tv

    # ── Tab 1: System Mapper ───────────────────────────────────────────────
    def _build_tab1(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="🖥  System Mapper")
        inner = self._scrolled(f)

        def fld(p, lbl, widget, r, helptext="", c=0):
            ttk.Label(p, text=lbl, style="Hdr.TLabel").grid(row=r, column=c,   sticky="e",  padx=8, pady=4)
            widget.grid(                                      row=r, column=c+1, sticky="w",  padx=8, pady=4)
            ttk.Label(p, text=helptext, foreground="gray",
                      wraplength=420, font=("Segoe UI", 8)).grid(row=r, column=c+2, sticky="w", padx=(4,8), pady=4)

        # Instructions header
        ttk.Label(inner, text="ℹ  Register the device under assessment. All fields help determine the threat profile and IEC 62443 classification.",
                  foreground="#005a8e", font=("Segoe UI", 9, "italic"),
                  wraplength=1100).pack(fill="x", padx=12, pady=(8,2))

        s1 = ttk.LabelFrame(inner, text=" Device Identity ", padding=8)
        s1.pack(fill="x", padx=10, pady=6)
        self.v_name   = tk.StringVar()
        self.v_id     = tk.StringVar(value=str(uuid.uuid4())[:8].upper())
        self.v_fw     = tk.StringVar(value="1.0.0")
        self.v_vendor = tk.StringVar()
        fld(s1, "Device Name:",      ttk.Entry(s1, textvariable=self.v_name,   width=36), 0,
            "A unique, human-readable name for this device (e.g., 'WOC Line-3 Stn-14').")
        fld(s1, "Device ID:",        ttk.Entry(s1, textvariable=self.v_id,     width=20), 1,
            "Auto-generated unique ID. Used to track this device in the catalog.")
        fld(s1, "Firmware Version:", ttk.Entry(s1, textvariable=self.v_fw,     width=20), 2,
            "Current firmware/software version deployed on the device.")
        fld(s1, "Vendor / OEM:",     ttk.Entry(s1, textvariable=self.v_vendor, width=36), 3,
            "Manufacturer or system integrator responsible for the device.")

        s2 = ttk.LabelFrame(inner, text=" Classification ", padding=8)
        s2.pack(fill="x", padx=10, pady=6)
        self.v_type = tk.StringVar(value=DEVICE_TYPES[0])
        self.v_os   = tk.StringVar(value=OS_TYPES[0])
        self.v_loc  = tk.StringVar(value=LOCATIONS[0])
        self.v_crit = tk.StringVar(value=CRITICALITY[0])
        self.v_zone = tk.StringVar(value=ZONES[0])
        fld(s2, "Device Type:",       ttk.Combobox(s2, textvariable=self.v_type, values=DEVICE_TYPES, state="readonly", width=44), 0,
            "Primary function of this device in the rail/transit system.")
        fld(s2, "Operating System:",  ttk.Combobox(s2, textvariable=self.v_os,   values=OS_TYPES,    state="readonly", width=30), 1,
            "The OS or firmware platform. Affects which system-level threats apply.")
        fld(s2, "Physical Location:", ttk.Combobox(s2, textvariable=self.v_loc,  values=LOCATIONS,   state="readonly", width=32), 2,
            "Where the device is physically installed. Impacts physical attack exposure.")
        fld(s2, "Criticality:",       ttk.Combobox(s2, textvariable=self.v_crit, values=CRITICALITY, state="readonly", width=38), 3,
            "Safety/mission impact if comprised. SIL-rated = highest scrutiny.")
        fld(s2, "Network Zone:",      ttk.Combobox(s2, textvariable=self.v_zone, values=ZONES,       state="readonly", width=42), 4,
            "IEC 62443 zone per Purdue model. Zone 0 = most restricted (safety).")

        s3 = ttk.LabelFrame(inner, text=" IEC 62443 / EU CRA Compliance Context ", padding=8)
        s3.pack(fill="x", padx=10, pady=6)
        self.v_slt      = tk.StringVar(value=SL_OPTIONS[1])
        self.v_cra_life = tk.StringVar(value="5 Years")
        self.v_notes    = tk.StringVar()
        fld(s3, "Target Security Level (SL-T):", ttk.Combobox(s3, textvariable=self.v_slt,      values=SL_OPTIONS, state="readonly", width=60), 0,
            "The security level to achieve per IEC 62443-4-2. SL 2 suits most transit devices.")
        fld(s3, "CRA Support Lifecycle:",        ttk.Entry(s3, textvariable=self.v_cra_life, width=20), 1,
            "EU CRA requires free security updates for min. 5 years from market placement.")
        fld(s3, "Notes / Assumptions:",          ttk.Entry(s3, textvariable=self.v_notes,    width=60), 2,
            "Optional: record assumptions, scope boundaries, or risk acceptance notes.")

        bf = ttk.Frame(inner)
        bf.pack(fill="x", padx=10, pady=8)
        ttk.Button(bf, text="▶  Next: Properties →",
                   command=lambda: self.nb.select(1)).pack(side="left", padx=4)
        ttk.Button(bf, text="🔄  New Device ID",
                   command=lambda: self.v_id.set(str(uuid.uuid4())[:8].upper())).pack(side="left", padx=4)


    # ── Tab 2: Device Properties (EMB3D) ──────────────────────────────────
    def _build_tab2(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="🔍  Properties")
        inner = self._scrolled(f)

        cats  = {}
        for pid, label, cat, tip in PROPERTIES:
            cats.setdefault(cat, []).append((pid, label, tip))
        icons = {"Hardware": "⚙ ", "System Software": "🖧 ",
                 "Application Software": "📦 ", "Networking": "🌐 "}

        for cat, props in cats.items():
            lf = ttk.LabelFrame(inner, text=f" {icons.get(cat,'')}{cat} Properties ", padding=8)
            lf.pack(fill="x", padx=10, pady=4)
            for i, (pid, label, tip) in enumerate(props):
                var = tk.BooleanVar()
                self.prop_vars[pid] = var
                cb = ttk.Checkbutton(lf, text=f"[{pid}]  {label}", variable=var)
                cb.grid(row=i // 2, column=i % 2, sticky="w", padx=12, pady=2)
                cb.bind("<Enter>", lambda e, t=tip: self._show_tip(t))
                cb.bind("<Leave>", lambda e: self._clear_tip())

        tp = ttk.Frame(inner)
        tp.pack(fill="x", padx=10, pady=2)
        self.tip_lbl = ttk.Label(tp, text="Hover over a property for its description.",
                                 foreground="gray", wraplength=1050)
        self.tip_lbl.pack(anchor="w")

        bf = ttk.Frame(inner)
        bf.pack(fill="x", padx=10, pady=8)
        ttk.Button(bf, text="⚠  Generate TARA Analysis",
                   command=self._generate_analysis).pack(side="left", padx=4)
        ttk.Button(bf, text="✖  Clear All",
                   command=lambda: [v.set(False) for v in self.prop_vars.values()]).pack(side="left", padx=4)
        ttk.Button(bf, text="✔  Select All",
                   command=lambda: [v.set(True) for v in self.prop_vars.values()]).pack(side="left", padx=4)


    # ── Tab 3: Threat Catalog ──────────────────────────────────────────────
    def _build_tab3(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="⚠  Threat Catalog")
        # Summary bar
        self.t3_summary = tk.StringVar(value="Generate analysis from the Properties tab to populate the threat catalog.")
        ttk.Label(f, textvariable=self.t3_summary, style="Title.TLabel",
                  padding=(8, 4)).pack(fill="x")
        # Filter bar
        ff = ttk.Frame(f)
        ff.pack(fill="x", padx=6, pady=2)
        ttk.Label(ff, text="Filter by Category:").pack(side="left", padx=4)
        self.t3_filter = tk.StringVar(value="All")
        cats_cb = ttk.Combobox(ff, textvariable=self.t3_filter,
                               values=["All", "Hardware", "System Software", "Application Software", "Networking"],
                               state="readonly", width=22)
        cats_cb.pack(side="left", padx=4)
        cats_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_t3_filter())
        ttk.Label(ff, text="  Filter by Priority:").pack(side="left", padx=4)
        self.t3_pfilter = tk.StringVar(value="All")
        pri_cb = ttk.Combobox(ff, textvariable=self.t3_pfilter,
                              values=["All", "Critical", "High", "Medium", "Low"],
                              state="readonly", width=12)
        pri_cb.pack(side="left", padx=4)
        pri_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_t3_filter())
        ttk.Button(ff, text="🔄 Reset Filters",
                   command=lambda: (self.t3_filter.set("All"), self.t3_pfilter.set("All"),
                                    self._apply_t3_filter())).pack(side="left", padx=8)

        cols3   = ("TID", "Threat Name", "Category", "Properties", "Likelihood", "Consequence", "Risk", "Priority")
        widths3 = (80, 220, 140, 100, 80, 100, 70, 75)
        self.t3_tv = self._treeview(f, cols3, widths3, height=18)
        self.t3_tv.tag_configure("Critical", background="#fce4e4")
        self.t3_tv.tag_configure("High",     background="#fef0e4")
        self.t3_tv.tag_configure("Medium",   background="#fefbe4")
        self.t3_tv.tag_configure("Low",      background="#e4fce4")

        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=6, pady=4)
        ttk.Button(bf, text="📋  Export Threat Catalog (CSV)",
                   command=self._export_tara_csv).pack(side="left", padx=4)
        ttk.Button(bf, text="▶  View Mitigations →",
                   command=lambda: self.nb.select(3)).pack(side="left", padx=4)
        # Store all rows for filtering
        self.t3_all_rows = []

    def _apply_t3_filter(self):
        cat_f = self.t3_filter.get()
        pri_f = self.t3_pfilter.get()
        for item in self.t3_tv.get_children():
            self.t3_tv.delete(item)
        RISK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        for row in self.t3_all_rows:
            tid, name, cat, props, L, C, risk, pri = row
            if cat_f != "All" and cat != cat_f:
                continue
            if pri_f != "All" and pri != pri_f:
                continue
            self.t3_tv.insert("", "end", values=row, tags=(pri,))

    # ── Tab 4: Technical Requirements & Mitigations ────────────────────────
    def _build_tab4(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="🛡  Mitigations")
        self.t4_summary = tk.StringVar(value="Run TARA analysis to populate mitigation requirements.")
        ttk.Label(f, textvariable=self.t4_summary, style="Title.TLabel",
                  padding=(8, 4)).pack(fill="x")

        cols4   = ("TID", "Threat Name", "IEC 62443-4-2 FR", "IEC 62443-4-1 SDL",
                   "NIST SP 800-82", "EU CRA Annex I", "Technical Mitigation", "Priority")
        widths4 = (75, 200, 175, 160, 110, 100, 320, 75)
        self.t4_tv = self._treeview(f, cols4, widths4, height=16)
        self.t4_tv.tag_configure("Critical", background="#fce4e4")
        self.t4_tv.tag_configure("High",     background="#fef0e4")
        self.t4_tv.tag_configure("Medium",   background="#fefbe4")

        # Implemented mitigations panel
        imp_lf = ttk.LabelFrame(f, text=" ✅  Mark Mitigations as Implemented (for SL-A Calculation) ", padding=6)
        imp_lf.pack(fill="x", padx=6, pady=4)
        self.impl_canvas = tk.Canvas(imp_lf, height=80, highlightthickness=0)
        impl_sb = ttk.Scrollbar(imp_lf, orient="horizontal", command=self.impl_canvas.xview)
        self.impl_canvas.configure(xscrollcommand=impl_sb.set)
        impl_sb.pack(side="bottom", fill="x")
        self.impl_canvas.pack(fill="x", expand=True)
        self.impl_inner = ttk.Frame(self.impl_canvas)
        self.impl_win   = self.impl_canvas.create_window((0, 0), window=self.impl_inner, anchor="nw")
        self.impl_inner.bind("<Configure>",
                             lambda e: self.impl_canvas.configure(scrollregion=self.impl_canvas.bbox("all")))

        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=6, pady=4)
        ttk.Button(bf, text="📋  Export Mitigations (CSV)",
                   command=self._export_tara_csv).pack(side="left", padx=4)
        ttk.Button(bf, text="📊  Update SL Assessment →",
                   command=lambda: (self._update_sl_tab(), self.nb.select(4))).pack(side="left", padx=4)


    # ── Tab 5: Security Level Assessment (IEC 62443) ───────────────────────
    def _build_tab5(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="📊  SL Assessment")

        hdr = ttk.Frame(f)
        hdr.pack(fill="x", padx=8, pady=4)
        ttk.Label(hdr, text="IEC 62443-4-2 Security Level Gap Analysis", style="Title.TLabel").pack(side="left")
        ttk.Button(hdr, text="📋 Export SL Assessment (CSV)",
                   command=self._export_sl_csv).pack(side="right", padx=4)

        # FR summary table
        cols5   = ("FR", "Fundamental Requirement", "Component Reqs", "SL-T", "SL-A", "Gap", "Status")
        widths5 = (55, 240, 120, 55, 55, 55, 80)
        self.t5_tv = self._treeview(f, cols5, widths5, height=9)
        self.t5_tv.tag_configure("met",     background="#e4fce4", foreground="#006600")
        self.t5_tv.tag_configure("partial", background="#fefbe4", foreground="#887700")
        self.t5_tv.tag_configure("gap",     background="#fce4e4", foreground="#cc0000")

        # Overall verdict
        self.sl_verdict = tk.StringVar(value="Run TARA and mark mitigations as implemented to compute SL-A.")
        ttk.Label(f, textvariable=self.sl_verdict, style="Title.TLabel",
                  padding=(8, 4), relief="groove").pack(fill="x", padx=8, pady=4)

        # SL guidance per FR (populated dynamically)
        guide_lf = ttk.LabelFrame(f, text=" SL Requirements Reference (per FR at each level) ", padding=6)
        guide_lf.pack(fill="x", padx=8, pady=4)
        cols_g   = ("FR", "Name", "SL 1", "SL 2", "SL 3", "SL 4")
        widths_g = (55, 230, 160, 200, 220, 220)
        self.t5_guide = self._treeview(guide_lf, cols_g, widths_g, height=7)
        for fr_id, fr in FR_MAP.items():
            self.t5_guide.insert("", "end", values=(
                fr_id, fr["name"], fr["sl1"], fr["sl2"], fr["sl3"], fr["sl4"]))

    # ── Tab 6: Device Catalog ──────────────────────────────────────────────
    def _build_tab6(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="📁  Device Catalog")

        hdr = ttk.Frame(f)
        hdr.pack(fill="x", padx=8, pady=4)
        ttk.Label(hdr, text="Registered Device Catalog", style="Title.TLabel").pack(side="left")

        cols6   = ("ID", "Name", "Type", "Zone", "SL-T", "SL-A", "Threats", "Criticality", "Date Added")
        widths6 = (80, 150, 190, 160, 60, 55, 65, 170, 120)
        self.t6_tv = self._treeview(f, cols6, widths6, height=16)
        self.t6_tv.bind("<Double-1>", lambda e: self._load_selected_device())

        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=6, pady=6)
        ttk.Button(bf, text="💾  Save Current Device to Catalog",
                   command=self._save_device).pack(side="left", padx=4)
        ttk.Button(bf, text="📂  Load Selected Device",
                   command=self._load_selected_device).pack(side="left", padx=4)
        ttk.Button(bf, text="🗑  Delete Selected",
                   command=self._delete_device).pack(side="left", padx=4)
        ttk.Button(bf, text="📋  Export Catalog (CSV)",
                   command=self._export_catalog_csv).pack(side="left", padx=4)
        ttk.Button(bf, text="🔄  Refresh",
                   command=self._refresh_catalog_tv).pack(side="left", padx=4)

        self._refresh_catalog_tv()


    # ── Core Logic ─────────────────────────────────────────────────────────
    def _generate_analysis(self):
        if not self.v_name.get().strip():
            messagebox.showwarning("Input Required", "Please enter a Device Name on the System Mapper tab before generating analysis.")
            return
        selected_props = {pid for pid, var in self.prop_vars.items() if var.get()}
        if not selected_props:
            messagebox.showwarning("No Properties Selected", "Please check at least one device property in the Properties tab.")
            return

        # Compute risk score (likelihood x consequence)
        SCORE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        RISK_LABEL = {(1,1):"Low",(1,2):"Low",(1,3):"Medium",(1,4):"Medium",
                      (2,1):"Low",(2,2):"Medium",(2,3):"High",(2,4):"High",
                      (3,1):"Medium",(3,2):"High",(3,3):"High",(3,4):"Critical",
                      (4,1):"Medium",(4,2):"High",(4,3):"Critical",(4,4):"Critical"}

        self.active_threats = []
        for t in THREATS:
            tid, name, cat, props, vec, L, C, iec42, nist, cra, mit, pri = t
            if any(p in selected_props for p in props):
                ls, cs = SCORE.get(L, 2), SCORE.get(C, 2)
                risk = RISK_LABEL.get((ls, cs), "Medium")
                self.active_threats.append((tid, name, cat, props, vec, L, C, iec42, nist, cra, mit, pri, risk))

        if not self.active_threats:
            messagebox.showinfo("No Threats", "No threats matched the selected properties.")
            return

        # ── Populate Tab 3 (Threat Catalog) ──────────────────────────────
        self.t3_all_rows = []
        for item in self.t3_tv.get_children():
            self.t3_tv.delete(item)
        for t in self.active_threats:
            tid, name, cat, props, vec, L, C, iec42, nist, cra, mit, pri, risk = t
            row = (tid, name, cat, ", ".join(props), L, C, risk, pri)
            self.t3_all_rows.append(row)
            self.t3_tv.insert("", "end", values=row, tags=(pri,))
        n = len(self.active_threats)
        crit_n = sum(1 for t in self.active_threats if t[11] == "Critical")
        self.t3_summary.set(
            f"Device: {self.v_name.get()} [{self.v_id.get()}]  |  "
            f"{n} threats identified  |  {crit_n} Critical  |  "
            f"Type: {self.v_type.get()}  |  Zone: {self.v_zone.get()}")

        # ── Populate Tab 4 (Mitigations) ─────────────────────────────────
        for item in self.t4_tv.get_children():
            self.t4_tv.delete(item)
        # Clear old impl checkboxes
        for w in self.impl_inner.winfo_children():
            w.destroy()
        self.impl_vars.clear()

        SDL_MAP = {
            "FR 1": "SR 1: Security Req. & Dev. Planning",
            "FR 2": "SR 2: Secure Design Principles",
            "FR 3": "SR 3: Secure Implementation / Code Review",
            "FR 4": "SR 3: Secure Implementation / Cryptography",
            "FR 5": "SR 4: Security Verification & Validation",
            "FR 6": "SR 5: Security Build & Integration",
            "FR 7": "SR 6: Security Guidelines / Hardening",
        }
        col_idx = 0
        for t in self.active_threats:
            tid, name, cat, props, vec, L, C, iec42, nist, cra, mit, pri, risk = t
            # Determine primary FR from iec42 string
            primary_fr = iec42.split("(")[0].strip() if "(" in iec42 else iec42[:4].strip()
            sdl = SDL_MAP.get(primary_fr, "SR 3: Secure Implementation")
            self.t4_tv.insert("", "end",
                values=(tid, name, iec42, sdl, nist, cra, mit, pri),
                tags=(pri,))
            # Impl checkbox
            var = tk.BooleanVar()
            self.impl_vars[tid] = var
            ttk.Checkbutton(self.impl_inner,
                text=f"{tid}", variable=var,
                command=self._update_sl_tab).grid(row=0, column=col_idx, padx=4, pady=2)
            col_idx += 1
        self.t4_summary.set(
            f"{n} technical requirements generated  |  "
            f"Tick checkboxes below to mark mitigations as implemented for SL-A calculation.")

        self._update_sl_tab()
        self.status_var.set(
            f"Analysis complete: {n} threats identified for '{self.v_name.get()}'. "
            f"Review Threat Catalog → Mitigations → SL Assessment tabs.")
        self.nb.select(2)

    # ── SL Assessment Logic ────────────────────────────────────────────────
    def _update_sl_tab(self):
        if not self.active_threats:
            return
        for item in self.t5_tv.get_children():
            self.t5_tv.delete(item)

        slt_int   = self._sl_int(self.v_slt.get())
        impl_tids = {tid for tid, var in self.impl_vars.items() if var.get()}

        SCORE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

        # Map FR -> list of threats in that FR
        fr_threats = {fr: [] for fr in FR_MAP}
        for t in self.active_threats:
            tid, name, cat, props, vec, L, C, iec42, nist, cra, mit, pri, risk = t
            for fr in FR_MAP:
                if fr in iec42:
                    fr_threats[fr].append(tid)

        total_gap = 0
        for fr_id, fr in FR_MAP.items():
            tids_here   = fr_threats[fr_id]
            total_here  = len(tids_here)
            impl_here   = sum(1 for tid in tids_here if tid in impl_tids)
            if total_here == 0:
                sla_int = slt_int   # no threats in this FR → assume met
                tag  = "met"
                status = "✅ N/A (no threats)"
            else:
                ratio = impl_here / max(total_here, 1)
                # SL-A = fraction of SL-T achieved
                sla_int = max(1, round(slt_int * ratio))
                gap = slt_int - sla_int
                total_gap += gap
                if gap == 0:
                    tag, status = "met",     "✅ Met"
                elif gap == 1:
                    tag, status = "partial", f"⚠ Gap -{gap}"
                else:
                    tag, status = "gap",     f"❌ Gap -{gap}"

            self.t5_tv.insert("", "end", tags=(tag,), values=(
                fr_id, fr["name"], fr["cr"],
                f"SL {slt_int}", f"SL {sla_int}",
                f"{slt_int - sla_int:+d}" if total_here > 0 else "—",
                status))

        # Overall verdict
        impl_count = len(impl_tids)
        total_count = len(self.active_threats)
        overall_sla = max(1, round(slt_int * impl_count / max(total_count, 1)))
        if total_gap == 0:
            verdict = f"✅  ACHIEVED SL {overall_sla} — All mitigations implemented. Compliant with IEC 62443-4-2 SL {slt_int} target."
        elif total_gap <= 2:
            verdict = (f"⚠  PARTIAL SL {overall_sla} — {impl_count}/{total_count} mitigations implemented. "
                       f"Minor gaps remain vs SL {slt_int} target.")
        else:
            verdict = (f"❌  SL {overall_sla} (Target: SL {slt_int}) — Significant gaps. "
                       f"Implement remaining {total_count - impl_count} mitigations to close delta.")
        self.sl_verdict.set(verdict)

    # ── Device Catalog Methods ─────────────────────────────────────────────
    def _load_catalog(self):
        if os.path.exists(CATALOG_FILE):
            try:
                with open(CATALOG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_catalog(self):
        with open(CATALOG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.catalog, f, indent=2, ensure_ascii=False)

    def _save_device(self):
        if not self.v_name.get().strip():
            messagebox.showwarning("Missing Data", "Please fill in a Device Name before saving.")
            return
        impl_count = len(self.active_threats)
        impl_done  = sum(1 for var in self.impl_vars.values() if var.get())
        slt_int    = self._sl_int(self.v_slt.get())
        sla_int    = max(1, round(slt_int * impl_done / max(impl_count, 1))) if impl_count else 0
        dev_id     = self.v_id.get()
        # Update existing or append
        entry = {
            "id":         dev_id,
            "name":       self.v_name.get(),
            "type":       self.v_type.get(),
            "os":         self.v_os.get(),
            "location":   self.v_loc.get(),
            "criticality":self.v_crit.get(),
            "zone":       self.v_zone.get(),
            "fw":         self.v_fw.get(),
            "vendor":     self.v_vendor.get(),
            "slt":        self.v_slt.get(),
            "sla":        f"SL {sla_int}" if impl_count else "Not assessed",
            "threats":    impl_count,
            "cra_life":   self.v_cra_life.get(),
            "notes":      self.v_notes.get(),
            "props":      [pid for pid, var in self.prop_vars.items() if var.get()],
            "impl":       [tid for tid, var in self.impl_vars.items() if var.get()],
            "date":       datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        existing = next((i for i, d in enumerate(self.catalog) if d["id"] == dev_id), None)
        if existing is not None:
            if messagebox.askyesno("Update Device", f"Device ID {dev_id} already in catalog. Overwrite?"):
                self.catalog[existing] = entry
        else:
            self.catalog.append(entry)
        self._save_catalog()
        self._refresh_catalog_tv()
        messagebox.showinfo("Saved", f"Device '{entry['name']}' saved to catalog.")

    def _refresh_catalog_tv(self):
        for item in self.t6_tv.get_children():
            self.t6_tv.delete(item)
        self.catalog = self._load_catalog()
        for d in self.catalog:
            self.t6_tv.insert("", "end", values=(
                d.get("id",""), d.get("name",""), d.get("type",""),
                d.get("zone",""), d.get("slt","")[:4],
                d.get("sla",""), d.get("threats",""),
                d.get("criticality",""), d.get("date","")))

    def _load_selected_device(self):
        sel = self.t6_tv.selection()
        if not sel:
            messagebox.showinfo("Select Device", "Please select a device row to load.")
            return
        vals  = self.t6_tv.item(sel[0], "values")
        did   = vals[0]
        entry = next((d for d in self.catalog if d["id"] == did), None)
        if not entry:
            return
        self.v_name.set(entry.get("name",""))
        self.v_id.set(entry.get("id",""))
        self.v_fw.set(entry.get("fw",""))
        self.v_vendor.set(entry.get("vendor",""))
        self.v_type.set(entry.get("type", DEVICE_TYPES[0]))
        self.v_os.set(entry.get("os", OS_TYPES[0]))
        self.v_loc.set(entry.get("location", LOCATIONS[0]))
        self.v_crit.set(entry.get("criticality", CRITICALITY[0]))
        self.v_zone.set(entry.get("zone", ZONES[0]))
        self.v_slt.set(entry.get("slt", SL_OPTIONS[1]))
        self.v_cra_life.set(entry.get("cra_life","5 Years"))
        self.v_notes.set(entry.get("notes",""))
        for pid, var in self.prop_vars.items():
            var.set(pid in entry.get("props", []))
        messagebox.showinfo("Loaded", f"Device '{entry['name']}' loaded. Click 'Generate TARA Analysis' to regenerate threats.")
        self.nb.select(0)

    def _delete_device(self):
        sel = self.t6_tv.selection()
        if not sel:
            messagebox.showinfo("Select Device", "Please select a device row to delete.")
            return
        vals = self.t6_tv.item(sel[0], "values")
        did  = vals[0]
        name = vals[1]
        if messagebox.askyesno("Confirm Delete", f"Delete device '{name}' (ID: {did}) from catalog?"):
            self.catalog = [d for d in self.catalog if d["id"] != did]
            self._save_catalog()
            self._refresh_catalog_tv()

    # ── Export Methods ─────────────────────────────────────────────────────
    def _export_tara_csv(self):
        if not self.active_threats:
            messagebox.showwarning("No Data", "Generate a TARA analysis first before exporting.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All Files", "*.*")],
            title="Export TARA Report",
            initialfile=f"TARA_{self.v_name.get()}_{datetime.now().strftime('%Y%m%d')}.csv")
        if not fp:
            return
        with open(fp, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["TARA REPORT — Rail & Transit EMB3D Tool"])
            w.writerow(["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            w.writerow(["Device Name:", self.v_name.get(), "Device ID:", self.v_id.get()])
            w.writerow(["Device Type:", self.v_type.get(), "FW Version:", self.v_fw.get()])
            w.writerow(["OS:", self.v_os.get(), "Location:", self.v_loc.get()])
            w.writerow(["Network Zone:", self.v_zone.get(), "Criticality:", self.v_crit.get()])
            w.writerow(["Target SL:", self.v_slt.get()])
            w.writerow(["CRA Lifecycle:", self.v_cra_life.get()])
            w.writerow([])
            w.writerow(["EMB3D TID", "Threat Name", "Category", "Triggering Properties",
                        "Attack Vector", "Likelihood", "Consequence", "Risk",
                        "IEC 62443-4-2 FR", "IEC 62443-4-1 SDL Practice",
                        "NIST SP 800-82 Control", "EU CRA Reference",
                        "Technical Mitigation", "Priority", "Implemented?"])
            SDL_MAP = {"FR 1":"SR 1: Security Req. & Planning","FR 2":"SR 2: Secure Design",
                       "FR 3":"SR 3: Secure Implementation","FR 4":"SR 3: Cryptography",
                       "FR 5":"SR 4: Security V&V","FR 6":"SR 5: Build & Integration",
                       "FR 7":"SR 6: Hardening Guide"}
            for t in self.active_threats:
                tid, name, cat, props, vec, L, C, iec42, nist, cra, mit, pri, risk = t
                pf  = iec42.split("(")[0].strip() if "(" in iec42 else iec42[:4].strip()
                sdl = SDL_MAP.get(pf, "SR 3: Secure Implementation")
                impl = "Yes" if self.impl_vars.get(tid, tk.BooleanVar()).get() else "No"
                w.writerow([tid, name, cat, ", ".join(props), vec, L, C, risk,
                            iec42, sdl, nist, cra, mit, pri, impl])
        messagebox.showinfo("Exported", f"TARA report saved to:\n{fp}")

    def _export_sl_csv(self):
        if not self.active_threats:
            messagebox.showwarning("No Data", "Generate a TARA analysis first.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All Files", "*.*")],
            title="Export SL Assessment",
            initialfile=f"SL_Assessment_{self.v_name.get()}_{datetime.now().strftime('%Y%m%d')}.csv")
        if not fp:
            return
        slt_int    = self._sl_int(self.v_slt.get())
        impl_tids  = {tid for tid, var in self.impl_vars.items() if var.get()}
        fr_threats = {fr: [] for fr in FR_MAP}
        for t in self.active_threats:
            tid, name, cat, props, vec, L, C, iec42, nist, cra, mit, pri, risk = t
            for fr in FR_MAP:
                if fr in iec42:
                    fr_threats[fr].append(tid)
        with open(fp, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["IEC 62443-4-2 SECURITY LEVEL GAP ANALYSIS"])
            w.writerow(["Device:", self.v_name.get(), "SL-T:", f"SL {slt_int}",
                        "Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            w.writerow([])
            w.writerow(["FR", "Fundamental Requirement", "Component Reqs",
                        "SL-T", "SL-A", "Gap", "Status", "Threats in FR", "Implemented"])
            for fr_id, fr in FR_MAP.items():
                tids      = fr_threats[fr_id]
                impl_here = sum(1 for tid in tids if tid in impl_tids)
                ratio     = impl_here / max(len(tids), 1) if tids else 1.0
                sla_int   = max(1, round(slt_int * ratio)) if tids else slt_int
                gap       = slt_int - sla_int
                status    = "Met" if gap == 0 else f"Gap -{gap}"
                w.writerow([fr_id, fr["name"], fr["cr"],
                            f"SL {slt_int}", f"SL {sla_int}",
                            f"{gap:+d}" if tids else "—",
                            status, len(tids), impl_here])
        messagebox.showinfo("Exported", f"SL Assessment saved to:\n{fp}")

    def _export_catalog_csv(self):
        if not self.catalog:
            messagebox.showwarning("Empty Catalog", "No devices in the catalog to export.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All Files", "*.*")],
            title="Export Device Catalog",
            initialfile=f"Device_Catalog_{datetime.now().strftime('%Y%m%d')}.csv")
        if not fp:
            return
        with open(fp, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["DEVICE CATALOG EXPORT — Rail & Transit EMB3D TARA Tool"])
            w.writerow(["Exported:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            w.writerow([])
            w.writerow(["ID","Name","Type","OS","Location","Criticality","Zone",
                        "FW Version","Vendor","SL-T","SL-A","Threats","CRA Lifecycle",
                        "Properties","Implemented","Notes","Date Added"])
            for d in self.catalog:
                w.writerow([
                    d.get("id",""), d.get("name",""), d.get("type",""), d.get("os",""),
                    d.get("location",""), d.get("criticality",""), d.get("zone",""),
                    d.get("fw",""), d.get("vendor",""), d.get("slt",""), d.get("sla",""),
                    d.get("threats",""), d.get("cra_life",""),
                    "; ".join(d.get("props",[])),
                    "; ".join(d.get("impl",[])),
                    d.get("notes",""), d.get("date","")])
        messagebox.showinfo("Exported", f"Device catalog saved to:\n{fp}")


# ── Entry Point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    root.resizable(True, True)
    app = ThreatModelApp(root)
    root.mainloop()