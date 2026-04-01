# Rail & Transit EMB3D TARA Tool

> **Threat Analysis and Risk Assessment (TARA) for Embedded Devices in Rail & Transit**
>
> Aligned with **MITRE EMB3D™ 2.0.1** · **MITRE ATT&CK® for ICS v18** · **IEC 62443-4-1 / -4-2** · **NIST SP 800-82** · **EU Cyber Resilience Act (CRA)**

---

## Overview

The **EMB3D TARA Tool** is a desktop application that helps embedded security engineers and product security teams perform structured threat modelling and risk assessment on embedded devices used in rail and transit systems (wayside controllers, onboard train computers, CBTC radio units, PLCs, passenger information systems, and more).

It translates the device's technical properties — hardware interfaces, software stack, network connectivity — into a prioritised list of applicable threats from the [MITRE EMB3D™ 2.0.1](https://emb3d.mitre.org/) framework, and then automatically maps each threat to:

- **MITRE ATT&CK® for ICS v18** adversary technique IDs (TTPs)
- **IEC 62443-4-2** Fundamental Requirements (FR 1–FR 7) and Component Requirements (CR)
- **IEC 62443-4-1** Secure Development Lifecycle (SDL) practices
- **NIST SP 800-82 / SP 800-53** controls
- **EU Cyber Resilience Act (CRA)** Annex I obligations

The tool computes an **Achieved Security Level (SL-A)** versus the operator-defined **Target Security Level (SL-T)** and provides a per-FR gap analysis to guide compliance efforts.

---

## Features

| Feature | Description |
|---|---|
| **System Mapper** | Register a device with type, OS, physical location, network zone, criticality, and CRA lifecycle |
| **EMB3D Property Selection** | 32 checkboxes across 4 EMB3D categories (Hardware, System Software, Application Software, Networking) |
| **Threat Catalog** | **81 threats** (full MITRE EMB3D™ 2.0.1 registry + 1 new entry TID-325), rail/transit-specific attack vectors, risk scoring, colour-coded by priority, filterable |
| **Technical Requirements** | Per-threat mitigation requirements with IEC 62443, ATT&CK for ICS TTPs, NIST, and EU CRA references |
| **SL Assessment** | FR-level SL-T vs SL-A gap table; auto-updates as mitigations are marked implemented |
| **Device Catalog** | JSON-backed multi-device registry; save, load, delete, export across sessions |
| **CSV Exports** | TARA report (with ATT&CK TTP column), SL gap analysis, and device catalog — all exportable to CSV |

---

## Supported Standards

| Standard | Version | Usage in Tool |
|---|---|---|
| [MITRE EMB3D™](https://emb3d.mitre.org/) | **2.0.1** | Threat taxonomy (TID-101 to TID-412) and device property model |
| [MITRE ATT&CK® for ICS](https://attack.mitre.org/matrices/ics/) | **v18** | Adversary TTP mapping per threat (T0xxx technique IDs) |
| IEC 62443-4-2 | Current | Component security requirements (FR 1–FR 7, CR mappings) and SL 1–4 assignment |
| IEC 62443-4-1 | Current | Secure Development Lifecycle practices (SR 1–SR 7) mapped per threat |
| NIST SP 800-82 | Rev 3 | OT/ICS security guide controls (AC, IA, SC, SI, AU, CM, CP families) |
| NIST SP 800-53 | Rev 5 | Control references cross-linked to IEC 62443 FRs |
| EU Cyber Resilience Act | 2024 | Annex I essential requirements mapped to each threat and mitigation |

---

## Threat Coverage

**81 threats** — complete coverage of the MITRE EMB3D™ 2.0.1 registry, each with rail/transit-specific attack vectors and ATT&CK for ICS v18 TTP mappings.

### ⚙ Hardware (16 threats)
| TID | Canonical Name |
|---|---|
| TID-101 | Power Consumption Analysis Side Channel |
| TID-102 | Electromagnetic Analysis Side Channel |
| TID-103 | Microarchitectural Side Channels |
| TID-105 | Hardware Fault Injection – Control Flow Modification |
| TID-106 | Data Bus Interception |
| TID-107 | Unauthorized Direct Memory Access (DMA) |
| TID-108 | ROM/NVRAM Data Extraction or Modification |
| TID-109 | RAM Chip Contents Readout |
| TID-110 | Hardware Fault Injection – Data Manipulation |
| TID-111 | Untrusted External Storage |
| TID-113 | Unverified Peripheral Firmware Loaded |
| TID-114 | Peripheral Data Bus Interception |
| TID-115 | Firmware/Data Extraction via Hardware Interface |
| TID-116 | Latent Privileged Access Port |
| TID-118 | Weak Peripheral Port Electrical Damage Protection |
| TID-119 | Latent Hardware Debug Port Allows Memory/Code Manipulation |

### 🖧 System Software (26 threats)
| TID | Canonical Name |
|---|---|
| TID-201 | Inadequate Bootloader Protection and Verification |
| TID-202 | Exploitable System Network Stack Component |
| TID-203 | Malicious OS Kernel Driver/Module Installable |
| TID-204 | Untrusted Programs Can Access Privileged OS Functions |
| TID-205 | Existing OS Tools Maliciously Used for Device Manipulation |
| TID-206 | Memory Management Protections Subverted |
| TID-207 | Container Escape |
| TID-208 | Virtual Machine Escape |
| TID-209 | Host Can Manipulate Guest Virtual Machines |
| TID-210 | Device Vulnerabilities Unpatchable |
| TID-211 | Device Allows Unauthenticated Firmware Installation |
| TID-212 | FW/SW Update Integrity Shared Secrets Extraction |
| TID-213 | Faulty FW/SW Update Integrity Verification |
| TID-214 | Secrets Extracted from Device Root of Trust |
| TID-215 | Unencrypted SW/FW Updates |
| TID-216 | Firmware Update Rollbacks Allowed |
| TID-217 | Remotely Initiated Updates Can Cause DoS |
| TID-218 | Operating System Susceptible to Rootkit |
| TID-219 | OS/Kernel Privilege Escalation |
| TID-220 | Unpatchable Hardware Root of Trust |
| TID-221 | Authentication Bypass By Message Replay |
| TID-222 | Critical System Service May Be Disabled |
| TID-223 | System Susceptible to RAM Scraping |
| TID-224 | Excessive Access via Software Diagnostic Features |
| TID-225 | Logs can be manipulated on the device |
| TID-226 | Device leaks security information in logs |

### 📦 Application Software (30 threats)
| TID | Canonical Name |
|---|---|
| TID-301 | Application Binaries Modified |
| TID-302 | Install Untrusted Application |
| TID-303 | Excessive Trust in Offboard Management/IDE Software |
| TID-304 | Manipulate Runtime Environment |
| TID-305 | Program Executes Dangerous System Calls |
| TID-306 | Sandboxed Environments Escaped |
| TID-307 | Device Code Representations Inconsistent |
| TID-308 | Code Overwritten to Avoid Detection |
| TID-309 | Device Exploits Engineering Workstation |
| TID-310 | Remotely Accessible Unauthenticated Services |
| TID-311 | Default Credentials |
| TID-312 | Credential Change Mechanism Can Be Abused |
| TID-313 | Unauthenticated Session Changes Credential |
| TID-314 | Passwords Can Be Guessed Using Brute-Force Attempts |
| TID-315 | Password Retrieval Mechanism Abused |
| TID-316 | Incorrect Certificate Verification Allows Authentication Bypass |
| TID-317 | Predictable Cryptographic Key |
| TID-318 | Insecure Cryptographic Implementation |
| TID-319 | Cross Site Scripting (XSS) |
| TID-320 | SQL Injection |
| TID-321 | HTTP Application Session Hijacking |
| TID-322 | Cross Site Request Forgery (CSRF) |
| TID-323 | Path Traversal |
| TID-324 | HTTP Direct Object Reference |
| **TID-325** | **HTTP Injection / Response Splitting** *(new in 2.0.1)* |
| TID-326 | Insecure Deserialization |
| TID-327 | Out of Bounds Memory Access |
| TID-328 | Hardcoded Credentials |
| TID-329 | Improper Password Storage |
| TID-330 | Cryptographic Timing Side-Channel |

### 🌐 Networking (9 threats)
| TID | Canonical Name |
|---|---|
| TID-401 | Undocumented Protocol Features |
| TID-404 | Remotely Triggerable Deadlock/DoS |
| TID-405 | Network Stack Resource Exhaustion |
| TID-406 | Unauthorized Messages or Connections |
| TID-407 | Missing Message Replay Protection |
| TID-408 | Unencrypted Sensitive Data Communication |
| TID-410 | Cryptographic Protocol Side Channel |
| TID-411 | Weak/Insecure Cryptographic Protocol |
| TID-412 | Network Routing Capability Abuse |

---

## Device Properties (EMB3D Model)

The tool uses **32 device properties** across 4 categories to identify applicable threats:

### ⚙ Hardware
`HP-1` Physical Ports (USB/SD/Serial) · `HP-2` Exposed Debug Interface (JTAG/UART/SWD) · `HP-3` Untrusted External Storage · `HP-4` DMA-capable Bus (PCIe) · `HP-5` Publicly Accessible Location · `HP-6` No Anti-tamper · `HP-7` Shared Power Bus · `HP-8` No EMI/RF Shielding

### 🖧 System Software
`SS-1` General-Purpose OS · `SS-2` Bootloader Without Secure Boot · `SS-3` OTA/Remote FW Updates · `SS-4` Virtualisation/Containers · `SS-5` Third-Party Kernel Modules · `SS-6` No Hardware Root of Trust · `SS-7` FW Rollback Allowed · `SS-8` Interactive Shell Accessible

### 📦 Application Software
`AS-1` Web Management Interface · `AS-2` SQL Database · `AS-3` Untrusted Input Sources · `AS-4` C/C++ Codebase · `AS-5` No Code Signing · `AS-6` Default/Hardcoded Credentials · `AS-7` Unvetted Third-Party Libraries · `AS-8` No Log Integrity

### 🌐 Networking
`NP-1` IP Network Interface · `NP-2` Legacy Protocols (Telnet/FTP/SNMPv1) · `NP-3` Unauthenticated Network Services · `NP-4` Serial/Fieldbus (MVB/CAN/Modbus) · `NP-5` Wireless Interface (Wi-Fi/BT/LTE) · `NP-6` No Network Segmentation · `NP-7` Accepts Broadcast/Multicast · `NP-8` No TLS / Cleartext Comms

---

## ATT&CK for ICS v18 TTP Mapping

Each threat is mapped to one or more **MITRE ATT&CK® for ICS v18** technique IDs. Representative examples:

| TID | Threat | ATT&CK for ICS TTPs |
|---|---|---|
| TID-119 | Latent Hardware Debug Port | T0820, T0839 |
| TID-201 | Inadequate Bootloader Protection | T0857 |
| TID-311 | Default Credentials | T0812 |
| TID-328 | Hardcoded Credentials | T0891 |
| TID-406 | Unauthorized Messages or Connections | T0830, T0856 |
| TID-407 | Missing Message Replay Protection | T0856, T0830 |
| TID-404 | Remotely Triggerable DoS | T0814 |
| TID-225 | Logs can be manipulated | T0872 |

TTPs appear in the **Mitigations** tab (ATT&CK for ICS column) and in the exported TARA CSV.

---

## IEC 62443 Security Level Framework

The tool implements the **IEC 62443-4-2 Security Level model**:

| Level | Defence Against |
|---|---|
| **SL 1** | Casual or unintentional violation |
| **SL 2** | Intentional violation using simple means (generic hacker) |
| **SL 3** | Sophisticated means with IACS-specific knowledge (hacktivist / insider) |
| **SL 4** | Nation-state level / Advanced Persistent Threat (APT) |

The **SL-A (Achieved)** is computed per-FR by tracking which mitigations have been marked as implemented. The gap between SL-T and SL-A is shown for all 7 Fundamental Requirements:

`FR 1` IAC · `FR 2` UC · `FR 3` SI · `FR 4` DC · `FR 5` RDF · `FR 6` TRE · `FR 7` RA

IEC 62443-4-1 SDL practices are mapped as: SR 1 (Security Management) → SR 2 (Requirements) → SR 3 (Secure Design) → SR 4 (Secure Implementation) → SR 5 (Security V&V) → SR 6 (Build & Integration) → SR 7 (Security Guidelines).

---

## Installation & Usage

### Prerequisites

- Python 3.8 or later
- `python3-tk` (Tkinter) — usually pre-installed on Linux; install via:
  ```bash
  sudo apt-get install python3-tk
  ```

### Run from Source

```bash
cd /home/aravind/projects/MITRE_Emb3d
python3 emb3d_req.py
```

### Run Pre-built Executable

A standalone Linux ELF binary (no Python install required) is located at:

```bash
./dist/EMB3D_TARA_Tool
```

### Build Executable from Source

```bash
pip3 install pyinstaller
pyinstaller --onefile --windowed --name "EMB3D_TARA_Tool" emb3d_req.py
# Output: dist/EMB3D_TARA_Tool
```

---

## Workflow

```
┌──────────────────────────────────────────────────────────┐
│  Tab 1: System Mapper                                    │
│  → Enter device name, type, OS, zone, SL-T, CRA life     │
├──────────────────────────────────────────────────────────┤
│  Tab 2: Properties                                       │
│  → Tick applicable EMB3D properties (32 checkboxes)      │
│  → Click ⚠ Generate TARA Analysis                       │
├──────────────────────────────────────────────────────────┤
│  Tab 3: Threat Catalog                                   │
│  → Review threats filtered by category / priority        │
│  → Colour-coded rows: 🔴 Critical · 🟧 High · 🟨 Medium  │
├──────────────────────────────────────────────────────────┤
│  Tab 4: Mitigations                                      │
│  → Review technical requirements + ATT&CK TTPs per threat│
│  → Tick ✅ Implemented for each completed mitigation     │
├──────────────────────────────────────────────────────────┤
│  Tab 5: SL Assessment                                    │
│  → FR-level SL-T vs SL-A gap analysis                    │
│  → Overall compliance verdict auto-updates               │
├──────────────────────────────────────────────────────────┤
│  Tab 6: Device Catalog                                   │
│  → Save device to catalog (persisted in JSON)            │
│  → Load previous devices · Delete · Export               │
└──────────────────────────────────────────────────────────┘
```

---

## CSV Export Format

### TARA Report (`TARA_<DeviceName>_YYYYMMDD.csv`)

| Column | Content |
|---|---|
| EMB3D TID | Threat identifier (e.g., TID-119) |
| Threat Name | Canonical MITRE EMB3D 2.0.1 name |
| Category | Hardware / System Software / App Software / Networking |
| Triggering Properties | Applicable EMB3D property IDs |
| Attack Vector | Rail/transit-specific scenario |
| Likelihood | Low / Medium / High |
| Consequence | Low / Medium / High / Critical |
| Risk | Computed risk matrix label |
| IEC 62443-4-2 FR | Fundamental Requirement and CR reference |
| IEC 62443-4-1 SDL | Secure Development Lifecycle practice (SR 1–SR 7) |
| NIST SP 800-82 | Control identifiers |
| EU CRA Annex I | Specific article reference |
| **ATT&CK for ICS TTP** | **ATT&CK for ICS v18 technique IDs (new)** |
| Technical Mitigation | Actionable requirement |
| Priority | Critical / High / Medium / Low |
| Implemented? | Yes / No (based on checkbox state) |

### SL Assessment (`SL_Assessment_<DeviceName>_YYYYMMDD.csv`)

FR-level breakdown: FR name, CR reference, SL-T, SL-A, gap, status, threat count, implemented count.

### Device Catalog (`Device_Catalog_YYYYMMDD.csv`)

All registered devices with full metadata: ID, name, type, OS, location, zone, SL-T, SL-A, threat count, properties, implemented mitigations, CRA lifecycle, notes.

---

## Data Persistence

Device data is saved to **`device_catalog.json`** in the same directory as the script. This file is created automatically on first save and persists across sessions. Back up this file to preserve your threat model inventory.

---

## Project Structure

```
MITRE_Emb3d/
├── emb3d_req.py          # Main application (~1250 lines)
├── emb3d_req.spec        # PyInstaller build spec
├── device_catalog.json   # Auto-created: registered device store
├── README.md             # This file
├── instructions.md       # Step-by-step user guide
├── build/                # PyInstaller build artefacts
└── dist/
    └── EMB3D_TARA_Tool   # Standalone Linux executable
```

---

## Changelog

### v2.0 (April 2026)
- **Threat names updated** to canonical MITRE EMB3D™ 2.0.1 names across all 81 entries
- **TID-325 added**: HTTP Injection / Response Splitting (previously missing from implementation)
- **ATT&CK for ICS v18 TTP field** added to all 81 threat tuples; new column in Mitigations tab and TARA CSV export
- **SDL_MAP corrected** per IEC 62443-4-1: FR→SR mapping now reflects SR 1–SR 7 correctly
- **Window title** updated to cite EMB3D 2.0.1 and ATT&CK for ICS v18

---

## Regulatory Context

### EU Cyber Resilience Act (CRA)
The EU CRA (effective 2024, mandatory compliance from 2027) requires manufacturers of products with digital elements to:
- Deliver products **without known exploitable vulnerabilities** (Annex I, §1a)
- Implement **secure by default** configurations (Annex I, §1a)
- Provide **security updates for the expected product lifetime**, minimum 5 years (Annex I, §2)
- Avoid **default or hardcoded credentials** (Annex I, §1f)

This tool maps each threat to the specific CRA Annex I article it addresses.

### IEC 62443 in Rail
IEC 62443 is the primary OT/ICS cybersecurity standard suite and is increasingly referenced in:
- **EN 50159** (railway communication safety)
- **ERA/TSI CCS** cybersecurity requirements
- **NIS2 Directive** obligations for critical infrastructure operators

### NIST SP 800-82 Rev 3
NIST's guide for OT security provides specific guidance for rail/transit ICS environments and forms the basis for control references in this tool.

---

## Disclaimer

This tool provides a **structured starting point** for TARA activities. Threat assessments generated are based on the selected device properties and must be validated by a qualified embedded security engineer with knowledge of the specific deployment context. The tool does not replace a full IEC 62443 security assessment or penetration test.

---

## License

Internal use tool. Refer to your organisation's software governance policy for redistribution rights.

---

*Built with MITRE EMB3D™ 2.0.1 · MITRE ATT&CK® for ICS v18 · IEC 62443-4-1/-4-2 · NIST SP 800-82 · EU CRA*
