# How to Use the EMB3D TARA Tool

This guide explains how to use the **Rail & Transit EMB3D Threat Analysis and Risk Assessment (TARA) Tool** step-by-step. It is written so that anyone — from graduate engineers to experienced security architects — can successfully generate a threat model.

## What Does This Tool Do?

Think of this tool as a translator. You tell it **what your device is** and **how it is built** (e.g., "It's a trackside controller running Linux with a Wi-Fi connection"), and the tool translates that into:
1. **The Threats:** What cyber attacks you need to worry about (based on MITRE EMB3D™).
2. **The Requirements:** What you must do to fix them (based on IEC 62443 and the EU Cyber Resilience Act).
3. **The Assessment:** How close you are to achieving your target Security Level (SL).

---

## Step-by-Step Guide

### Step 1: Register Your Device (System Mapper Tab)

When you open the application, you start on the **🖥 System Mapper** tab. This is where you give the tool basic context about your device.

Here is what each field means:

* **Device Name:** A human-readable name for your device. Give it a specific name like "Line 3 Wayside Object Controller" or "Train Wi-Fi Gateway".
* **Device ID:** A unique 8-character string auto-generated for you. You don't need to change this. It helps identify the device in reports.
* **Firmware Version:** The current software version (e.g., "1.0.0").
* **Vendor / OEM:** The company that makes the device (e.g., Siemens, Alstom, or your own company).
* **Device Type:** What the device actually does. (e.g., is it an Onboard Train Computer? A Passenger Display? A radio unit?)
* **Operating System:** What OS runs on it. If it runs Linux, choose "Linux". If it has no OS and runs directly on the chip, choose "Bare Metal".
* **Physical Location:** Where the device lives. A device locked in a data centre faces different physical threats than a box sitting next to the tracks in the rain.
* **Criticality:** How bad is it if this device breaks or gets hacked?
  * *Safety-Critical:* People could get hurt (e.g., train braking systems).
  * *Mission-Critical:* Trains stop running, massive delays.
  * *Operational:* Annoying, but trains still run (e.g., air conditioning controls).
  * *Non-Critical:* Passenger Wi-Fi or ad screens.
* **Network Zone:** Where does this sit on the network? Is it buried deep in a secure safety network (Zone 0/1) or connected to the internet (Zone 3/4)?
* **Target Security Level (SL-T):** This is your goal. How strong do the defences need to be?
  * *SL 1:* Protection against accidental mistakes.
  * *SL 2:* Protection against generic hackers (best for most internet-connected transit gear).
  * *SL 3:* Protection against skilled, targeted hackers (hacktivists, insiders).
  * *SL 4:* Protection against nation-state attacks.
* **CRA Support Lifecycle:** By law (EU CRA), you must provide security updates for the expected life of the device. Usually "5 Years" or "10 Years".

### Step 2: Define the Attack Surface (Properties Tab)

Once you've filled out the fields above, click the **Next: Properties →** button or click the **🔍 Properties** tab at the top.

Here, you will see 32 checkboxes divided into four categories: **Hardware**, **System Software**, **Application Software**, and **Networking**. 

**Your job here is to simply tick the boxes that are TRUE for your device.** 

> **💡 Tip:** Hover your mouse over any checkbox to see a tooltip with more details about what it means.

If your device has an Ethernet port, tick *NP-1*. If it has a Web Interface for admins, tick *AS-1*. If it uses default passwords, tick *AS-6*.

*Once you have ticked all applicable boxes, click the big button at the top:*
**`⚠ Generate TARA Analysis`**

### Step 3: Review the Threats (Threat Catalog Tab)

The tool has now calculated your unique threat profile. Click on the **⚠ Threat Catalog** tab.

You will see a large table listing all the MITRE EMB3D threats that apply to *your specific device*. 

*   **TID:** The MITRE Tracking ID.
*   **Threat Name:** What the attack is called.
*   **Likelihood & Consequence:** How likely it is to happen, and how bad it would be.
*   **Risk & Priority:** The tool automatically calculates the risk rating. 
    *   🔴 **Critical** threats are highlighted in red. You must fix these immediately.
    *   🟧 **High** threats in orange.
    *   🟨 **Medium** threats in yellow.

*Use the dropdown filters at the top if you only want to look at "Networking" threats or only "Critical" threats.*

### Step 4: Implement Mitigations (Mitigations Tab)

Now that you know the threats, how do you fix them? Go to the **🛡 Mitigations** tab.

This tab shows the exact same list of threats, but instead of showing risk scores, it shows **Requirements**:
*   **Technical Mitigation:** What you actually need to build or configure to stop the attack.
*   **IEC 62443 / NIST / CRA:** The exact standard clauses this fix satisfies.

**The most important part of this tab is the "Implemented" checklist at the bottom.**
There is a horizontal scrolling panel named: `✅ Mark Mitigations as Implemented`.

As your engineering team builds fixes (e.g., they add encryption, or they remove a debug port), you come to this panel and tick the box for that specific TID (e.g., tick `TID-119`).

### Step 5: Check Your Compliance (SL Assessment Tab)

Go to the **📊 SL Assessment** tab. This is your report card.

IEC 62443 divides security into 7 "Fundamental Requirements" (FRs), like "Use Control" or "Data Confidentiality".

This table compares your **Target SL (SL-T)** against your **Achieved SL (SL-A)** for each of the 7 categories.
*   If your Target was SL 2, but you haven't implemented any mitigations in FR 4, your Achieved SL-A for FR 4 will be SL 1. The status will show `❌ Gap -1`.
*   As you tick boxes in the Mitigations tab, these numbers will automatically go up.
*   The large text at the bottom will tell you your overall verdict (e.g., `✅ ACHIEVED SL 2`).

### Step 6: Save and Export (Device Catalog Tab)

Once your assessment is done, go to the **📁 Device Catalog** tab.

1.  Click **💾 Save Current Device to Catalog**. This saves all your tabs, properties, and ticked mitigations into the tool's memory (`device_catalog.json`). You can reload it tomorrow or next month to update it.
2.  Click **📋 Export Catalog (CSV)** or go back to any previous tab to export specific CSV reports (like the full TARA report or the SL Gap report) to share with management, auditors, or customers.

---

## Worked Example: A Wayside Object Controller

Let's do a fast example of how to use the tool for a new piece of hardware: a **Wayside Object Controller (WOC)** that controls track switches. 

**Step 1: System Mapper**
*   **Name:** WOC-Switch-Unit
*   **Type:** Wayside Object Controller (WOC)
*   **OS:** Linux (Hardened)
*   **Location:** Trackside / Wayside
*   **Criticality:** Safety-Critical (SIL 2/3/4)
*   **Target SL:** SL 3 (Because it's safety critical and outdoors)

**Step 2: Properties**
We look at our WOC hardware and software and we tick these boxes:
*   `HP-1` (It has physical USB ports for maintenance)
*   `HP-5` (It lives outside in a trackside cabinet)
*   `SS-1` (It runs a generic OS kernel)
*   `SS-3` (We can update it over the air/network)
*   `AS-1` (It has a small web interface for field techs)
*   `NP-1` (It connects to the IP train network)
*   `NP-8` (Currently, it sends logs in cleartext without TLS)

**Step 3 & 4: Analysis**
We click `Generate TARA Analysis` and look at the Mitigations. 
The tool spots that because it's trackside (`HP-5`) and has USB ports (`HP-1`), it's vulnerable to *TID-111 (Untrusted External Storage)* and tells us to disable USB mass storage in the Linux kernel via IEC 62443 FR 2.

**Step 5: Assessment**
We go to the SL Assessment tab. Because our goal is SL 3, but we haven't implemented anything yet, the tool shows massive gaps across all 7 FR categories. 

Whenever the engineering team disables the USB driver and turns on TLS encryption, we go to the Mitigations tab, tick the boxes for those TIDs, and watch our SL-A score climb to SL 3 until the red gaps turn green. We save the device to the catalog, export the CSV, and hand it to the safety auditor.
