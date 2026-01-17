# Forensic Analysis: Multi-Stage Dridex/Ursnif Infection (Host 10.11.27.101)

## 📌 Executive Summary
This project details a high fidelity forensic investigation into a compromised internal host (**10.11.27.101**). The investigation confirmed a multi-stage attack chain where an initial **Ursnif (Gozi)** loader facilitated the delivery of the **Dridex banking Trojan**. The analysis covers network traffic triage, protocol anomaly detection, and artifact extraction using industry-standard tools.

## 🛠️ Tools & Environment
* **Platform:** Kali Linux (VirtualBox Environment)
* **Traffic Analysis:** Wireshark
* **Intelligence:** Cisco Talos, VirusTotal, AbuseIPDB
* **Evidence Source:** `traffic-with-dridex-infection.pcap`

---

## 🔍 Investigation Methodology (Multi Layered Framework)

### LAYER 1: Initial Triage & Traffic Volumetrics
The investigation began by identifying high risk external communicators. Analysis of the **Endpoints** window revealed heavy data exfiltration and payload delivery patterns.

![Endpoint Traffic Analysis](Screenshots/traffic_endpoints.jpg)
*Figure 1: Wireshark Endpoints listing malicious IPs 95.181.198.231 and 185.244.150.230.*

* **Primary Attacker IP:** `95.181.198.231` (Payload Hosting)
* **C2 Infrastructure:** `185.244.150.230` (Beaconing)

---

### LAYER 2: HTTP & DNS Protocol Investigation
The attacker utilized compromised web infrastructure to host malicious modules. We observed unauthorized GET requests disguised within common image directories to evade basic detection.

![HTTP Traffic Evidence](Screenshots/http_get_requests.jpg)
*Figure 2: Sequence of suspicious HTTP GET requests originating from the victim host.*

DNS queries showed the infected host resolving **DGA (Domain Generation Algorithm)** domains used for C2 persistence.

![Domain Resolution](Screenshots/dns_resolution_cochrimato.jpg)
*Figure 3: TCP Stream confirming communication with the malicious domain cochrimato.com.*

---

### LAYER 3: Payload & Artifact Extraction
During the analysis, two primary malicious artifacts were identified and analyzed for file headers.

1. **`oiioiashdqbwe.rar`**: An initial compressed archive containing the loader.
2. **`spet10.spr`**: The primary Dridex binary.

![Binary Header Analysis](Screenshots/binary_mz_header.jpg)
*Figure 4: Hex view of spet10.spr showing the "MZ" Magic Number, confirming it is a Windows Portable Executable (PE) file.*

---

## 📊 Indicators of Compromise (IoCs)

| IoC Type | Value | Role |
| :--- | :--- | :--- |
| **IP Address** | `95.181.198.231` | Payload Delivery Server |
| **IP Address** | `185.244.150.230` | Command & Control (C2) |
| **Domain** | `cochrimato.com` | Malware Staging Domain |
| **File Name** | `spet10.spr` | Dridex Trojan Binary (MZ Header) |
| **File Name** | `oiioiashdqbwe.rar` | Malicious Archive |

---

## 🛡️ Attacker TTPs (MITRE ATT&CK Mapping)
* **T1566.001 - Phishing: Spearphishing Attachment:** Initial access via weaponized macros.
* **T1059.005 - Command and Scripting Interpreter (VBA):** Execution of secondary payloads.
* **T1071.001 - Application Layer Protocol (Web):** Use of HTTP for C2 and data exfiltration.
* **T1204.002 - User Execution (Malicious File):** Victim triggered the infection chain.

---

## 📉 Conclusion & Remediation
The host was successfully compromised by the Dridex botnet. Due to the high risk of credential theft:
1. **Isolate** the host from the VLAN immediately.
2. **Block** all listed IoCs at the enterprise firewall and DNS level.
3. **Reset** all user credentials associated with the host.

---

## ⚖️ Disclaimer
This analysis was performed for educational and professional portfolio purposes. All malware samples were handled in an isolated, secure laboratory environment.

**Analyst:** Oluwabusayo Stella SHADARE  
**Date:** January 17, 2026
