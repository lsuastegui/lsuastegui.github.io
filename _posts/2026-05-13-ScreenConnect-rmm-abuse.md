---

title: "ScreenConnect Abuse Case Study: From Telegram Telemetry to Infrastructure Pivoting"

description: "A case study covering the investigation of a malicious ScreenConnect deployment, Telegram-based operator telemetry, infrastructure pivoting, and MSI forensic reconstruction"

date: 2026-05-13

categories: [Threat Research]

tags: [screenconnect, rmm, initial-access]

media_subpath: /assets/img/posts/2026-05-13-ScreenConnect-rmm-abuse

---

  

> A case study covering the investigation of a malicious ScreenConnect deployment, Telegram-based operator telemetry, infrastructure pivoting, and MSI forensic reconstruction.

  

## Key Findings

  

- Telegram-based operator telemetry

- Self-hosted ScreenConnect deployment

- Infrastructure overlap using the identifier `TEMO`

- Legitimate signed ConnectWise binaries repackaged into a malicious MSI

- No PE trojanization or Authenticode stuffing

- RSA modulus-based infrastructure pivoting

- SafeBoot persistence for unattended access

  

## Introduction

  

This investigation started from a malicious VBS script hosted on an exposed Internet-facing system:

  

```text

http[:]//96.126.176.23/screen/panel1.vbs

```

  

![Contents of the panel1.vbs dropper script](panel1.png){: width="700" }

  

At first glance, the sample looked fairly typical:

- VBScript

- PowerShell execution

- MSI download

- remote access deployment

  

However, the script immediately exposed something operationally interesting:

- a hardcoded Telegram bot token,

- a Telegram chat ID,

- and a direct MSI delivery URL.

  

The VBS downloaded a ScreenConnect MSI package from:

```text

http[:]//96.126.176.23/screen/panel1.msi

```

and silently installed it through:

```text

msiexec.exe /i sc.msi /qn /norestart

```

The script then collected:

- hostname,

- username,

- operating system,

- public IP address,

- execution timestamp,

  

and sent the information directly to a Telegram bot controlled by the operator.

  

The notification string embedded in the script was:

```text

=== SCREENCONNECT INSTALLED PANEL 82===

```

At this stage, the malware family itself was still unknown. However, several things already stood out:

  

- direct-IP payload hosting,

- Telegram-based operator telemetry,

- unattended MSI installation,

- and a fully automated infection workflow.

  

More importantly, the script exposed operational infrastructure immediately:

  

- delivery server,

- Telegram bot,

- and operator telemetry.

  

Rather than focusing exclusively on the payload itself, the investigation quickly shifted toward understanding:

  

- who was operating the infrastructure,

- how the deployment was managed,

- and whether the exposed operational artifacts could be used to pivot further.

  

## Telegram Investigation

The embedded Telegram bot token allowed direct interaction with the Telegram Bot API.

  

The first step was validating whether the bot was still active:

```text

curl https://api.telegram.org/bot<TOKEN>/getMe

```

![Telegram Bot API getMe response confirming the bot is active](getme.png){: width="700" }

  

The bot responded successfully:

```text

{

  "ok": true,

  "result": {

    ...

    "first_name": "(New_Screen)",

    "username": "newscreennnbot"

    ...

  }

}

```

This immediately confirmed:

- the bot was still alive,

- the token remained valid,

- and the operator had not rotated credentials.

The next step was checking whether updates were still available:

```text

curl https://api.telegram.org/bot<TOKEN>/getUpdates

```

![Telegram Bot API getUpdates response with pending operator messages](getupdates.png){: width="700" }

  

Surprisingly, the bot was operating in polling mode rather than webhook mode.

  

This was confirmed through:

```text

curl https://api.telegram.org/bot<TOKEN>/getWebhookInfo

```

Response:

```text

{

  "ok": true,

  "result": {

    "url": "",

    "has_custom_certificate": false,

    "pending_update_count": 20

  }

}

```

This meant Telegram itself was buffering operator interactions and pending messages.

  

The retrieved updates exposed a Telegram account interacting manually with the bot:

  

- Username: @temo_15

- Display name: Kemo

- Language: ar

![Telegram account interacting with the bot](telegram_temo.png){: width="700" }

  

Observed messages included:

```text

..

2

22

722782

```

The interaction pattern appeared manual rather than automated.

  

At this point there still was not enough evidence to directly attribute the account to the operator. However, one detail became extremely important later in the investigation:

```text

temo

```

  

## Infrastructure Pivoting

The next phase focused on infrastructure correlation.

  

Using RDP metadata indexed by Shodan and Censys, searches were performed using values identified during the Telegram investigation.

  

Useful queries included:

```text

port:3389 "Target Name: TEMO"

```

```text

port:3389 "NetBIOS Domain Name: TEMO"

```

```text

port:3389 "FQDN: temo"

```

  

![Shodan results for RDP hosts exposing the TEMO target name](shodan_1.png){: width="700" }

  

![Censys results for hosts reusing the TEMO naming convention](censys.png){: width="700" }

  

This quickly revealed exposed RDP infrastructure reusing the same naming convention.

One of the identified systems exposed the following NTLM metadata:

```text

Target Name: TEMO

NetBIOS Domain Name: TEMO

NetBIOS Computer Name: TEMO

DNS Domain Name: temo

FQDN: temo

```

  

The same host also exposed a self-signed TLS certificate:

```text

Issuer: CN=temo

Subject: CN=temo

```

This was the first strong operational overlap between:

  

- Telegram telemetry,

- infrastructure naming,

- and exposed remote administration services.

  

Further investigation identified two systems of interest.

  

## Delivery Infrastructure

```text

96.126.176.23

```

![Shodan host details for the delivery server 96.126.176.23](shodan_3.png){: width="700" }

  

This host served the initial malicious VBS payload and exposed:

  

- RDP,

- Windows 11,

- matching TEMO NTLM metadata,

- and a matching self-signed certificate.

  
  

This system is assessed with high confidence as operational delivery infrastructure.

  

## Related Infrastructure

```text

45.94.80.250

```

![Shodan host details for the related RDP host 45.94.80.250](shodan_2.png){: width="700" }

  

This host exposed:

  

- RDP only,

- Windows Server 2022,

- identical TEMO NTLM naming,

- and matching self-signed certificate naming.

  

While no malware payloads were directly hosted on this system, the overlap strongly suggests shared administration or related operational infrastructure.

  

At this point the investigation had evolved far beyond simple malware triage and into infrastructure correlation and operator-linked telemetry analysis.

  

## Transitioning From Infrastructure to Payload Analysis

By this point in the investigation, several things had already become clear:

  

- the operation relied on Telegram-based telemetry,

- the payload was being delivered from self-hosted infrastructure,

- and the identifier `TEMO` repeatedly appeared across:

  - Telegram activity,

  - RDP metadata,

  - self-signed certificates,

  - and exposed infrastructure.

  

However, the MSI payload itself still had not been fully analyzed.

  

At first glance, the installer looked relatively small and unsophisticated. But after extracting the MSI tables and rebuilding the installation logic, the deployment methodology turned out to be significantly more interesting than expected.

  

Most notably:

- the binaries themselves were legitimate,

- the Authenticode signatures were valid,

- and the malicious behavior existed almost entirely inside the MSI configuration.

  

This was not a traditional trojanized binary.

  

Instead, the operator had taken legitimate ScreenConnect components and repackaged them into a malicious deployment workflow.

  

## Initial MSI Triage

  

Basic triage identified the payload as a Windows Installer package:

  

| Field | Value |

|---|---|

| Filename | `panel1.msi` |

| ProductVersion | `19.6.26378.7317` |

| Build Tool | `WiX Toolset 3.11` |

| Vendor | `ScreenConnect Software` |

  

MSI SHA256:

  

```text

7186fd91cf080ca01c0cf53f90efce2be374030fdaade9cb57ca60e2882a68aa

```

The installer itself was unsigned.

  

However, after extracting the embedded binaries, something immediately stood out:

the primary ScreenConnect executables carried intact and cryptographically valid ConnectWise signatures.

This significantly changed the direction of the investigation.

  

## Authenticode Analysis

The malware logic existed almost entirely in configuration and deployment orchestration rather than binary modification itself.

The extracted binaries included:

- ScreenConnect.WindowsClient.exe

- ServiceExeWithService

- ServiceExeWithoutService

  

All three binaries contained valid ConnectWise Authenticode signatures.

  

Verification confirmed:

  

- signatures were intact,

- binaries were not modified,

- and RFC3161 timestamps were valid.

  

Useful verification command:

  

```text

pedump --security ScreenConnect.WindowsClient.exe

```

The signing certificate belonged to:

```text

ConnectWise, LLC

```

  

with DigiCert-backed code signing and a valid timestamp chain.

  

This meant the attack did not rely on:

  

- PE patching,

- binary trojanization,

- or Authenticode stuffing.

  

Instead, the operator preserved the legitimate signed binaries entirely unchanged.

  

This is an important distinction because several recently documented ScreenConnect abuse campaigns modify signed PE files directly. In this case, the operator used a much cleaner approach:

the malicious configuration lived entirely inside the MSI metadata.

  

## Extracting the MSI Property Table

  

At this stage the investigation shifted toward MSI forensic reconstruction.

  

One of the most useful commands during the analysis was:

  

```text

msiinfo export panel1.msi Property

```

This exported the complete MSI Property table directly from the installer database.

  

Several fields immediately stood out:

  

| Property       | Value                                     |

| -------------- | ----------------------------------------- |

| `ProductName`  | ScreenConnect Client (e68408845a66f329) |

| `SERVICE_NAME` | ScreenConnect Client (e68408845a66f329) |

| `URL_SCHEME`   | sc-e68408845a66f329                     |

| `UpgradeCode`  | {B66A86DE-5FAB-8B51-E684-08845A66F329}  |

  

The identifier:

```text

e68408845a66f329

```

appeared repeatedly throughout the installer:

  

- product name,

- service name,

- URI scheme,

- and upgrade identifiers.

  

This strongly suggested the value represented a persistent ScreenConnect instance identifier tied to the operator-controlled deployment.

  

## Reconstructing the C2 Configuration

The most important field in the MSI was:

```text

SERVICE_CLIENT_LAUNCH_PARAMETERS

```

The raw value contained the complete ScreenConnect connection configuration:

```text

?e=Access&y=Guest&h=168.222.97.20&p=8041&k=<RSA_KEY>

```

After decoding the parameters:

| Parameter | Value           | Meaning                      |

| --------- | --------------- | ---------------------------- |

| `e`       | `Access`        | unattended persistent access |

| `y`       | `Guest`         | victim role                  |

| `h`       | `168.222.97.20` | C2 host                      |

| `p`       | `8041`          | C2 port                      |

| `k`       | RSA public key  | server authentication        |

  

Several things became immediately clear:

  

- the deployment was configured for unattended remote access,

- the operator was using self-hosted infrastructure,

- and no cloud relay fallback existed.

  

If the server at:

```text

168.222.97.20:8041

```

goes offline, the implant becomes inactive.

  

This strongly suggests:

  

- direct operator-managed infrastructure,

- rather than commodity cloud-managed ScreenConnect usage.

  

## RSA Public Key Extraction

The `k=` parameter embedded inside the MSI contained a Microsoft CryptoAPI PUBLICKEYBLOB.

  

After extraction and decoding, the installer was found to carry a unique RSA-2048 public key associated with the operator-controlled ScreenConnect server.

  

The modulus SHA256 was calculated as:

```text

eb09aa3594fbfd90f0afae7813fdb120d64259ab10b438d98ad23890a5852d9e

```

Unlike IP-based indicators, the embedded RSA modulus remains stable across infrastructure changes and represents a significantly more durable hunting pivot.

  

Why this matters:

  

- every ScreenConnect server generates its own RSA key pair,

- every client installer generated by that server carries the matching public key,

- and the modulus remains stable even if infrastructure changes later.

  

In practice, another MSI carrying the same RSA modulus would almost certainly belong to the same operator-controlled ScreenConnect deployment.

  

At the time of analysis:

  

- no VirusTotal matches,

- no OTX matches,

- no MalwareBazaar matches,

- and no public indexing existed for either:

    - the RSA modulus,

    - or the session identifier.

  

This strongly suggested:

  

- a low-volume deployment,

- private infrastructure,

- or a previously unreported campaign.

  

## Persistence Mechanisms

  

The installer configured several persistence mechanisms automatically.

  

The most notable were:

  

### Windows Service Installation

  

The MSI created an auto-start service:

  

```text

ScreenConnect Client (e68408845a66f329)

```

configured for persistent unattended access.

  

### Safe Mode Persistence

  

The installer also added:

```text

HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME]

```

allowing the implant to execute even in Safe Mode with Networking enabled.

  

This stood out because:

  

- many commodity deployments do not implement SafeBoot persistence,

- and it suggests awareness of remediation and incident response procedures.

  

### Custom URL Scheme

  

The MSI registered:

```text

sc-e68408845a66f329://

```

as a custom URI handler capable of relaunching the client automatically.

  

## Tradecraft Assessment

  

At this point the deployment methodology became much clearer.

  

The operator workflow appears to have been:

  

1. Obtain legitimate ScreenConnect binaries  

2. Preserve valid signatures unchanged  

3. Build a custom MSI using WiX  

4. Inject malicious configuration into MSI Property tables  

5. Deploy through VBS automation  

6. Receive infection telemetry through Telegram  

  

This approach provides several advantages for the operator:

  

- valid signed binaries,

- reduced AV suspicion,

- no PE tampering artifacts,

- cleaner operational deployment,

- and reusable infrastructure identity through RSA keys and session IDs.

  

Rather than modifying malware binaries directly, the operator abused the installation and configuration workflow itself.

  

## Key IOCs

  

### Delivery Infrastructure

  

| Type | Value |

|---|---|

| Initial VBS Delivery | `http[:]//96.126.176.23/screen/panel1.vbs` |

| MSI Payload | `http[:]//96.126.176.23/screen/panel1.msi` |

| ScreenConnect C2 | `168.222.97.20:8041` |

  

### Related Infrastructure

  

| IP | Notes |

|---|---|

| `96.126.176.23` | Initial payload delivery infrastructure |

| `45.94.80.250` | Related RDP infrastructure |

| `168.222.97.20` | Self-hosted ScreenConnect server |

  

### Telegram Artifacts

  

| Artifact | Value |

|---|---|

| Telegram Username | `@temo_15` |

| Telegram Display Name | `Kemo` |

| Telegram Bot Username | `newscreennnbot` |

| Notification String | `=== SCREENCONNECT INSTALLED PANEL 82===` |

  
  

### ScreenConnect Identifiers

  

| Artifact | Value |

|---|---|

| Session Identifier | `e68408845a66f329` |

| URL Scheme | `sc-e68408845a66f329` |

| UpgradeCode | `{B66A86DE-5FAB-8B51-E684-08845A66F329}` |

| ProductName | `ScreenConnect Client (e68408845a66f329)` |

  
  

### Cryptographic Pivots

  

| Artifact | Value |

|---|---|

| RSA Modulus SHA256 | `eb09aa3594fbfd90f0afae7813fdb120d64259ab10b438d98ad23890a5852d9e` |

| RSA Modulus MD5 | `fbed818145092847b1948f12365b80cb` |

  

### MSI Hashes

  

| Algorithm | Value |

|---|---|

| MD5 | `a8f74aece37e4b5855268b4ac9f55b6d` |

| SHA1 | `005ccf8811cee1c625ff7336bb98cbd0aa25f227` |

| SHA256 | `7186fd91cf080ca01c0cf53f90efce2be374030fdaade9cb57ca60e2882a68aa` |

  
  

### Persistence Artifacts

  

| Artifact | Value |

|---|---|

| SafeBoot Persistence | `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME]` |

| Installed Service | `ScreenConnect Client (e68408845a66f329)` |

| URI Handler | `sc-e68408845a66f329://` |