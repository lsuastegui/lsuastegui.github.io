---
title: "AsyncRAT Campaign Analysis: Infrastructure Patterns, IoCs, and Operational Insights"
description: Network IoCs extracted from multiple AsyncRAT samples, the domain and subdomain reuse patterns behind them, and a Diamond Model view of the activity
date: 2026-04-30
categories:
  - Malware Analysis
tags:
  - AsyncRAT
  - RAT
  - ConfigExtraction
media_subpath: /assets/img/posts/2026-04-30-asyncrat-config-extractor
---

  

This report documents the analysis of multiple samples associated with AsyncRAT, a widely used open-source remote access trojan (RAT) frequently leveraged in commodity malware campaigns.

  

The objective of this research was to:
  
- Extract and validate network-based Indicators of Compromise (IoCs)
- Identify infrastructure patterns across samples
- Evaluate consistency in operator tradecraft

  

## Key Findings



### Infrastructure Reuse

  

Analysis revealed strong domain clustering, with threat actors reusing base domains and segmenting activity via subdomains.

  

Examples:

  

- teammambaperth.com  
- javhd.co.uk  
- jvrakia.com  

  

Each domain hosts multiple subdomains tied to different malware families or campaign labels.

  

### Thematic Subdomain Naming

  

Subdomains frequently reference well-known malware families:

  

- ryuk.teammambaperth.com  
- locky.javhd.co.uk  
- formbook.javhd.co.uk  
- azorult.teammambaperth.com  

  

This pattern suggests:

  

- Campaign labeling by operators  
- Internal segmentation or tracking  
- Reuse of infrastructure across multiple campaigns  

  

### Network Configuration

  

Across samples:

  

- **Ports observed:** 80, 443  
- **Protocol:** HTTP/HTTPS-based C2  
- **Fallback mechanisms:** Not observed  

  

This indicates a preference for blending with legitimate web traffic.

  

## Extracted IoCs

  

### Domains

  

```text
teammambaperth.com
www.teammambaperth.com
ryuk.teammambaperth.com
downadup.teammambaperth.com
gh0st.teammambaperth.com
azorult.teammambaperth.com
javhd.co.uk
www.javhd.co.uk
industroyer.javhd.co.uk
locky.javhd.co.uk
formbook.javhd.co.uk
jvrakia.com
www.jvrakia.com
triton.jvrakia.com
client.jvrakia.com
lokibot.jvrakia.com
malware.jvrakia.com
smalltimes.com
xl365.livebytexscore.com
```

  

### Campaign Identifiers

  

- `ECeDRSA3bolG`
- `6I1A2I5KBH4Q`
- `5Q2ZsaDMmVnm`

  

## Diamond Model Analysis

  

The activity observed can be mapped using the Diamond Model of Intrusion Analysis:

  

![Diamond Model of the AsyncRAT activity: adversary, infrastructure, capability and victim](async_diamond.png){: width="700" }

  

### Relationships

  

The strongest relationships observed:

  

- One domain → multiple subdomains → multiple campaign labels  

- One configuration → reused across multiple samples  

- Builder-driven artifacts → consistent across campaigns  

  

## Tradecraft Assessment

| Behavior | Assessment |
|---|---|
| Infrastructure reuse | High |
| Domain segmentation | Consistent |
| Use of legitimate ports | Yes |
| Obfuscation | Moderate |
| Dynamic C2 | Not observed |
| Operational sophistication | Low to medium |

## Tooling
  
IoCs were extracted using a custom-built script:
  
[extract_asyncrat_iocs.py](https://github.com/lsuastegui/asyncrat-config-extractor)

  

## Conclusion

  
This analysis demonstrates that AsyncRAT campaigns:
  

- Rely heavily on reusable infrastructure  
- Use subdomain-based segmentation  
- Blend into normal web traffic  
- Generate noisy artifacts requiring analyst validation  

  

While technically unsophisticated, these campaigns remain effective due to:

  

- Ease of deployment  
- Availability of tooling  
- Low operational cost