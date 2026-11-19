---

title: ""

description: ""

date: {{date:YYYY-MM-DD}}

categories: [Malware Analysis]

tags: []

media_subpath: /assets/img/posts/{{title}}

---

  

<!--

BEFORE PUBLISHING (delete this block):

- File name: YYYY-MM-DD-short-slug.md, inside _posts/

- categories: [Malware Analysis] or [Threat Research]

- tags: CamelCase, reuse existing ones (XWorm, AsyncRAT, RAT, ConfigExtraction,

  YARA, DotNet, ScreenConnect, DattoRMM, RMMAbuse, Phishing, IOCs, ...)

- Images: copy them to assets/img/posts/<same name as this file>/

- No "# Title" line in the body: the title comes from the header above

- One blank line before and after every table, image and code block

- Defang live URLs and IPs: hxxp://, example[.]com

-->

  

> One or two sentences: what was analyzed and the main result.

  

## Key Findings

  

- Finding 1

- Finding 2

- Finding 3

  

## Introduction

  

Context: where the sample or lead came from, and why it is worth analyzing.

  

## Analysis

  

### Sample Overview

  

| Field | Value |

|---|---|

| File name | `sample.exe` |

| File type | PE32 executable |

| SHA256 | `0000000000000000000000000000000000000000000000000000000000000000` |

  

### First Step

  

Explain what you did and why, then show the evidence.

  

```bash

command --used here

```

  

![Short description of what the screenshot shows](screenshot.png){: width="700" }

_Figure 1 — Caption shown under the image_

  

### Next Step

  

Continue the analysis.

  

## Detection

  

```yara

rule Family_Component

{

    strings:

        $s1 = "example"

    condition:

        all of them

}

```

  

## Tooling

  

Code and rules: [repository-name](https://github.com/lsuastegui/repository-name)

  

## Indicators of Compromise

  

### Hashes

  

| Algorithm | Value |

|---|---|

| SHA256 | `0000000000000000000000000000000000000000000000000000000000000000` |

  

### Network

  

| Type | Value |

|---|---|

| Domain | `example[.]com` |

| IP | `192.0.2[.]1` |

| URL | `hxxp://example[.]com/path` |

  

### Host

  

| Type | Value |

|---|---|

| Service | `ServiceName` |

| Registry | `HKLM\SOFTWARE\Example` |

| File path | `%PROGRAMFILES%\Example\` |

  

## Conclusion

  

What this means for defenders, and what to hunt for.