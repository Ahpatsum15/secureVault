---
tags:
  - projects
  - cybersecurity
  - cryptography
  - Threat_model
author: Mustapha El Bouazaoui (Steph)
version: "1.0"
---


# Identify Assets 

| Asset           | Why it's valuable?                        | If compromised                        |
| --------------- | ----------------------------------------- | ------------------------------------- |
| Master password | Unlocks the entire vault                  | Attacker can decrypt everything       |
| Vault data      | Contains all user credential              | Total account takeover for user       |
| Encryption keys | Unlocks the vault or assure its integrity | Accessing or Tampering with user data |

# Identify Actors 

| Actor           | Capabilities                     | Goal                 |
| --------------- | -------------------------------- | -------------------- |
| Remote attacker | brute-force passwords            | Steal vault          |
| Malware         | Local access to files and memory | Extract vault or key |
| Developer       | Inject backdoor / malicious code | Steal vault          |

## Define System Architecture

```
User <-> App (Frontend)
App <-> Local Vault (encrypted file)
```
> Vault is encrypted locally using AES with a key derived from the master password. 

## Identify **Threats**

STRIDE model 

| Threat                 | Description           | SecureVault                               | Mitigation                                   |
| ---------------------- | --------------------- | ----------------------------------------- | -------------------------------------------- |
| Tampering              | Modifying data        | Alter encrypted vault                     | Authentication tag                           |
| Information Disclosure | Leaking data          | Malware reads decrypted vault from memory |                                              |
| Elevation of Privilege | Gaining higher rights | Exploit vulnerability to decrypt vault    | Can't acces to vault without master passowrd |

## Identify **Vulnerabilities**


| Vulnerability             | Severity | Impact                    |
| ------------------------- | -------- | ------------------------- |
| Weak key derivation       | High     | Vault brute-forced        |
| No Integrity check        | High     | Data tampering undetected |
| Sensitive logs            | Medium   | Privacy leak              |
| Insecure update mechanism | High     | code injection            |
| Session too long          | Medium   | Privacy leak              |
| Bad implementation        | Medium   | Backdoor                  |

## Define **Mitigations**


| Threat             | Mitigation                                                                                                                                | Limitation                                |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| Brute-force        | Argon2id with salt and high iterations (Following OWASP recommendations)\[memory-hard computation]                                        | Weak master password may still vulnerable |
| Data tampering     | HKDF-sha256                                                                                                                               | -                                         |
| Malware            | Secure memory handling                                                                                                                    | -                                         |
| Insider            | No cloud service, completely offline with open-source code, documents on the security used, algorithms implemented used public libraries. | Vault sync.                               |
| Bad implementation | No self implementation of the principal algorithms and using the official ones instead.                                                   | -                                         |

## Prioritize **Risks**


| Threat               | Likelihood | Impact | Priority |
| -------------------- | ---------- | ------ | -------- |
| Weak master password | High       | High   | Critical |
| Bad implementation   | Low        | High   | Medium   |
| Malware              | Low        | High   | Low      |
| Data tampering       | Low        | Medium | Low      |
| Insider              | Low        | Medium | Low      |

## Document

This is version 1. 
There's possiblity to add cloud service in the future to give the option for the user to sync. his vault and have access to it using only his master password on any device he would like, which may introduce more threats, vulnerabilities. This document will be updated accordingly.