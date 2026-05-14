# Active Directory Security Assessment Lab

![Active Directory](https://img.shields.io/badge/Active%20Directory-003366?style=flat&logo=windows&logoColor=white)
![PingCastle](https://img.shields.io/badge/PingCastle-Assessment-orange?style=flat)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Attack%20Simulation-557C94?style=flat&logo=kalilinux&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=flat)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat)

---

## Overview

Deployed an intentionally vulnerable Active Directory environment using BadBlood on an Azure-hosted Windows Server Domain Controller. Assessed the environment with PingCastle, validated critical findings through Kerberoasting, AS-REP Roasting, and LDAP enumeration from Kali Linux, then remediated all exploitable vulnerabilities and documented measurable improvement through before/after PingCastle scoring.

---

## Attack Chain

```
[Kali Linux — Attacker VM]
        │
        ├──▶ SMB/LDAP Enumeration (2,500 users, 500 groups exposed)
        │
        ├──▶ Kerberoasting (51 service accounts targeted)
        │         └── Cracked GABRIELLE_MEDINA in 5 seconds
        │
        ├──▶ AS-REP Roasting (183 accounts — zero authentication required)
        │         └── 183 hashes extracted without credentials
        │
        └──▶ Credential Discovery
                  └── RICKEY_MOSES — plaintext password in AD description field
        
[PingCastle Assessment]
        │
        ├──▶ Baseline Score: 100/100 (maximum risk)
        │
        ├──▶ Remediation: 9 rules resolved, all exploitable findings eliminated
        │
        └──▶ Post-Remediation: 37 → 31 rules, Stale Objects 45 → 20
```

---

## Tools Used

| Tool | Role |
|---|---|
| Windows Server 2022 (Azure VM) | Domain Controller — `badblood.local` |
| BadBlood | Injected 2,500 vulnerable users, 500 groups, misconfigured ACLs and SPNs |
| PingCastle | AD security assessment — before/after scoring |
| Kali Linux (UTM) | Attack simulation — enumeration, Kerberoasting, AS-REP Roasting |
| Impacket | Kerberos ticket extraction and AD enumeration |
| CrackMapExec | SMB/LDAP domain enumeration |
| Hashcat | Offline password hash cracking |
| PowerShell | Bulk remediation scripting |

---

## Environment Setup

### Infrastructure

| Component | Details |
|---|---|
| Domain Controller | Azure VM (B2as), Windows Server 2022, `badblood.local` |
| Attacker Machine | Kali Linux on UTM (M1 MacBook) |
| Network Access | NSG rules restricted to single IP — ports 88, 389, 445, 636, 3389 |

### BadBlood Population

| Object Type | Count |
|---|---|
| Users | 2,500 |
| Groups | 500 |
| Computers | 100 |
| Kerberoastable accounts (SPNs) | 51 |
| AS-REP Roastable accounts | 183 |
| Passwords in description fields | 28 |

<details>
<summary>📸 Environment Screenshots</summary>
<br>
<img src="screenshots/vm-overview.png" width="80%"/>
<img src="screenshots/nsg-rules.png" width="80%"/>
<img src="screenshots/badblood-output.png" width="80%"/>
<img src="screenshots/ad-populated.png" width="80%"/>
</details>

---

## PingCastle Assessment — Before

Initial scan scored **100/100** — the worst possible rating.

| Category | Score |
|---|---|
| Stale Objects | 45 / 100 |
| Privileged Accounts | 100 / 100 |
| Trusts | 0 / 100 |
| Anomalies | 42 / 100 |
| **Overall** | **100 / 100** |

37 total rules triggered across all categories.

<details>
<summary>📸 PingCastle Before Screenshots</summary>
<br>
<img src="screenshots/pingcastle-before-score.png" width="80%"/>
<img src="screenshots/pingcastle-before-categories.png" width="80%"/>
</details>

---

## Attack Simulation

### Domain Enumeration

Authenticated as `labadmin` via CrackMapExec and Impacket to enumerate the full domain — 2,500 users, 500 groups, and all associated metadata exposed via SMB and LDAP.

<details>
<summary>📸 Enumeration Screenshots</summary>
<br>
<img src="screenshots/smb-enum-users.png" width="80%"/>
<img src="screenshots/smb-enum-groups.png" width="80%"/>
</details>

### Kerberoasting

Extracted Kerberos service tickets from all 51 accounts with SPNs set. Cracked `GABRIELLE_MEDINA`'s password (`P@ssw0rd123`) in **5 seconds** using Hashcat with the rockyou wordlist.

```bash
impacket-GetUserSPNs -dc-ip <DC-IP> badblood.local/labadmin:'<password>' -request -outputfile kerberoast_hashes.txt
hashcat -m 13100 single_hash.txt /usr/share/wordlists/rockyou.txt
```

This demonstrates that any authenticated domain user can request crackable service tickets offline — no lockout, no detection, no rate limiting.

<details>
<summary>📸 Kerberoasting Screenshots</summary>
<br>
<img src="screenshots/kerberoastable-accounts.png" width="80%"/>
<img src="screenshots/kerberoast-hashes.png" width="80%"/>
<img src="screenshots/kerberoast-cracked.png" width="80%"/>
</details>

### AS-REP Roasting

Extracted authentication hashes from **183 accounts** with Kerberos pre-authentication disabled — **without providing any credentials**.

```bash
impacket-GetNPUsers badblood.local/ -dc-ip <DC-IP> -usersfile users.txt -no-pass -format hashcat -outputfile asrep_hashes.txt
```

183 hashes were extracted unauthenticated. While the randomly generated lab passwords resisted the rockyou wordlist, in a production environment weak or reused passwords would be cracked within minutes. The vulnerability itself — handing crackable material to unauthenticated attackers — is the critical finding regardless of crack success.

<details>
<summary>📸 AS-REP Roasting Screenshots</summary>
<br>
<img src="screenshots/asrep-roast-results.png" width="80%"/>
</details>

### Critical Finding: Plaintext Password in AD Description

During SMB enumeration, discovered account `RICKEY_MOSES` with a password stored in plain text in the Active Directory description field:

> `"Just so I dont forget my password is v5x!T8TGHRQih8TcwscL8!n6"`

Any authenticated domain user can read description fields via LDAP by default. This is a common real-world finding that PingCastle does not detect — **28 total accounts** had credentials stored in description fields.

<details>
<summary>📸 Credential Discovery Screenshot</summary>
<br>
<img src="screenshots/rickey-moses-password.png" width="80%"/>
</details>

---

## MITRE ATT&CK Mapping

| Phase | Attack | Tactic | Technique | ID |
|---|---|---|---|---|
| Recon | SMB/LDAP enumeration | Discovery | Account Discovery: Domain Account | T1087.002 |
| Recon | Group enumeration | Discovery | Permission Groups Discovery | T1069.002 |
| Credential Access | Kerberoasting | Credential Access | Kerberoasting | T1558.003 |
| Credential Access | AS-REP Roasting | Credential Access | AS-REP Roasting | T1558.004 |
| Credential Access | Password in description | Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
| Credential Access | Hashcat cracking | Credential Access | Brute Force: Password Cracking | T1110.002 |

---

## Remediation

### Kerberoastable Accounts (51 → 0)

Removed all user-assigned SPNs via PowerShell. Only the built-in `krbtgt` account retains its SPN as expected.

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | ForEach-Object {
    $user = $_
    $user.ServicePrincipalName | ForEach-Object {
        Set-ADUser $user -ServicePrincipalName @{Remove=$_}
    }
}
```

### AS-REP Roastable Accounts (183 → 0)

Re-enabled Kerberos pre-authentication on all accounts.

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false
```

### Passwords in Description Fields (28 → 0)

Cleared all description fields containing credential strings.

```powershell
$descUsers = Get-ADUser -Filter * -Properties Description | Where-Object { $_.Description -match "password|pwd|pass" }
foreach ($user in $descUsers) {
    Set-ADUser -Identity $user -Description " "
}
```

### Domain Admin Reduction (6 → 1)

Removed 5 BadBlood accounts from Domain Admins, leaving only `labadmin`.

### Password Policy Hardening

| Setting | Before | After |
|---|---|---|
| MinPasswordLength | 7 | 14 |
| LockoutThreshold | 0 (unlimited) | 5 attempts |
| LockoutDuration | 00:10:00 | 00:30:00 |

### Additional Hardening

- Enabled AD Recycle Bin
- Set machine account quota to 0
- Disabled Print Spooler on DC
- Enabled OU deletion protection on all OUs
- Emptied Schema Admins group
- Marked admin accounts as sensitive (cannot be delegated)
- Disabled 2,306 inactive accounts

<details>
<summary>📸 Remediation Screenshots</summary>
<br>
<img src="screenshots/spn-remediation.png" width="80%"/>
<img src="screenshots/asrep-remediation.png" width="80%"/>
<img src="screenshots/description-remediation.png" width="80%"/>
<img src="screenshots/domain-admin-reduction.png" width="80%"/>
<img src="screenshots/password-policy-before.png" width="80%"/>
<img src="screenshots/password-policy-after.png" width="80%"/>
</details>

---

## PingCastle Assessment — After

| Category | Before | After | Change |
|---|---|---|---|
| Stale Objects | 45 | 20 | 🟢 −25 |
| Privileged Accounts | 100 | 100 | 🔴 See note below |
| Trusts | 0 | 0 | ✅ Clean |
| Anomalies | 42 | 52 | 🔴 Lab artifacts |
| **Rules Triggered** | **37** | **31** | **🟢 −6 rules** |
| **Rules Resolved** | — | **9** | ✅ |

The Privileged Group category remains at 100 due to `P-ControlPathIndirectEveryone` (3,968 objects with indirect control paths through Everyone/Authenticated Users). Investigation confirmed this stems from BadBlood's deeply nested group structure — Protected Users was nested inside 4 BadBlood distribution and admin groups, creating indirect privilege chains across the domain. Remediating this in production would require a phased group membership audit using BloodHound to visualize and dismantle indirect privilege chains.

### Key Improvements Within Persisted Findings

| Finding | Before | After |
|---|---|---|
| Admins not in Protected Users | 26 accounts | 2 accounts |
| Service accounts without AES | 61 accounts | 11 accounts |
| Domain Admins | 6 accounts | 1 account |
| Operator groups score | 30 pts | 10 pts |

<details>
<summary>📸 PingCastle After Screenshots</summary>
<br>
<img src="screenshots/pingcastle-after-score.png" width="80%"/>
<img src="screenshots/pingcastle-after-categories.png" width="80%"/>
</details>

---

## Results Summary

| Metric | Before | After |
|---|---|---|
| Kerberoastable accounts | 51 | 0 |
| AS-REP Roastable accounts | 183 | 0 |
| Passwords in descriptions | 28 | 0 |
| Domain Admins | 6 | 1 |
| PingCastle rules triggered | 37 | 31 |
| PingCastle rules resolved | — | 9 |
| Stale Objects score | 45 | 20 |
| Inactive accounts disabled | 0 | 2,306 |
| Password cracked (Kerberoast) | — | 5 seconds |
| AS-REP hashes extracted unauthenticated | — | 183 |

---

## Troubleshooting & Decisions

**Kerberos encryption type mismatch** — Initial Kerberoasting attempts returned empty hash files. The DC only supported AES encryption, which Impacket requested as `$krb5tgs$18$` (slow to crack). Resolved by enabling RC4 encryption on SPN accounts to generate `$krb5tgs$23$` hashes crackable in seconds. Documents the real-world tradeoff between encryption security and legacy compatibility.

**BloodHound collection blocked** — SharpHound was blocked by Microsoft Defender SmartScreen on the DC. Remote collection via bloodhound-python failed due to DNS resolution constraints between the Kali VM and Azure-hosted DC. In a production assessment, SharpHound would be executed locally on a domain-joined workstation.

**PingCastle score ceiling** — Despite resolving 9 rules and eliminating all exploitable credential findings, the overall score remained at 100 due to structural ACL issues across 3,968 objects. Investigated the root cause — BadBlood nested Protected Users inside distribution and admin groups, creating indirect control paths. This demonstrates that security remediation is iterative and structural issues require sustained effort beyond a single assessment cycle.

---

## Lessons Learned

- Kerberoasting and AS-REP Roasting are devastatingly simple attacks. Extracting crackable hashes took seconds, required minimal tooling, and generated zero alerts. The defense isn't complexity — it's removing SPNs from user accounts and never disabling pre-authentication.

- The most critical finding (28 plaintext passwords in AD descriptions) was the simplest vulnerability and the easiest to fix. PingCastle didn't even detect it — manual enumeration during the attack phase revealed it. Automated tools don't catch everything.

- Remediating individual vulnerabilities is straightforward. Fixing structural issues (nested group ACLs, indirect control paths) requires understanding the full privilege chain — tools like BloodHound exist specifically for this, and it's the difference between a quick fix and real security improvement.

---

## Future Improvements

- [ ] Deploy BloodHound on a domain-joined workstation to visualize and remediate the 3,968 indirect control paths
- [ ] Implement fine-grained password policies (FGPP) for service accounts with 20+ character minimums
- [ ] Enable Advanced Audit Policy and PowerShell Script Block Logging via GPO
- [ ] Disable LLMNR and NetBIOS via GPO to close poisoning attack vectors
- [ ] Enable Kerberos armoring (FAST) across the domain
- [ ] Integrate Microsoft Sentinel for AD sign-in log monitoring (connects to Contoso project)

---

## Cost

Total Azure cost: **under $10** across the project. VM deallocated between sessions.

---

## Disclaimer

This lab was built for educational purposes in a controlled environment using BadBlood to generate fictional vulnerable AD objects. All attack simulation was performed against an isolated Azure tenant with no connection to production systems.
