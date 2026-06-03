# dMSA-Reaper Knowledge File

This file preserves the project context, design decisions, technical facts, pitfalls, and reference targets for building `dmsa-reaper`.

## 1. Project goal

`dmsa-reaper` is an Active Directory dMSA abuse-path mapper and controlled primitive executor for authorized Windows Server 2025 assessments.

The tool should answer:

```text
Given current credentials, where are dMSA abuse paths executable, which primitive applies, what rights make it possible, and can the tool execute/verify/rollback the selected primitive?
```

The tool is not a reporting platform. It does not need PDF/HTML output, dashboarding, or blue-team packaging.

Final shape:

```text
dmsa-reaper
├── map
├── paths
├── exploit
├── verify
└── rollback
```

## 2. Core design decision

The tool must be a mapper + path engine + primitive executor.

Do not build a single BadSuccessor PoC. Existing tools already cover isolated primitives. The gap is correlation:

```text
schema + effective ACLs + KDS prerequisite + Server 2025 presence + dMSA object state + target-side reciprocal rights + post-patch requirements
```

## 3. Current ecosystem and why this tool is different

### Akamai BadSuccessor repo

Use as reference for original research and OU permission scanning.

Important limitation: the public PowerShell scanner says it does not expand group membership and does not evaluate DENY ACEs fully. That means false positives and incomplete effective-rights modeling.

Search target:

```text
akamai BadSuccessor Get-BadSuccessorOUPermissions does not expand group membership deny ACEs
```

Reference:

```text
https://github.com/akamai/BadSuccessor
```

### NetExec badsuccessor module

Useful enumeration reference.

Search target:

```text
NetExec nxc modules badsuccessor.py dMSA CreateChild
```

Reference:

```text
https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py
```

### Impacket badsuccessor.py

Useful Python implementation reference. It uses LDAP/LDAPS, `ldap3`, and Impacket LDAP security descriptor parsing.

Search target:

```text
impacket examples badsuccessor.py PR 2010 0.13
```

References:

```text
https://github.com/fortra/impacket/blob/master/examples/badsuccessor.py
https://www.coresecurity.com/blog/whats-new-impackets-013-release
```

### Metasploit bad_successor module

Closest existing comparable exploitation module. It is still primitive-oriented, not a full dMSA-wide mapper/path engine with effective rights and rollback.

Search target:

```text
Metasploit auxiliary admin ldap bad_successor CREATE_DMSA GET_TICKET
```

References:

```text
https://www.rapid7.com/db/modules/auxiliary/admin/ldap/bad_successor/
https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/ldap/bad_successor.rb
```

### Rubeus

Reference for dMSA Kerberos support. Use external adapter first. Do not implement native Kerberos in V0.

Search target:

```text
Rubeus PR 194 KERB-DMSA-KEY-PACKAGE dmsa asktgs
Rubeus PR 204 dMSA standalone previousKeys
```

References:

```text
https://github.com/GhostPack/Rubeus/pull/194
https://github.com/GhostPack/Rubeus/pull/204
```

Caution:

- PR #194 is merged.
- PR #204-style improvements may not be merged upstream; verify current status before depending on it.

### BloodHound

Do not claim a specific open feature request unless verified. Safer wording:

```text
dMSA primitives are not yet first-class in the mainstream BloodHound workflow.
```

OpenGraph export can be a later feature, not MVP.

## 4. Primary research references

### Microsoft schema and protocol docs

Use these first when verifying schema facts.

Search targets:

```text
MS-ADSC msDS-DelegatedManagedServiceAccount
MS-ADA2 msDS-ManagedAccountPrecededByLink
MS-ADA2 msDS-SupersededManagedAccountLink
MS-ADA2 msDS-GroupMSAMembership
MS-ADTS searchFlags fCONFIDENTIAL
MS-ADTS LDAP_SERVER_SD_FLAGS_OID
MS-ADTS msDS-ManagedPassword constructed msDS-GroupMSAMembership access check
```

Known references:

```text
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/2c3e6e0a-134d-47e3-9ed5-edb71145def3
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/6ce9e113-5c1e-4ba3-8078-419dd4e33561
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c5b9ddb6-a9dd-4bdc-9a68-775fb346f21e
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7c1cdf82-1ecc-4834-827e-d26ff95fb207
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0
```

### Microsoft dMSA setup docs

Use for KDS root key and dMSA prerequisites.

Search target:

```text
Microsoft setting up delegated Managed Service Accounts KDS root key must be generated before dMSA created migrated
```

Reference:

```text
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa
```

### BadSuccessor original and post-patch research

Search targets:

```text
Akamai BadSuccessor Abusing dMSA Active Directory
Akamai BadSuccessor Is Dead Long Live BadSuccessor CVE-2025-53779 patch
SpecterOps near return king account takeover BadSuccessor post patch
Huntress dMSA Ouroboros credential extraction Windows Server 2025
Semperis Golden dMSA
```

References:

```text
https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch
https://specterops.io/blog/2025/10/20/the-near-return-of-the-king-account-takeover-using-the-badsuccessor-technique/
https://www.huntress.com/blog/dmsa-ouroboros-credential-extraction-windows-server-2025
https://github.com/Semperis/GoldenDMSA
```

## 5. Verified schema facts

### msDS-DelegatedManagedServiceAccount class

Known facts:

```text
ldapDisplayName: msDS-DelegatedManagedServiceAccount
schemaIDGUID: 0feb936f-47b3-49f2-9386-1dedc2c23765
subClassOf: computer
systemPossSuperiors: container, organizationalUnit
systemMustContain:
  - msDS-ManagedPasswordInterval
  - msDS-DelegatedMSAState
```

Resolve dynamically from schema. Hardcoded GUID only as fallback.

### msDS-ManagedAccountPrecededByLink

Known facts:

```text
ldapDisplayName: msDS-ManagedAccountPrecededByLink
schemaIDGUID: a0945b2b-57a2-43bd-b327-4d112a4e8bd1
linkID: 2224
single-valued: true
meaning: forward link from dMSA to superseded service account object
lives_on: dMSA
```

### msDS-SupersededManagedAccountLink

Known facts:

```text
ldapDisplayName: msDS-SupersededManagedAccountLink
schemaIDGUID: 3752e002-43be-48c8-b3ca-2cb2fffbc8a1
linkID: 2222
meaning: forward link from service account to delegated managed service account object
lives_on: target account
```

There is also:

```text
msDS-SupersededManagedAccountLinkBL
linkID: 2223
meaning: backlink
```

### msDS-GroupMSAMembership

Known facts:

```text
ldapDisplayName: msDS-GroupMSAMembership
systemIdGuid: 888eedd6-ce04-df40-b462-b8a50e41ba38
syntax: String(NT-Sec-Desc)
```

Important: this is a security descriptor, not a SID list.

### msDS-ManagedPassword

Do not model this as a normal readable attribute in V0.

It is constructed:

```text
systemFlags includes FLAG_ATTR_IS_CONSTRUCTED
```

Access is checked through the security descriptor stored in `msDS-GroupMSAMembership`, not by normal DACL readability of `msDS-ManagedPassword`.

## 6. Attribute-to-object mapping

This is critical. Do not conflate the side where an attribute lives.

```text
msDS-DelegatedMSAState              -> dMSA
msDS-ManagedAccountPrecededByLink   -> dMSA
msDS-GroupMSAMembership             -> dMSA
msDS-KeyCredentialLink              -> dMSA / user / computer depending on object
msDS-SupersededManagedAccountLink   -> target account
msDS-SupersededServiceAccountState  -> target account
```

The internal model should store:

```python
AttributeSpec(
    ldap_name="msDS-SupersededManagedAccountLink",
    lives_on="target",
    guid="..."
)
```

## 7. KDS root key gate

KDS root key existence is a hard requirement for dMSA capability.

Map stage must check:

```text
CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,<ConfigNC>
```

Then:

```python
dmsa_capable = has_server_2025_dc and has_dmsa_schema and has_kds_root_key
```

If no KDS root key exists, the dMSA attack surface is mostly moot.

## 8. Server 2025 and patch state

Required:

- detect Windows Server 2025 DC presence.
- collect DC `operatingSystem` and `operatingSystemVersion`.
- do not trust version alone for patch state.

For pre-patch vs post-patch behavior, behavioral validation is more reliable than build number fingerprinting:

```text
write/link behavior may succeed, but KDC ticket issuance may fail post-patch unless mutual pairing exists.
```

The original direct one-sided BadSuccessor path was patched under CVE-2025-53779. Treat it as:

```text
legacy-oneway-link
```

Do not prioritize it. It is useful for labs, CTFs, and unpatched environments.

Main 2026 primitive priority:

```text
postpatch-mutual-pair
```

## 9. LDAP signing, LDAPS, and CBT

V0 must handle LDAP/LDAPS cleanly.

Required CLI flags:

```bash
--use-ldaps
--check-binding
```

The tool should differentiate:

```text
invalid credentials
bind refused due to signing/channel binding requirements
TLS/certificate error
insufficient access rights
LDAP modify failure
```

Use Impacket 0.13 behavior and `CheckLDAPStatus.py` as reference.

Search targets:

```text
Impacket 0.13 CheckLDAPStatus SASL signing channel binding
Microsoft LDAP signing channel binding Windows Server 2025
```

## 10. LDAP security descriptor flags

Default:

```text
sdflags = 0x5
```

Meaning:

```text
OWNER_SECURITY_INFORMATION = 0x1
GROUP_SECURITY_INFORMATION = 0x2
DACL_SECURITY_INFORMATION  = 0x4
SACL_SECURITY_INFORMATION  = 0x8
```

Why default 0x5:

- need owner for owner-implied rights.
- need DACL for ACE evaluation.
- avoid SACL access failures.

Add knobs:

```bash
--sdflags 0x4
--sdflags 0x5
--sdflags 0x7
--try-sacl
```

`--try-sacl` should request SACL and handle access denial without crashing.

## 11. Confidential attributes

Detect confidential attributes through schema `searchFlags`.

Rule:

```python
is_confidential = bool(searchFlags & 0x80)
```

Important: normal `RIGHT_DS_READ_PROPERTY` is not enough for confidential attributes. There is an extended/control access requirement. The effective-rights engine should mark confidential reads as blocked unless the required extended right is present.

Do not say this is controlled by `dSHeuristics`.

## 12. Effective rights engine

This is the highest-risk engineering part.

Required logic:

```text
- direct SID match
- nested group membership
- Everyone
- Authenticated Users
- SELF
- CREATOR OWNER
- OWNER RIGHTS SID
- explicit DENY before ALLOW
- inherited ACEs
- object-specific ACEs
- GenericAll
- GenericWrite
- WriteDACL
- WriteOwner
- CreateChild all-object
- CreateChild object-specific dMSA class GUID
- WriteProperty all-attribute
- WriteProperty object-specific attribute GUID
- property-set support when possible
- owner-implied WriteDACL
```

Pitfalls:

- GUID endianness in object-specific ACEs.
- inherited ACE applicability.
- owner-implied rights restricted by OWNER RIGHTS SID.
- false positives when ignoring DENY ACEs.
- false negatives when not expanding nested groups.

The tool should be more precise than existing scanners.

## 13. Path classifiers

### 13.1 postpatch-mutual-pair

Main 2026 path.

Requires:

```text
dmsa_capable = true

AND

can create/control a dMSA

AND

can write dMSA-side:
  - msDS-DelegatedMSAState
  - msDS-ManagedAccountPrecededByLink

AND

can write target-side:
  - msDS-SupersededManagedAccountLink
  - msDS-SupersededServiceAccountState
```

Important:

- target-side writes are checked on the target account.
- dMSA-side writes are checked on the dMSA.

### 13.2 existing-dmsa-postpatch-mutual

Direct existing-dMSA postpatch use requires dMSA-side migration control:

```text
GenericAll
GenericWrite
WriteProperty:msDS-ManagedAccountPrecededByLink
WriteProperty:msDS-DelegatedMSAState
```

AND exact target-side reciprocal writes:

```text
WriteProperty:msDS-SupersededManagedAccountLink
WriteProperty:msDS-SupersededServiceAccountState
```

Do not treat WriteDACL, WriteOwner, msDS-KeyCredentialLink, or
msDS-GroupMSAMembership as direct migration-link control. Those are separate
candidate surfaces or future DACL-escalation work.

### 13.3 existing-dmsa-legacy-link

Legacy/lab existing-dMSA mode writes only the dMSA-side migration attributes. It
requires an explicit legacy flag and does not establish patched post-BadSuccessor
mutual state unless the target-side reciprocal attributes are already present.

### 13.4 legacy-oneway-link

Legacy direct path.

Condition:

```text
unpatched/pre-CVE-2025-53779 behavior or lab/CTF target
```

Do not prioritize over postpatch mutual pair.

### 13.5 self-write-map

Once dMSA is controlled, enumerate inherited/default self-write surfaces.

The dMSA class inherits from `computer`. The default security descriptor and inherited rights matter.

Known interesting surfaces:

```text
msDS-KeyCredentialLink
msDS-AllowedToActOnBehalfOfOtherIdentity
Personal Information property set
Web Information property set
Private Information property set
```

Validate against Microsoft schema and Huntress writeup before implementing.

### 13.6 self-pkinit-loop

Formerly discussed as "Ouroboros". Use technical name in code:

```text
self-pkinit-loop
```

Candidate conditions:

```text
can write msDS-KeyCredentialLink on dMSA
AND
can write msDS-GroupMSAMembership on dMSA
```

Do not claim Microsoft treats it as a separate CVE. Huntress argues it should be separate, but Microsoft reportedly treated it as duplicate of existing dMSA surface. For implementation, model it as a distinct primitive because the conditions differ.

Known gotcha:

`msDS-GroupMSAMembership` must be a proper NT security descriptor. Naive SID list handling is wrong.

Huntress noted the KDC authorization check may require expanded rights, not generic shorthand. Verify exact SDDL/ACE requirements from current research before implementing.

## 14. Primitive engine

Each primitive is a plugin:

```python
class Primitive:
    name: str
    modifies_directory: bool

    def check(self, ctx, path): ...
    def plan(self, ctx, path): ...
    def execute(self, ctx, plan): ...
    def verify(self, ctx, op): ...
    def rollback(self, ctx, op): ...
```

Implement order:

```text
1. postpatch-mutual-pair
2. existing-dmsa-postpatch-mutual
3. existing-dmsa-legacy-link
4. legacy-oneway-link
5. self-write-map
6. self-pkinit-loop candidate
7. KDS/golden-style exposure later
```

## 15. Operation logging and rollback

Mandatory for all LDAP writes.

Store under:

```text
.reaper/operations/OP-xxxx.json
```

Rules:

- write operation log before LDAP modify.
- for attribute modification, read and store previous value before write.
- for object creation, store intended DN before creation.
- rollback in reverse order.
- verify rollback before declaring success.
- if step 2 fails after step 1 succeeds, rollback step 1 immediately.

This is especially important for postpatch-mutual-pair, where both dMSA-side and target-side writes are needed.

## 16. Kerberos verification

Do not reimplement Kerberos first.

V0/V1:

```text
verify --mode ldap
```

Later:

```text
verify --mode rubeus
verify --mode external
verify --mode native
```

Rubeus PR #194 is the reference for dMSA Kerberos support. PR #204 may be needed for improved parsing depending on current status.

Native Python Kerberos is later work.

## 17. Minimal build order

### V0 — Mapper foundation

```text
[ ] CLI skeleton
[ ] LDAP/LDAPS auth
[ ] RootDSE discovery
[ ] Schema resolver
[ ] KDS root key existence check
[ ] Server 2025 DC detection
[ ] Current user SID + nested group expansion
[ ] dMSA object enumeration
[ ] OU/container enumeration
[ ] target object enumeration
[ ] SD retrieval with sdflags=0x5
[ ] ACL parsing
[ ] confidential attribute detection
[ ] JSON state output
```

### V1 — Effective rights and paths

```text
[ ] DENY precedence
[ ] inherited ACEs
[ ] object-specific ACE matching
[ ] owner-implied rights
[ ] CreateChild:dMSA detection
[ ] WriteProperty:specific-attribute detection
[ ] postpatch-mutual-pair classifier
[ ] existing-dmsa-postpatch-mutual classifier
[ ] existing-dmsa-legacy-link classifier
[ ] legacy-oneway-link classifier
[ ] path output
```

### V2 — First controlled exploit primitive

```text
[ ] operation log
[ ] rollback model
[ ] create-controlled-dMSA primitive
[ ] dMSA-side migration attribute modify
[ ] target-side reciprocal attribute modify
[ ] LDAP-state verification
[ ] reverse-order rollback
```

### V3 — Advanced primitives

```text
[ ] self-write-map
[ ] self-pkinit-loop candidate
[ ] Rubeus adapter
[ ] external verifier
```

### V4 — Optional

```text
[ ] BloodHound/OpenGraph export
[ ] KDS/golden-style exposure module
[ ] native Kerberos parser
```

## 18. Testing plan

Unit tests must not require live AD where possible.

Fixtures:

- fake schema entries.
- fake rootDSE.
- fake DACL/security descriptors.
- fake nested group graph.
- fake dMSA/target objects.
- fake operation logs.

Required tests:

```text
- schema resolver returns GUIDs dynamically.
- confidential searchFlags detection.
- SD flags parser.
- object-specific ACE GUID matching.
- DENY before ALLOW.
- nested groups.
- owner-implied WriteDACL.
- CreateChild:dMSA.
- WriteProperty specific attr.
- attribute lives_on mapping.
- KDS root key absence disables dmsa_capable.
- postpatch-mutual-pair classifier.
- existing-dmsa-postpatch-mutual classifier.
- existing-dmsa-legacy-link classifier.
- legacy-oneway-link classifier.
- operation log is written before modify.
- rollback runs reverse order.
```

## 19. Important wording choices

Use:

```text
controlled primitive executor
postpatch-mutual-pair
legacy-oneway-link
self-pkinit-loop
LDAP-state verification
operation rollback
```

Avoid in public docs:

```text
quietest path
stealth
evasion
mass hash dumping
automatic domain compromise
surrogate process
MDI bypass
SACL avoidance
```

The tool can still be offensive. The wording should remain precise and professional.

## 20. Open questions Codex should verify before implementing

When unsure, search these topics:

```text
current Rubeus dMSA support merged status
current Impacket badsuccessor.py implementation details
current Metasploit bad_successor module actions
current Microsoft schema docs for new dMSA attributes
current Windows Server 2025 LDAP signing/channel binding defaults
current Huntress dMSA Ouroboros SDDL exact requirements
current Akamai post-patch BadSuccessor implementation notes
current BloodHound OpenGraph custom edge schema
```

Primary sources are preferred:

```text
Microsoft Open Specifications
Microsoft Learn Windows Server dMSA docs
GitHub source code of Impacket / NetExec / Metasploit / Rubeus
Akamai / SpecterOps / Huntress / Semperis research posts
```
