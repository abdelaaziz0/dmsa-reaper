# Codex Prompt — Build dMSA-Reaper

You are Codex. Build a Python CLI tool named `dmsa-reaper`.

## Mission

Create an Active Directory dMSA abuse-path mapper and controlled primitive executor for authorized Windows Server 2025 assessments.

The tool must follow this workflow:

```text
map -> paths -> exploit -> verify -> rollback
```

The tool is not a reporting platform, dashboard, C2, or generic AD scanner. It maps dMSA-specific abuse paths and executes selected dMSA primitives under explicit operator control.

## Scope

Implement the project in Python 3.11+.

Core commands:

```bash
dmsa-reaper map
dmsa-reaper paths
dmsa-reaper exploit
dmsa-reaper verify
dmsa-reaper rollback
```

The MVP should prioritize accurate mapping, effective ACL evaluation, schema resolution, path classification, operation logging, and safe rollback.

Do not implement stealth/evasion features, automatic domain-wide exploitation, or mass credential extraction. Do not implement report generation, dashboards, PDF/HTML output, or blue-team-only audit packaging.

## Required behavior

### `map`

Build a complete dMSA-relevant state model.

Required checks:

- LDAP/LDAPS bind.
- Kerberos ccache support where practical.
- RootDSE discovery:
  - `defaultNamingContext`
  - `configurationNamingContext`
  - `schemaNamingContext`
- Schema resolver:
  - dynamically resolve class/attribute GUIDs.
  - do not rely on hardcoded dMSA GUIDs except as fallback.
- dMSA schema presence.
- Windows Server 2025 DC presence.
- KDS root key existence.
- Current principal SID and nested group memberships.
- dMSA object enumeration.
- OU/container enumeration.
- Target account enumeration.
- Owner + DACL retrieval with LDAP SD flags default `0x5`:
  - `OWNER_SECURITY_INFORMATION = 0x1`
  - `DACL_SECURITY_INFORMATION = 0x4`
- Optional SACL retrieval only via explicit `--try-sacl`.
- Effective rights evaluation:
  - DENY ACE precedence.
  - inherited ACEs.
  - object-specific ACEs.
  - owner-implied rights.
  - nested groups.
  - `SELF`, `CREATOR OWNER`, `Authenticated Users`, `Everyone`.
  - `OWNER RIGHTS` SID handling.
- Confidential attribute detection through `searchFlags & 0x80`.
- Attribute-to-object-side mapping:
  - dMSA-side attributes must be checked on dMSA objects.
  - target-side attributes must be checked on target accounts.

State output:

```bash
dmsa-reaper map --json state.json
```

### `paths`

Consume map state and compute executable dMSA abuse paths.

Prioritize these path classes:

1. `postpatch-mutual-pair`
2. `existing-dmsa-postpatch-mutual`
3. `legacy-oneway-link`
4. `self-write-map`
5. `self-pkinit-loop` candidate
6. `kds-exposure` candidate

A path must include:

- path ID.
- principal.
- target object.
- dMSA object or container.
- primitive name.
- required rights.
- whether the path requires creating a dMSA.
- whether the path requires modifying an existing dMSA.
- whether the path requires modifying a target account.
- verification method available.
- rollback availability.

Example output:

```text
P-0001 postpatch-mutual-pair HIGH
  principal: CORP\svc-web
  container: OU=Apps,DC=corp,DC=local
  target: CN=svc-backup,CN=Users,DC=corp,DC=local
  required:
    - CreateChild:msDS-DelegatedManagedServiceAccount on OU=Apps
    - WriteProperty:msDS-SupersededManagedAccountLink on target
    - WriteProperty:msDS-SupersededServiceAccountState on target
  exploit:
    dmsa-reaper exploit --path P-0001 --confirm
```

### `exploit`

Execute one selected path or one selected primitive.

Required:

- `--confirm` is mandatory for any LDAP write.
- All write primitives must create a durable operation log before modifying LDAP.
- If multi-step writes fail, rollback previous successful writes in reverse order.
- Do not automatically exploit all paths.

Commands:

```bash
dmsa-reaper exploit --path P-0001 --confirm
dmsa-reaper exploit postpatch-mutual-pair --path P-0001 --confirm
dmsa-reaper exploit existing-dmsa-postpatch-mutual --path P-0002 --confirm
dmsa-reaper exploit legacy-oneway-link --path P-0003 --confirm
```

### `verify`

Support at least LDAP-state verification in MVP.

Future adapters can be added for Rubeus or external ticket tooling.

Commands:

```bash
dmsa-reaper verify --op OP-0001 --mode ldap
dmsa-reaper verify --op OP-0001 --mode external
```

### `rollback`

Every LDAP write must be reversible when technically possible.

Commands:

```bash
dmsa-reaper rollback --op OP-0001
```

Rollback must:

- process changes in reverse order.
- restore previous values.
- delete objects created by the tool only if they did not exist before.
- verify rollback state.
- never claim rollback success without LDAP verification.

## Project layout

Use this structure:

```text
dmsa_reaper/
├── cli.py
├── auth/
│   ├── ldap_bind.py
│   ├── kerberos.py
│   ├── ldaps.py
│   └── channel_binding.py
├── schema/
│   ├── resolver.py
│   ├── guids.py
│   └── searchflags.py
├── ldap/
│   ├── rootdse.py
│   ├── query.py
│   ├── sd_control.py
│   └── modify.py
├── acl/
│   ├── parser.py
│   ├── effective_rights.py
│   ├── ace_matcher.py
│   ├── group_expansion.py
│   └── owner_rights.py
├── map/
│   ├── environment.py
│   ├── dmsa_objects.py
│   ├── containers.py
│   ├── targets.py
│   └── kds.py
├── paths/
│   ├── model.py
│   ├── classifier.py
│   └── ranking.py
├── primitives/
│   ├── base.py
│   ├── postpatch_mutual_pair.py
│   ├── existing_dmsa_control.py
│   ├── legacy_oneway_link.py
│   ├── self_write_map.py
│   └── self_pkinit_loop.py
├── ops/
│   ├── operation_log.py
│   ├── verify.py
│   └── rollback.py
└── output/
    ├── console.py
    └── json.py
tests/
pyproject.toml
README.md
```

## Libraries

Prefer:

```text
typer
rich
pydantic
ldap3
impacket
dnspython
networkx
pytest
```

Use `impacket.ldap.ldaptypes` for security descriptor parsing where possible.

## Data models

Use Pydantic or dataclasses.

Minimum models:

```python
class Environment:
    domain: str
    forest: str | None
    default_nc: str
    config_nc: str
    schema_nc: str
    has_dmsa_schema: bool
    has_server_2025_dc: bool
    has_kds_root_key: bool
    dmsa_capable: bool

class SchemaCache:
    schema_nc: str
    config_nc: str
    object_version: int | None
    dmsa_class_guid: str | None
    attr_guids: dict[str, str]
    search_flags: dict[str, int]
    confidential_attrs: list[str]

class Principal:
    name: str
    sid: str
    groups: list[str]

class DmsaObject:
    dn: str
    sam: str | None
    sid: str | None
    state: int | None
    group_msa_membership_raw: bytes | None
    preceded_by: str | None
    superseded_link: str | None
    key_credential_link_present: bool
    owner_sid: str | None

class ContainerObject:
    dn: str
    owner_sid: str | None
    rights: list

class TargetObject:
    dn: str
    sam: str | None
    sid: str | None
    object_classes: list[str]
    owner_sid: str | None
    writable_attrs: list[str]

class Finding:
    id: str
    primitive: str
    principal: str
    object_dn: str
    rights: list[str]
    confidence: str

class Path:
    id: str
    primitive: str
    principal: str
    dmsa_dn: str | None
    container_dn: str | None
    target_dn: str | None
    required_rights: list[str]
    requires_create_dmsa: bool
    requires_modify_dmsa: bool
    requires_modify_target: bool
    verification_modes: list[str]
    rollback_available: bool

class AttributeChange:
    dn: str
    attribute: str
    before: list | None
    after: list | None
    mode: str

class Operation:
    id: str
    primitive: str
    path_id: str
    created_dns: list[str]
    changed_attrs: list[AttributeChange]
    verified: bool
    rollback_available: bool
```

## Important technical rules

### Schema

Resolve these dynamically from the Schema NC:

- `msDS-DelegatedManagedServiceAccount`
- `msDS-DelegatedMSAState`
- `msDS-ManagedAccountPrecededByLink`
- `msDS-SupersededManagedAccountLink`
- `msDS-SupersededManagedAccountLinkBL`
- `msDS-SupersededServiceAccountState`
- `msDS-GroupMSAMembership`
- `msDS-KeyCredentialLink`

Hardcoded fallback values may be included only if clearly marked as fallback.

Known stable references:

- `msDS-DelegatedManagedServiceAccount` schemaIDGUID:
  - `0feb936f-47b3-49f2-9386-1dedc2c23765`
- `msDS-ManagedAccountPrecededByLink` schemaIDGUID:
  - `a0945b2b-57a2-43bd-b327-4d112a4e8bd1`
- `msDS-SupersededManagedAccountLink` schemaIDGUID:
  - `3752e002-43be-48c8-b3ca-2cb2fffbc8a1`
- `msDS-GroupMSAMembership` systemIdGuid:
  - `888eedd6-ce04-df40-b462-b8a50e41ba38`

### Attribute side mapping

Do not conflate dMSA-side and target-side attributes.

```text
msDS-DelegatedMSAState              -> dMSA
msDS-ManagedAccountPrecededByLink   -> dMSA
msDS-GroupMSAMembership             -> dMSA
msDS-KeyCredentialLink              -> dMSA / user / computer depending on object
msDS-SupersededManagedAccountLink   -> target account
msDS-SupersededServiceAccountState  -> target account
```

### KDS root key

KDS root key existence is a hard environment gate.

Search:

```text
CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,<ConfigNC>
```

If there is no KDS root key, set:

```text
dmsa_capable = false
```

### msDS-ManagedPassword

Do not model `msDS-ManagedPassword` as a normal readable attribute in V0.

It is constructed and authorization depends on the security descriptor stored in `msDS-GroupMSAMembership`, not normal object DACL readability.

### Confidential attributes

Detect confidential attributes with:

```text
searchFlags & 0x80
```

If an attribute is confidential, normal `ReadProperty` is not enough. The tool should mark confidential-read assumptions as blocked unless the required extended access/control right is present.

### LDAP SD flags

Default:

```text
sdflags = 0x5  # OWNER | DACL
```

Options:

```bash
--sdflags 0x4
--sdflags 0x5
--sdflags 0x7
--try-sacl
```

`--try-sacl` must request SACL explicitly and handle access denial cleanly.

### Effective rights

The ACL engine is the most important part.

Implement:

- ACE matching by SID.
- nested group SIDs.
- deny before allow.
- inherited ACEs.
- `GenericAll`.
- `GenericWrite`.
- `WriteDACL`.
- `WriteOwner`.
- `CreateChild` all-object and object-specific.
- `WriteProperty` all-attribute and object-specific.
- property-set support if implemented.
- owner-derived `WriteDACL`.
- `OWNER RIGHTS` SID restrictions.
- correct GUID endianness handling for object-specific ACEs.

### Path classification

Implement these classifiers:

#### `postpatch-mutual-pair`

Requires:

- dMSA capability.
- can create/control a dMSA.
- can write dMSA-side migration attributes on dMSA:
  - `msDS-DelegatedMSAState`
  - `msDS-ManagedAccountPrecededByLink`
- can write target-side reciprocal attributes on target:
  - `msDS-SupersededManagedAccountLink`
  - `msDS-SupersededServiceAccountState`

This is the main 2026 path.

#### `existing-dmsa-postpatch-mutual`

Requires:

- current principal can write both dMSA-side migration attributes directly, via
  `GenericAll`, via `GenericWrite`, or via both specific WriteProperty rights:
  - `GenericAll`
  - `GenericWrite`
  - `WriteProperty:msDS-ManagedAccountPrecededByLink`
  - `WriteProperty:msDS-DelegatedMSAState`
- current principal can write both target-side reciprocal attributes:
  - `WriteProperty:msDS-SupersededManagedAccountLink`
  - `WriteProperty:msDS-SupersededServiceAccountState`

`WriteDACL`, `WriteOwner`, `msDS-KeyCredentialLink`, and
`msDS-GroupMSAMembership` are not direct proof for this primitive.

#### `existing-dmsa-legacy-link`

Lab/legacy mode that writes only dMSA-side migration attributes. It requires
an explicit legacy flag and is not enough for patched post-BadSuccessor behavior
unless target-side reciprocal state is already present.

#### `legacy-oneway-link`

Legacy/pre-patch path.

Do not prioritize this path. It exists for labs, CTFs, and unpatched Windows Server 2025 DCs.

#### `self-write-map`

After dMSA control, enumerate what the dMSA principal can write to itself or sensitive attributes it can influence.

#### `self-pkinit-loop`

Candidate only in MVP.

Requires:

- write access to `msDS-KeyCredentialLink` on dMSA.
- write access to `msDS-GroupMSAMembership` on dMSA.

Do not implement native Kerberos PKINIT in MVP. Add adapter later.

## Operation logging

Write operation logs before each LDAP modify.

Store operations under:

```text
.reaper/operations/OP-xxxx.json
```

Rules:

- If creating an object, log the intended DN before create.
- If modifying an attribute, read and log previous values before write.
- If a two-step primitive fails after step 1, rollback step 1 immediately.
- Rollback must run reverse-order changes.

## Existing tooling to compare against

Do not clone a single tool. dMSA-Reaper’s differentiator is the mapper/path engine.

Existing tools and limits:

- Akamai BadSuccessor PowerShell scanner:
  - finds OU permissions.
  - does not expand group membership.
  - does not fully evaluate DENY ACEs/effective permissions.
- NetExec `badsuccessor` module:
  - useful enumeration module.
  - not a full path engine.
- Impacket `examples/badsuccessor.py`:
  - operational primitive tooling.
  - not a full effective-rights mapper/path engine.
- Metasploit `auxiliary/admin/ldap/bad_successor`:
  - closest comparable exploitation module.
  - supports BadSuccessor-oriented actions.
  - still primitive-oriented, not a dMSA-wide mapper/path engine.
- Rubeus:
  - reference for dMSA Kerberos support.
  - use external adapter first; do not reimplement Kerberos in V0.
- BloodHound:
  - dMSA primitives are not yet first-class mainstream edges/workflow.
  - OpenGraph export is optional later, not MVP.

## Testing

Create unit tests for:

- schema GUID decoding and lookup.
- searchFlags confidential detection.
- SD flags builder.
- ACE GUID matching, including little-endian object GUID conversion.
- deny precedence.
- nested group effective rights.
- owner-implied rights.
- CreateChild:dMSA detection.
- WriteProperty:specific-attribute detection.
- path classifier:
  - postpatch-mutual-pair.
  - existing-dMSA-control.
  - legacy-oneway-link.
- operation log creation before modify.
- rollback reverse-order behavior.

Use fixtures for security descriptors rather than requiring a live AD in unit tests.

## Delivery target

Build the V0/V1 skeleton first:

- CLI works.
- `map` can connect and output structured JSON.
- schema resolver works.
- environment checks work.
- ACL parser has tests.
- path classifier runs on JSON fixtures.
- exploit primitives can be scaffolded with safe interfaces and operation logging.
- at least one controlled LDAP write primitive can be implemented only after mapping and rollback are working.

Prefer correctness over breadth.
