from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)
from typer.testing import CliRunner

from dmsa_reaper.acl.parser import parse_security_descriptor
from dmsa_reaper.cli import app
from dmsa_reaper.models import (
    AttributeChange,
    AttributeValue,
    CheckStatus,
    ContainerObject,
    DmsaObject,
    Environment,
    MapState,
    Operation,
    Principal,
    Right,
    SchemaCache,
    TargetObject,
)
from dmsa_reaper.ops.cleanup import cleanup_operation
from dmsa_reaper.ouroboros.checks import (
    active_ouroboros_findings,
    classify_ouroboros_paths,
)
from dmsa_reaper.ouroboros.credentials import generate_shadow_credential
from dmsa_reaper.ouroboros.extract import extract_ouroboros_credentials
from dmsa_reaper.primitives._ldap_helpers import (
    build_group_msa_membership_sd_for_sids,
)


class OuroborosTests(unittest.TestCase):
    @staticmethod
    def _capable_state() -> MapState:
        sid = "S-1-5-21-1-2-3-1100"
        container_dn = "OU=Services,DC=corp,DC=local"
        target_dn = "CN=svc_sql,OU=Services,DC=corp,DC=local"
        return MapState(
            environment=Environment(
                domain="corp.local",
                dmsa_capable_status=CheckStatus.present,
            ),
            schema_cache=SchemaCache(),
            current_principal=Principal(name="operator", sid=sid),
            containers=[
                ContainerObject(
                    dn=container_dn,
                    rights=[
                        Right(
                            principal_sid=sid,
                            right="CreateChild:dMSA",
                            object_dn=container_dn,
                        )
                    ],
                )
            ],
            targets=[
                TargetObject(
                    dn=target_dn,
                    sam="svc_sql",
                    writable_attrs=[
                        "msDS-SupersededManagedAccountLink",
                        "msDS-SupersededServiceAccountState",
                    ],
                )
            ],
        )

    def test_membership_descriptor_uses_expanded_rights_for_every_sid(self) -> None:
        sids = ["S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"]
        parsed = parse_security_descriptor(
            build_group_msa_membership_sd_for_sids(sids)
        )
        self.assertFalse(parsed.parse_failed)
        self.assertEqual({ace.sid for ace in parsed.aces}, set(sids))
        for ace in parsed.aces:
            self.assertEqual(ace.ace_type, "allow")
            self.assertTrue(
                {"ControlAccess", "WriteProperty", "WriteDACL", "WriteOwner"}
                <= ace.rights
            )
            self.assertNotIn("GenericAll", ace.rights)

    def test_shadow_credential_pfx_matches_keycredential(self) -> None:
        material = generate_shadow_credential(
            subject="ouro-test$",
            owner_dn="CN=ouro-test,DC=corp,DC=local",
            pfx_password="correct horse battery staple",
        )
        key, certificate, _ = load_key_and_certificates(
            material.pfx_bytes,
            b"correct horse battery staple",
        )
        self.assertIsNotNone(key)
        self.assertIsNotNone(certificate)
        self.assertTrue(material.key_credential_value.startswith("B:"))
        self.assertTrue(
            material.key_credential_value.endswith(
                ":CN=ouro-test,DC=corp,DC=local"
            )
        )

    def test_classifies_only_full_postpatch_capability(self) -> None:
        state = self._capable_state()
        paths = classify_ouroboros_paths(state)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].primitive, "ouroboros")
        self.assertTrue(paths[0].id.startswith("OURO-"))
        self.assertEqual(
            paths[0].target_dn,
            "CN=svc_sql,OU=Services,DC=corp,DC=local",
        )

    def test_cli_exploit_dry_run_uses_ouroboros_workflow(self) -> None:
        runner = CliRunner()
        with patch("dmsa_reaper.cli.run_live_map", return_value=self._capable_state()):
            result = runner.invoke(
                app,
                [
                    "ouroboros",
                    "exploit",
                    "--target-account",
                    "svc_sql",
                    "--domain",
                    "corp.local",
                    "--dry-run",
                ],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("STAGE 3", result.output)
        self.assertIn("msDS-KeyCredentialLink", result.output)
        self.assertIn("No LDAP writes were made", result.output)

    def test_finds_complete_and_partial_persistence_indicators(self) -> None:
        state = MapState(
            environment=Environment(),
            schema_cache=SchemaCache(),
            dmsas=[
                DmsaObject(
                    dn="CN=complete,DC=corp,DC=local",
                    key_credential_count=1,
                    ouroboros_self_authorized=True,
                ),
                DmsaObject(
                    dn="CN=partial,DC=corp,DC=local",
                    key_credential_count=2,
                ),
                DmsaObject(dn="CN=clean,DC=corp,DC=local"),
            ],
        )
        findings = active_ouroboros_findings(state)
        self.assertEqual([item["status"] for item in findings], [
            "active-ouroboros",
            "partial-indicator",
        ])

    def test_extract_writes_protected_structured_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            pfx_path = run_dir / "ouroboros.pfx"
            pfx_path.write_bytes(b"pfx")
            manifest_path = run_dir / "ouroboros-credential.json"
            manifest_path.write_text(
                json.dumps({"pfx_password": "secret"}),
                encoding="utf-8",
            )
            operation = Operation(
                id="OP-20260803-deadbeef",
                primitive="ouroboros",
                status="executed",
                metadata={
                    "domain": "corp.local",
                    "dc_ip": "10.0.0.10",
                    "created_dmsa_sam": "ouro-test$",
                    "target_dn": "CN=svc_sql,DC=corp,DC=local",
                    "ouroboros": {
                        "run_dir": str(run_dir),
                        "pfx_path": str(pfx_path),
                        "credential_manifest": str(manifest_path),
                    },
                },
            )
            package = {
                "current-keys": [
                    {"keytype": 18, "keyvalue": bytes.fromhex("11" * 32)}
                ],
                "previous-keys": [
                    {"keytype": 23, "keyvalue": bytes.fromhex("22" * 16)}
                ],
            }
            with patch(
                "dmsa_reaper.ouroboros.extract._request_key_package",
                new=AsyncMock(return_value=package),
            ):
                result = extract_ouroboros_credentials(operation)
            self.assertEqual(result["candidate_target_nt_hashes"], ["22" * 16])
            artifact = Path(result["artifact"])
            self.assertTrue(artifact.is_file())
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

    def test_cleanup_deletes_ouroboros_dmsa_despite_target_conflict(self) -> None:
        target_change = AttributeChange(
            dn="CN=svc_sql,DC=corp,DC=local",
            attribute="msDS-SupersededServiceAccountState",
            before=[AttributeValue.from_python(0)],
            after=[AttributeValue.from_python(2)],
            mode="replace",
        )
        internal_change = AttributeChange(
            dn="CN=ouro-test,DC=corp,DC=local",
            attribute="msDS-KeyCredentialLink",
            before=None,
            after=[AttributeValue.from_python("B:1:0:DN")],
            mode="replace",
        )
        operation = Operation(
            id="OP-20260803-feedface",
            primitive="ouroboros",
            status="executed",
            created_dns=["CN=ouro-test,DC=corp,DC=local"],
            changed_attrs=[target_change, internal_change],
        )
        conflict = {
            "dn": target_change.dn,
            "attribute": target_change.attribute,
            "status": "conflict",
            "reason": "third-party change",
        }
        deleted = {
            "dn": internal_change.dn,
            "status": "cleaned",
            "reason": "deleted GUID-matched created object",
        }
        with (
            patch("dmsa_reaper.ops.cleanup._restore_attribute", return_value=conflict),
            patch(
                "dmsa_reaper.ops.cleanup._cleanup_created_object",
                return_value=deleted,
            ) as cleanup_created,
        ):
            result = cleanup_operation(operation, conn=object())
        cleanup_created.assert_called_once()
        self.assertEqual(result.status, "cleanup-conflict")
        self.assertTrue(
            result.metadata["cleanup"]["ouroboros_persistence_removed"]
        )


if __name__ == "__main__":
    unittest.main()
