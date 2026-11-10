"""Create the release signing key and sign update manifests (Windows, release maintainers).

The private key stays on this computer. It is stored encrypted for the current
Windows account (DPAPI), outside the repository, and is never printed. The app
carries only the public key: ``PUBLIC_KEYS`` in ``src/updater.py``.

    python scripts/release_signing.py keygen
    python scripts/release_signing.py public
    python scripts/release_signing.py sign dist/installer/Odysseus-Setup-1.0.3.exe --version 1.0.3 --release 2

``sign`` writes ``update.json`` and ``update.json.sig`` next to the installer.
Publish both with the installer in a full release tagged ``v<version>-setup.<release>``.

Only this Windows account on this computer can read the key file, so a copy of
it is not a backup. If the account is lost, the key is lost: existing installs
then need one manual install of a release signed with a new key.
"""
import argparse
import base64
import ctypes
import hashlib
import json
import os
import sys
from ctypes import wintypes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def key_file() -> str:
    override = os.environ.get("ODYSSEUS_RELEASE_KEY_FILE", "").strip()
    return override or os.path.join(os.environ["APPDATA"], "Odysseus-Release", "update-signing.key")


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, *, protect: bool) -> bytes:
    """Encrypt or decrypt ``data`` for the current Windows account."""
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    call = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    call.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.POINTER(_Blob), ctypes.c_void_p,
                     ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    call.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buffer = ctypes.create_string_buffer(data, len(data))
    source = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    result = _Blob()
    # 0x1 = CRYPTPROTECT_UI_FORBIDDEN: fail rather than open a prompt.
    if not call(ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(result)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(result.pbData, ctypes.c_void_p))


def _load_key() -> Ed25519PrivateKey:
    try:
        with open(key_file(), "rb") as handle:
            return Ed25519PrivateKey.from_private_bytes(_dpapi(handle.read(), protect=False))
    except FileNotFoundError:
        raise SystemExit(f"No signing key at {key_file()}. Create one with: keygen") from None


def _public_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def keygen() -> str:
    """Create the key, store it protected, and return the public key text."""
    path = key_file()
    if os.path.exists(path):
        raise SystemExit(f"A signing key already exists at {path}. It was left alone.")
    key = Ed25519PrivateKey.generate()
    secret = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "xb") as handle:
        handle.write(_dpapi(secret, protect=True))
    return _public_text(key)


def sign(installer: str, version: str, release: int) -> str:
    """Write the signed manifest for ``installer`` next to it. Returns the manifest path."""
    digest = hashlib.sha256()
    with open(installer, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    manifest = {
        "version": version,
        "release": release,
        "tag": f"v{version}-setup.{release}",
        "file": os.path.basename(installer),
        "size": os.path.getsize(installer),
        "sha256": digest.hexdigest(),
    }
    raw = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    signature = base64.b64encode(_load_key().sign(raw))
    # The app must accept what is published: check with its own verifier first.
    from src import updater
    updater.parse_manifest(raw, signature)
    target = os.path.join(os.path.dirname(os.path.abspath(installer)), updater.MANIFEST_NAME)
    with open(target, "wb") as handle:
        handle.write(raw)
    with open(target + ".sig", "wb") as handle:
        handle.write(signature)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("keygen", help="create the signing key and print its public half")
    commands.add_parser("public", help="print the public half of the signing key")
    sign_args = commands.add_parser("sign", help="write update.json and its signature next to an installer")
    sign_args.add_argument("installer")
    sign_args.add_argument("--version", required=True)
    sign_args.add_argument("--release", required=True, type=int)
    args = parser.parse_args(argv)
    if args.command == "keygen":
        print(keygen())
        print("Put this public key into PUBLIC_KEYS in src/updater.py.", file=sys.stderr)
    elif args.command == "public":
        print(_public_text(_load_key()))
    else:
        print(sign(args.installer, args.version, args.release))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
