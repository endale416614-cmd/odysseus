"""Tests for signed update manifests, staging and the install at start in src/updater.py."""
import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src import updater

# Taken at import time, before the autouse fixture replaces it.
REAL_ENABLED = updater.enabled
RELEASE_SIGNING = Path(__file__).resolve().parents[1] / "scripts" / "release_signing.py"
ASSETS = "https://release-assets.githubusercontent.com/files/"
WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="the signing tool uses Windows DPAPI")


def _public_text(private):
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def make_release(key, *, version="1.0.3", release=3, payload=b"installer-bytes" * 1000, **overrides):
    manifest = {
        "version": version,
        "release": release,
        "tag": f"v{version}-setup.{release}",
        "file": f"Odysseus-Setup-{version}.exe",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    manifest.update(overrides)
    raw = json.dumps(manifest).encode()
    signature = base64.b64encode(key.sign(raw))
    return raw, signature, payload


@pytest.fixture
def key(monkeypatch):
    private = Ed25519PrivateKey.generate()
    monkeypatch.setattr(updater, "PUBLIC_KEYS", (_public_text(private),))
    return private


@pytest.fixture(autouse=True)
def started(monkeypatch, tmp_path):
    """Isolate the module. Returns the list of installer paths that were started."""
    starts = []

    def record(path):
        starts.append(path)

    monkeypatch.setattr(updater, "UPDATES_DIR", str(tmp_path / "updates"))
    monkeypatch.setattr(updater, "UPDATE_LOG_FILE", str(tmp_path / "update.log"))
    monkeypatch.setattr(updater, "APP_VERSION", "1.0.3")
    monkeypatch.setattr(updater, "APP_RELEASE", 2)
    monkeypatch.setattr(updater, "enabled", lambda: True)
    monkeypatch.setattr(updater, "_start_installer", record)
    return starts


def serve(monkeypatch, raw, signature, payload, **options):
    """Fake release host that answers like the real one. Returns the list of requests it has seen."""
    manifest = json.loads(raw)
    tag, name = manifest["tag"], manifest["file"]
    base = f"https://github.com/{updater.RELEASE_REPO}/releases/download/{tag}/"
    body = options.get("installer_body", payload)
    installer_target = options.get("installer_redirect", ASSETS + name)
    hops = {
        updater.FEED_URL: (options.get("feed_status", 200), base + updater.MANIFEST_NAME),
        updater.FEED_URL + ".sig": (options.get("signature_status", 200), base + updater.MANIFEST_NAME + ".sig"),
        base + updater.MANIFEST_NAME: (200, ASSETS + updater.MANIFEST_NAME),
        base + updater.MANIFEST_NAME + ".sig": (200, ASSETS + updater.MANIFEST_NAME + ".sig"),
        base + name: (200, installer_target),
    }
    bodies = {
        ASSETS + updater.MANIFEST_NAME: raw,
        ASSETS + updater.MANIFEST_NAME + ".sig": signature,
        ASSETS + name: body,
    }
    seen = []

    def handler(request):
        seen.append(request)
        url = str(request.url)
        if url in hops:
            status, target = hops[url]
            if status != 200:
                return httpx.Response(status)
            return httpx.Response(302, headers={"location": target})
        if url == options.get("installer_redirect"):
            # The foreign host offers the genuine installer: only the host check can stop it.
            return httpx.Response(200, content=body)
        if url == ASSETS + name and "range" in request.headers:
            start = int(request.headers["range"].removeprefix("bytes=").partition("-")[0])
            return httpx.Response(206, content=body[start:])
        if url in bodies:
            return httpx.Response(200, content=bodies[url])
        return httpx.Response(404)

    monkeypatch.setattr(
        updater, "_client",
        lambda: httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    return seen


def stage(monkeypatch, key, **options):
    raw, signature, payload = make_release(key)
    serve(monkeypatch, raw, signature, payload, **options)
    return updater.stage_latest()


def _names(folder):
    return sorted(path.name for path in folder.iterdir()) if folder.is_dir() else []


# ---- Manifest ------------------------------------------------------------------

def test_signed_manifest_is_returned(key):
    raw, signature, _ = make_release(key)
    manifest = updater.parse_manifest(raw, signature)
    assert manifest == json.loads(raw)
    assert manifest["tag"] == "v1.0.3-setup.3"


def test_changed_byte_breaks_signature(key):
    raw, signature, _ = make_release(key)
    index = raw.index(b"3")
    tampered = raw[:index] + b"4" + raw[index + 1:]
    with pytest.raises(updater.UpdateError):
        updater.parse_manifest(tampered, signature)


def test_signature_from_other_key_is_refused(key):
    raw, _, _ = make_release(key)
    _, other_signature, _ = make_release(Ed25519PrivateKey.generate())
    with pytest.raises(updater.UpdateError):
        updater.parse_manifest(raw, other_signature)


def test_signature_not_base64_is_refused(key):
    raw, _, _ = make_release(key)
    with pytest.raises(updater.UpdateError):
        updater.parse_manifest(raw, b"%%%")


@pytest.mark.parametrize("overrides", [
    {"file": "..\\evil.exe"},
    {"file": "setup.exe"},
    {"tag": "main"},
    {"size": 0},
    {"size": True},
    {"sha256": "ABC"},
    {"version": "1.0.x"},
    {"release": "3"},
    {"release": True},
], ids=["file-traversal", "file-wrong-name", "tag-not-release", "size-zero", "size-bool",
        "sha256-short", "version-letters", "release-string", "release-bool"])
def test_malformed_signed_manifest_is_refused(key, overrides):
    raw, signature, _ = make_release(key, **overrides)
    with pytest.raises(updater.UpdateError):
        updater.parse_manifest(raw, signature)


@pytest.mark.parametrize("version, release, expected", [
    ("1.0.3", 3, True),
    ("1.0.3", 2, False),
    ("1.0.3", 1, False),
    ("1.0.4", 0, True),
    ("1.0.2", 9, False),
])
def test_is_newer(version, release, expected):
    assert updater.is_newer({"version": version, "release": release}) is expected


# ---- Staging -------------------------------------------------------------------

def test_stage_happy_path(tmp_path, monkeypatch, key):
    raw, signature, payload = make_release(key)
    serve(monkeypatch, raw, signature, payload)
    manifest = updater.stage_latest()
    updates = tmp_path / "updates"
    assert manifest == json.loads(raw)
    assert (updates / manifest["file"]).read_bytes() == payload
    assert (updates / "update.json").read_bytes() == raw
    assert (updates / "update.json.sig").read_bytes() == signature
    assert not list(updates.glob("*.part"))


def test_feed_404_stages_nothing(tmp_path, monkeypatch, key):
    raw, signature, payload = make_release(key)
    serve(monkeypatch, raw, signature, payload, feed_status=404)
    assert updater.stage_latest() is None
    updates = tmp_path / "updates"
    assert not (updates / json.loads(raw)["file"]).exists()
    assert not (updates / "update.json").exists()


def test_release_not_newer_downloads_no_installer(monkeypatch, key):
    raw, signature, payload = make_release(key, release=2)
    seen = serve(monkeypatch, raw, signature, payload)
    assert updater.stage_latest() is None
    installer_name = json.loads(raw)["file"]
    assert not any(installer_name in str(request.url) for request in seen)


@pytest.mark.parametrize("target", [
    "https://evil.example/x.exe",
    "http://release-assets.githubusercontent.com/files/x.exe",
], ids=["other-host", "no-tls"])
def test_installer_redirect_off_the_allowed_hosts_is_not_followed(tmp_path, monkeypatch, key, target):
    raw, signature, payload = make_release(key)
    seen = serve(monkeypatch, raw, signature, payload, installer_redirect=target)
    assert updater.stage_latest() is None
    assert target not in [str(request.url) for request in seen]
    updates = tmp_path / "updates"
    assert not (updates / json.loads(raw)["file"]).exists()
    assert not (updates / "update.json").exists()


def test_installer_bytes_differ_from_manifest(tmp_path, monkeypatch, key):
    raw, signature, payload = make_release(key)
    serve(monkeypatch, raw, signature, payload, installer_body=b"x" * len(payload))
    assert updater.stage_latest() is None
    updates = tmp_path / "updates"
    assert not (updates / json.loads(raw)["file"]).exists()
    assert not (updates / "update.json").exists()
    assert not list(updates.glob("*.part"))


def test_missing_signature_stages_nothing(tmp_path, monkeypatch, key):
    raw, signature, payload = make_release(key)
    serve(monkeypatch, raw, signature, payload, signature_status=404)
    assert updater.stage_latest() is None
    updates = tmp_path / "updates"
    assert not (updates / json.loads(raw)["file"]).exists()
    assert not (updates / "update.json").exists()


def test_partial_download_is_resumed(tmp_path, monkeypatch, key):
    raw, signature, payload = make_release(key)
    manifest = json.loads(raw)
    half = len(payload) // 2
    updates = tmp_path / "updates"
    updates.mkdir()
    part = updates / (manifest["sha256"][:16] + ".part")
    part.write_bytes(payload[:half])
    seen = serve(monkeypatch, raw, signature, payload)
    assert updater.stage_latest() is not None
    assert (updates / manifest["file"]).read_bytes() == payload
    ranges = [request.headers["range"] for request in seen if "range" in request.headers]
    assert f"bytes={half}-" in ranges


def test_stale_partial_file_is_deleted(tmp_path, monkeypatch, key):
    updates = tmp_path / "updates"
    updates.mkdir()
    stale = updates / "deadbeefdeadbeef.part"
    stale.write_bytes(b"old")
    raw, signature, payload = make_release(key)
    serve(monkeypatch, raw, signature, payload)
    assert updater.stage_latest() is not None
    assert not stale.exists()


def test_stage_disabled_makes_no_request(monkeypatch, key):
    raw, signature, payload = make_release(key)
    seen = serve(monkeypatch, raw, signature, payload)
    monkeypatch.setattr(updater, "enabled", lambda: False)
    assert updater.stage_latest() is None
    assert seen == []


# ---- Install at start ----------------------------------------------------------

def test_apply_starts_staged_installer(tmp_path, monkeypatch, key, started):
    manifest = stage(monkeypatch, key)
    assert updater.apply_staged() is True
    updates = tmp_path / "updates"
    assert started == [str(updates / manifest["file"])]
    assert json.loads((updates / "attempts.json").read_text(encoding="utf-8")) == {manifest["tag"]: 1}


def test_apply_refuses_changed_installer(tmp_path, monkeypatch, key, started):
    manifest = stage(monkeypatch, key)
    updates = tmp_path / "updates"
    (updates / manifest["file"]).write_bytes(b"other bytes")
    assert updater.apply_staged() is False
    assert started == []
    assert _names(updates) == []


def test_apply_refuses_changed_manifest(tmp_path, monkeypatch, key, started):
    stage(monkeypatch, key)
    updates = tmp_path / "updates"
    (updates / "update.json").write_bytes((updates / "update.json").read_bytes() + b" ")
    assert updater.apply_staged() is False
    assert started == []
    assert _names(updates) == []


def test_apply_refuses_release_not_newer(tmp_path, monkeypatch, key, started):
    stage(monkeypatch, key)
    updates = tmp_path / "updates"
    monkeypatch.setattr(updater, "APP_RELEASE", 3)
    assert updater.apply_staged() is False
    assert started == []
    assert _names(updates) == []


def test_apply_gives_up_after_max_attempts(tmp_path, monkeypatch, key, started):
    manifest = stage(monkeypatch, key)
    for _ in range(updater.MAX_ATTEMPTS):
        assert updater.apply_staged() is True
    assert updater.apply_staged() is False
    assert len(started) == updater.MAX_ATTEMPTS
    updates = tmp_path / "updates"
    assert (updates / manifest["file"]).exists()
    assert (updates / "update.json").exists()


def test_apply_keeps_lone_partial_file(tmp_path, started):
    updates = tmp_path / "updates"
    updates.mkdir()
    lone = updates / "abcdef0123456789.part"
    lone.write_bytes(b"partial")
    assert updater.apply_staged() is False
    assert lone.exists()
    assert started == []


def test_apply_removes_stray_installer(tmp_path, started):
    updates = tmp_path / "updates"
    updates.mkdir()
    stray = updates / "Odysseus-Setup-1.0.3.exe"
    stray.write_bytes(b"stray")
    assert updater.apply_staged() is False
    assert not stray.exists()
    assert started == []


def test_apply_disabled_touches_nothing(tmp_path, monkeypatch, key, started):
    manifest = stage(monkeypatch, key)
    monkeypatch.setattr(updater, "enabled", lambda: False)
    assert updater.apply_staged() is False
    assert started == []
    updates = tmp_path / "updates"
    assert (updates / manifest["file"]).exists()
    assert (updates / "update.json").exists()


# ---- enabled() -----------------------------------------------------------------

@WINDOWS_ONLY
@pytest.mark.parametrize("value, expected", [
    (None, True),
    ("1", True),
    ("0", False),
    ("false", False),
    ("OFF", False),
    ("no", False),
])
def test_enabled_reads_switch_in_frozen_build(monkeypatch, value, expected):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("ODYSSEUS_AUTO_UPDATE", raising=False)
    if value is not None:
        monkeypatch.setenv("ODYSSEUS_AUTO_UPDATE", value)
    assert REAL_ENABLED() == expected


def test_enabled_false_when_not_frozen(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert REAL_ENABLED() is False


# ---- Signing tool --------------------------------------------------------------

def _load_signing():
    spec = importlib.util.spec_from_file_location("release_signing", RELEASE_SIGNING)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@WINDOWS_ONLY
def test_keygen_creates_protected_key(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_RELEASE_KEY_FILE", str(tmp_path / "key.bin"))
    signing = _load_signing()
    key_path = tmp_path / "key.bin"
    public = signing.keygen()
    assert len(public) == 44
    assert len(base64.b64decode(public, validate=True)) == 32
    blob = key_path.read_bytes()
    assert len(blob) > 32
    secret = signing._dpapi(blob, protect=False)
    assert len(secret) == 32
    assert secret not in blob
    assert public == _public_text(Ed25519PrivateKey.from_private_bytes(secret))
    with pytest.raises(SystemExit):
        signing.keygen()
    assert key_path.read_bytes() == blob


@WINDOWS_ONLY
def test_sign_writes_manifest_the_app_accepts(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_RELEASE_KEY_FILE", str(tmp_path / "key.bin"))
    signing = _load_signing()
    installer = tmp_path / "Odysseus-Setup-1.0.3.exe"
    installer.write_bytes(b"fake installer" * 100)
    public = signing.keygen()
    monkeypatch.setattr(updater, "PUBLIC_KEYS", (public,))
    signing.sign(str(installer), "1.0.3", 3)
    raw = (tmp_path / "update.json").read_bytes()
    signature = (tmp_path / "update.json.sig").read_bytes()
    manifest = updater.parse_manifest(raw, signature)
    content = installer.read_bytes()
    assert manifest["sha256"] == hashlib.sha256(content).hexdigest()
    assert manifest["size"] == len(content)
    assert manifest["file"] == installer.name
    assert manifest["tag"] == "v1.0.3-setup.3"


BACKUP_PASSPHRASE = "a passphrase used only by this test"


def _key_with_backup(tmp_path, monkeypatch):
    """A fresh key in the test folder and its backup. Returns (module, public key, key path, backup path)."""
    key_path = tmp_path / "key.bin"
    monkeypatch.setenv("ODYSSEUS_RELEASE_KEY_FILE", str(key_path))
    signing = _load_signing()
    public = signing.keygen()
    copy = tmp_path / "backup.pem"
    signing.backup(str(copy), BACKUP_PASSPHRASE)
    return signing, public, key_path, copy


@WINDOWS_ONLY
def test_backup_restores_the_same_key_without_the_key_file(tmp_path, monkeypatch):
    signing, public, key_path, copy = _key_with_backup(tmp_path, monkeypatch)
    secret = signing._dpapi(key_path.read_bytes(), protect=False)
    text = copy.read_bytes()
    assert text.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert secret not in text
    with pytest.raises(TypeError):  # it does not open without a passphrase
        serialization.load_pem_private_key(text, password=None)
    key_path.unlink()  # as after the Windows account is gone
    assert signing.restore(str(copy), BACKUP_PASSPHRASE) == public
    assert signing._public_text(signing._load_key()) == public


@WINDOWS_ONLY
def test_restore_refuses_a_wrong_passphrase(tmp_path, monkeypatch):
    signing, _, key_path, copy = _key_with_backup(tmp_path, monkeypatch)
    key_path.unlink()
    with pytest.raises(SystemExit):
        signing.restore(str(copy), "some other passphrase")
    assert not key_path.exists()


@WINDOWS_ONLY
def test_backup_and_restore_never_overwrite(tmp_path, monkeypatch):
    signing, _, key_path, copy = _key_with_backup(tmp_path, monkeypatch)
    key_before, copy_before = key_path.read_bytes(), copy.read_bytes()
    with pytest.raises(SystemExit):
        signing.backup(str(copy), BACKUP_PASSPHRASE)
    with pytest.raises(SystemExit):
        signing.restore(str(copy), BACKUP_PASSPHRASE)
    assert key_path.read_bytes() == key_before
    assert copy.read_bytes() == copy_before


@WINDOWS_ONLY
def test_backup_and_restore_commands_ask_for_the_passphrase(tmp_path, monkeypatch, capsys):
    key_path = tmp_path / "key.bin"
    monkeypatch.setenv("ODYSSEUS_RELEASE_KEY_FILE", str(key_path))
    signing = _load_signing()
    public = signing.keygen()
    copy = tmp_path / "backup.pem"
    entries = iter([BACKUP_PASSPHRASE, "a different second entry"])
    monkeypatch.setattr(signing.getpass, "getpass", lambda prompt: next(entries))
    with pytest.raises(SystemExit):
        signing.main(["backup", str(copy)])
    assert not copy.exists()
    monkeypatch.setattr(signing.getpass, "getpass", lambda prompt: BACKUP_PASSPHRASE)
    assert signing.main(["backup", str(copy)]) == 0
    key_path.unlink()
    assert signing.main(["restore", str(copy)]) == 0
    assert public in capsys.readouterr().out


@WINDOWS_ONLY
def test_backup_refuses_a_short_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_RELEASE_KEY_FILE", str(tmp_path / "key.bin"))
    signing = _load_signing()
    signing.keygen()
    with pytest.raises(SystemExit):
        signing.backup(str(tmp_path / "backup.pem"), "short")
    assert not (tmp_path / "backup.pem").exists()


@WINDOWS_ONLY
def test_sign_refuses_when_app_key_differs(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_RELEASE_KEY_FILE", str(tmp_path / "key.bin"))
    signing = _load_signing()
    installer = tmp_path / "Odysseus-Setup-1.0.3.exe"
    installer.write_bytes(b"fake installer")
    signing.keygen()
    other_public = _public_text(Ed25519PrivateKey.generate())
    monkeypatch.setattr(updater, "PUBLIC_KEYS", (other_public,))
    with pytest.raises(updater.UpdateError):
        signing.sign(str(installer), "1.0.3", 3)
    assert not (tmp_path / "update.json").exists()
