# src/updater.py
"""Signed updates for the packaged Windows build.

While the app runs, :func:`stage_latest` reads the signed manifest of the
newest full release, downloads the installer it names and checks it. At the
next start :func:`apply_staged` checks the staged pair again and starts the
installer, which replaces the program files and starts the app again.

Trust rests on one thing: the manifest carries an Ed25519 signature made with
a release key whose public half is in ``PUBLIC_KEYS``. The network, the
release host and the download folder are all treated as untrusted. A manifest
only counts when it describes a release newer than the running one, so an old
signed release cannot be replayed as an update.
"""
import base64
import contextlib
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.constants import APP_RELEASE, APP_VERSION, UPDATE_LOG_FILE, UPDATES_DIR

logger = logging.getLogger(__name__)

RELEASE_REPO = "endale416614-cmd/odysseus"
MANIFEST_NAME = "update.json"
# "latest" is the newest full release: a pre-release or a draft is never delivered.
FEED_URL = f"https://github.com/{RELEASE_REPO}/releases/latest/download/{MANIFEST_NAME}"
# Observed chain: github.com "latest" link -> github.com tag link -> GitHub release asset host.
ALLOWED_HOSTS = frozenset({
    "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
})
# Public halves of the release signing keys (Ed25519, base64). A second entry allows a key change.
PUBLIC_KEYS = (
    "wY1VCLmgyn1tdCxwnxUCZL5MsudtfM8D1t/fjdlIDWo=",
)
MAX_MANIFEST_BYTES = 16 * 1024
MAX_INSTALLER_BYTES = 2 * 1024 ** 3
# A staged release whose installer did not take effect is tried this often, then left alone.
MAX_ATTEMPTS = 2

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")
_TAG_RE = re.compile(r"v\d+(?:\.\d+)*-setup\.\d+")
_FILE_RE = re.compile(r"Odysseus-Setup-\d+(?:\.\d+)*\.exe")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_OFF = {"0", "false", "off", "no"}


class UpdateError(Exception):
    """An update was refused. The message says why, for the log."""


def enabled() -> bool:
    """Updates run in the packaged Windows build unless ODYSSEUS_AUTO_UPDATE switches them off."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return False
    return os.environ.get("ODYSSEUS_AUTO_UPDATE", "1").strip().lower() not in _OFF


def _log(message: str) -> None:
    """Record an update event. At start the app's own logging is not set up yet."""
    logger.info("update: %s", message)
    try:
        os.makedirs(os.path.dirname(UPDATE_LOG_FILE), exist_ok=True)
        with open(UPDATE_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {message}\n")
    except OSError:
        pass


# ---- Manifest ------------------------------------------------------------------

def parse_manifest(raw: bytes, signature: bytes) -> dict:
    """Return the manifest in ``raw`` when ``signature`` proves it genuine and it is well formed.

    :raises UpdateError: the signature matches no release key, or a field is not as expected.
    """
    try:
        proof = base64.b64decode(signature.strip(), validate=True)
    except ValueError as exc:
        raise UpdateError("the manifest signature is not base64") from exc
    for key in PUBLIC_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True)).verify(proof, raw)
            break
        except (InvalidSignature, ValueError):
            continue
    else:
        raise UpdateError("the manifest signature matches no release key")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise UpdateError("the manifest is not JSON") from exc
    # type() rather than isinstance(): True and False are integers too.
    well_formed = (
        isinstance(data, dict)
        and isinstance(data.get("version"), str) and _VERSION_RE.fullmatch(data["version"])
        and type(data.get("release")) is int and data["release"] >= 0
        and isinstance(data.get("tag"), str) and _TAG_RE.fullmatch(data["tag"])
        and isinstance(data.get("file"), str) and _FILE_RE.fullmatch(data["file"])
        and type(data.get("size")) is int and 0 < data["size"] <= MAX_INSTALLER_BYTES
        and isinstance(data.get("sha256"), str) and _SHA256_RE.fullmatch(data["sha256"])
    )
    if not well_formed:
        raise UpdateError("the manifest is malformed")
    return data


def _order(version: str, release: int) -> tuple:
    return tuple(int(part) for part in version.split(".")), release


def is_newer(manifest: dict) -> bool:
    """Whether ``manifest`` describes a release above the running one."""
    return _order(manifest["version"], manifest["release"]) > _order(APP_VERSION, APP_RELEASE)


# ---- Download ------------------------------------------------------------------

def _client() -> httpx.Client:
    return httpx.Client(follow_redirects=False, timeout=httpx.Timeout(15.0, read=60.0))


def _checked(url: str) -> str:
    parts = urlparse(url)
    if parts.scheme != "https" or (parts.hostname or "") not in ALLOWED_HOSTS:
        raise UpdateError("a download link pointed to an unexpected host")
    return url


@contextlib.contextmanager
def _open(client: httpx.Client, url: str, headers: dict | None = None):
    """Yield the response for ``url``, following redirects by hand and checking every hop."""
    for _ in range(6):
        with client.stream("GET", _checked(url), headers=headers or {}) as response:
            if response.is_redirect:
                url = str(response.url.join(response.headers["location"]))
                continue
            yield response
            return
    raise UpdateError("the release host redirected too often")


def _get_small(client: httpx.Client, url: str) -> bytes | None:
    """The content of a small release file, or None when the release does not have it."""
    with _open(client, url) as response:
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise UpdateError(f"the release host answered {response.status_code}")
        body = b""
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > MAX_MANIFEST_BYTES:
                raise UpdateError("a release file is larger than expected")
        return body


def _download(client: httpx.Client, url: str, dest: Path, size: int) -> None:
    """Fetch ``url`` into ``dest``, continuing a partial file. The caller checks the result."""
    have = dest.stat().st_size if dest.exists() else 0
    if have > size:
        dest.unlink()
        have = 0
    if have == size:
        return
    with _open(client, url, {"Range": f"bytes={have}-"} if have else None) as response:
        if response.status_code == 200:
            have = 0  # the server ignored the range: start over
        elif response.status_code != 206:
            raise UpdateError(f"the release host answered {response.status_code}")
        with open(dest, "ab" if have else "wb") as out:
            for chunk in response.iter_bytes(1 << 20):
                have += len(chunk)
                if have > size:
                    raise UpdateError("the installer is larger than the manifest says")
                out.write(chunk)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _installer_ok(manifest: dict, path: Path) -> bool:
    return (path.is_file() and path.stat().st_size == manifest["size"]
            and _sha256(path) == manifest["sha256"])


# ---- Staging -------------------------------------------------------------------

def stage_latest() -> dict | None:
    """Download and check the newest release when it is newer than the running one.

    Returns the manifest once the installer is staged. Never raises: an update
    that cannot be staged must not disturb the running app.
    """
    if not enabled():
        return None
    try:
        return _stage()
    except (UpdateError, httpx.HTTPError, OSError, KeyError, ValueError) as exc:
        _log(f"not staged: {exc or type(exc).__name__}")
        return None


def _stage() -> dict | None:
    root = Path(UPDATES_DIR)
    with _client() as client:
        raw = _get_small(client, FEED_URL)
        if raw is None:
            return None  # no full release with a manifest yet
        signature = _get_small(client, FEED_URL + ".sig")
        if signature is None:
            raise UpdateError("the release has no manifest signature")
        manifest = parse_manifest(raw, signature)
        if not is_newer(manifest):
            return None
        root.mkdir(parents=True, exist_ok=True)
        installer = root / manifest["file"]
        if not _installer_ok(manifest, installer):
            # Named after the content: a partial file of another release is never continued.
            part = root / (manifest["sha256"][:16] + ".part")
            for stale in root.glob("*.part"):
                if stale != part:
                    stale.unlink(missing_ok=True)
            # Tag and file name come from the signed manifest and match fixed patterns.
            url = f"https://github.com/{RELEASE_REPO}/releases/download/{manifest['tag']}/{manifest['file']}"
            _download(client, url, part, manifest["size"])
            if not _installer_ok(manifest, part):
                part.unlink(missing_ok=True)
                raise UpdateError("the downloaded installer does not match the manifest")
            os.replace(part, installer)
    # Written last: apply_staged only ever sees a complete, checked pair.
    (root / (MANIFEST_NAME + ".sig")).write_bytes(signature)
    (root / MANIFEST_NAME).write_bytes(raw)
    _log(f"release {manifest['tag']} is staged and installs at the next start")
    return manifest


def _clear(*, keep_partial: bool = False) -> None:
    """Remove what is staged. A file still in use is left for the next start."""
    root = Path(UPDATES_DIR)
    if root.is_dir():
        for entry in root.iterdir():
            if keep_partial and entry.suffix == ".part":
                continue
            try:
                entry.unlink()
            except OSError:
                pass


# ---- Install at start ----------------------------------------------------------

def apply_staged() -> bool:
    """Start the staged installer when it is genuine and newer. True means: exit now.

    Never raises. Anything doubtful is removed and the app starts as it is.
    """
    if not enabled():
        return False
    try:
        return _apply()
    except (OSError, ValueError) as exc:
        _log(f"not installed: {exc or type(exc).__name__}")
        return False


def _apply() -> bool:
    root = Path(UPDATES_DIR)
    try:
        raw = (root / MANIFEST_NAME).read_bytes()
    except OSError:
        # Nothing staged. A partial download stays for the next round; anything
        # else is a leftover, such as an installer that was still running.
        _clear(keep_partial=True)
        return False
    try:
        manifest = parse_manifest(raw, (root / (MANIFEST_NAME + ".sig")).read_bytes())
    except (UpdateError, OSError) as exc:
        _log(f"staged update removed: {exc}")
        _clear()
        return False
    if not is_newer(manifest):
        _clear()  # the usual case right after a successful update
        return False
    installer = root / manifest["file"]
    if not _installer_ok(manifest, installer):
        _log(f"staged update removed: the installer for {manifest['tag']} does not match its manifest")
        _clear()
        return False
    counter = root / "attempts.json"
    try:
        tried = json.loads(counter.read_text(encoding="utf-8")).get(manifest["tag"], 0)
    except (OSError, ValueError, AttributeError):
        tried = 0
    if type(tried) is not int or tried >= MAX_ATTEMPTS:
        return False  # the installer ran before and the old version is still here
    counter.write_text(json.dumps({manifest["tag"]: tried + 1}), encoding="utf-8")
    _log(f"installing {manifest['tag']} (attempt {tried + 1})")
    _start_installer(str(installer))
    return True


def _start_installer(path: str) -> None:
    """Run the installer on its own, so it can replace the files of this process."""
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    # The installer starts the app again. That copy must come up as a fresh
    # instance, not as a child of this one, hence the reset variable.
    env = {**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"}
    # /SILENT shows the progress window and asks nothing.
    subprocess.Popen(
        [path, "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/RELAUNCH=1"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=flags, close_fds=True, env=env,
    )
