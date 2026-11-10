"""Windows boundary for agent commands: a Job Object plus low integrity.

Two halves in one file.

The application half (``supports_write_boundary``, ``prepare_workspace``) runs
inside the app. The launcher half (``main``) is started by ``containment.run``
in place of the command. It puts itself into a kill-on-close Job Object, lowers
its own integrity level to low, then runs the command and returns its exit
code. Every process the command starts inherits both.

What this enforces: writes are confined to low-labelled folders (the
workspace), and no descendant outlives the launcher. What it does not enforce:
reads. A low-integrity process can read whatever the user can read.

Standard library only, so the launcher starts without the application.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import byref, sizeof

#: Exit code when the boundary could not be established. The command did not run.
EXIT_NO_BOUNDARY = 125
#: Exit code when the boundary held but the command could not be started.
EXIT_NOT_STARTED = 126

_LOW_SID = "S-1-16-4096"
_LOW_LABEL_DIR = "S:(ML;OICI;NW;;;LW)"
_LOW_LABEL_FILE = "S:(ML;;NW;;;LW)"
#: Medium with no-read-up: a low-integrity process cannot open it at all.
_SHIELD_LABEL_DIR = "S:(ML;OICI;NRNW;;;ME)"
#: Medium, the ordinary default, stated explicitly to stop an inherited shield.
_PLAIN_LABEL_DIR = "S:(ML;OICI;NW;;;ME)"
_SE_FILE_OBJECT = 1
_LABEL_SECURITY_INFORMATION = 0x10
_FILE_PERSISTENT_ACLS = 0x8
_DRIVE_REMOTE = 4
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_EXTENDED_LIMIT_INFORMATION = 9
_TOKEN_QUERY = 0x8
_TOKEN_ADJUST_DEFAULT = 0x80
_TOKEN_USER = 1
_TOKEN_INTEGRITY_LEVEL = 25
_SE_GROUP_INTEGRITY = 0x20
_ERROR_ACCESS_DENIED = 5

_VP = ctypes.c_void_p
_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", _VP), ("Attributes", _DWORD)]


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", _DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", _DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", _DWORD), ("SchedulingClass", _DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits), ("IoInfo", ctypes.c_uint64 * 6),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _api():
    """Load the two system libraries with typed prototypes. Windows only."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)

    def proto(dll, name, restype, *argtypes):
        fn = getattr(dll, name)
        fn.restype, fn.argtypes = restype, argtypes

    wstr, pdw = ctypes.c_wchar_p, ctypes.POINTER(_DWORD)
    proto(k32, "GetCurrentProcess", _HANDLE)
    proto(k32, "CloseHandle", _BOOL, _HANDLE)
    proto(k32, "LocalFree", _VP, _VP)
    proto(k32, "GetDriveTypeW", ctypes.c_uint, wstr)
    proto(k32, "GetVolumeInformationW", _BOOL, wstr, _VP, _DWORD, _VP, _VP, pdw, _VP, _DWORD)
    proto(k32, "CreateJobObjectW", _HANDLE, _VP, wstr)
    proto(k32, "SetInformationJobObject", _BOOL, _HANDLE, ctypes.c_int, _VP, _DWORD)
    proto(k32, "AssignProcessToJobObject", _BOOL, _HANDLE, _HANDLE)
    proto(adv, "OpenProcessToken", _BOOL, _HANDLE, _DWORD, ctypes.POINTER(_HANDLE))
    proto(adv, "GetTokenInformation", _BOOL, _HANDLE, ctypes.c_int, _VP, _DWORD, pdw)
    proto(adv, "SetTokenInformation", _BOOL, _HANDLE, ctypes.c_int, _VP, _DWORD)
    proto(adv, "GetLengthSid", _DWORD, _VP)
    proto(adv, "ConvertStringSidToSidW", _BOOL, wstr, ctypes.POINTER(_VP))
    proto(adv, "ConvertSidToStringSidW", _BOOL, _VP, ctypes.POINTER(ctypes.c_wchar_p))
    proto(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", _BOOL, wstr, _DWORD,
          ctypes.POINTER(_VP), _VP)
    proto(adv, "ConvertSecurityDescriptorToStringSecurityDescriptorW", _BOOL, _VP, _DWORD, _DWORD,
          ctypes.POINTER(ctypes.c_wchar_p), _VP)
    proto(adv, "GetSecurityDescriptorSacl", _BOOL, _VP, ctypes.POINTER(_BOOL), ctypes.POINTER(_VP),
          ctypes.POINTER(_BOOL))
    proto(adv, "GetNamedSecurityInfoW", _DWORD, wstr, ctypes.c_int, _DWORD, _VP, _VP, _VP,
          ctypes.POINTER(_VP), ctypes.POINTER(_VP))
    proto(adv, "SetNamedSecurityInfoW", _DWORD, wstr, ctypes.c_int, _DWORD, _VP, _VP, _VP, _VP)
    return k32, adv


def _fail(what: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{what} failed: {ctypes.FormatError(code).strip()}")


# ── Application half ────────────────────────────────────────────────────────
def supports_write_boundary(path: str) -> bool:
    """True when the volume holding ``path`` can store integrity labels.

    Labels need a local volume with persistent permissions (NTFS). A network
    share or a FAT volume cannot hold them, so nothing would confine writes.
    """
    full = os.path.abspath(path)
    if full.startswith("\\\\"):
        return False
    root = os.path.splitdrive(full)[0] + "\\"
    k32, _adv = _api()
    if k32.GetDriveTypeW(root) == _DRIVE_REMOTE:
        return False
    flags = _DWORD()
    if not k32.GetVolumeInformationW(root, None, 0, None, None, byref(flags), None, 0):
        return False
    return bool(flags.value & _FILE_PERSISTENT_ACLS)


def _label_text(k32, adv, path: str) -> str:
    """The integrity label of ``path`` in SDDL form, or "" when it has none."""
    sacl, descriptor = _VP(), _VP()
    if adv.GetNamedSecurityInfoW(path, _SE_FILE_OBJECT, _LABEL_SECURITY_INFORMATION,
                                 None, None, None, byref(sacl), byref(descriptor)):
        return ""
    try:
        text = ctypes.c_wchar_p()
        if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, _LABEL_SECURITY_INFORMATION, byref(text), None):
            return ""
        try:
            return text.value or ""
        finally:
            k32.LocalFree(ctypes.cast(text, _VP))
    finally:
        k32.LocalFree(descriptor)


def has_low_label(path: str) -> bool:
    """True when ``path`` itself carries the low integrity label."""
    k32, adv = _api()
    return ";LW)" in _label_text(k32, adv, path)


def _set_label(adv, k32, path: str, sddl: str) -> int:
    descriptor, present, sacl, defaulted = _VP(), _BOOL(), _VP(), _BOOL()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, byref(descriptor), None):
        raise _fail("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        adv.GetSecurityDescriptorSacl(descriptor, byref(present), byref(sacl), byref(defaulted))
        return adv.SetNamedSecurityInfoW(path, _SE_FILE_OBJECT, _LABEL_SECURITY_INFORMATION,
                                         None, None, None, sacl)
    finally:
        k32.LocalFree(descriptor)


def _own_user_sid(k32, adv) -> str:
    token = _HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), _TOKEN_QUERY, byref(token)):
        raise _fail("OpenProcessToken")
    try:
        size = _DWORD()
        adv.GetTokenInformation(token, _TOKEN_USER, None, 0, byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, _TOKEN_USER, buffer, size, byref(size)):
            raise _fail("GetTokenInformation")
        text = ctypes.c_wchar_p()
        sid = ctypes.cast(buffer, ctypes.POINTER(_SidAndAttributes)).contents.Sid
        if not adv.ConvertSidToStringSidW(sid, byref(text)):
            raise _fail("ConvertSidToStringSidW")
        try:
            return text.value
        finally:
            k32.LocalFree(ctypes.cast(text, _VP))
    finally:
        k32.CloseHandle(token)


def _grant_self_full_control(k32, adv, root: str) -> bool:
    """Give the current user full control of ``root``. Needs ownership of it."""
    grant = subprocess.run(
        ["icacls", root, "/grant", f"*{_own_user_sid(k32, adv)}:(OI)(CI)F", "/C", "/Q"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
    )
    return grant.returncode == 0


def _set_folder_label(k32, adv, folder: str, sddl: str) -> None:
    """Set an inheritable label on ``folder``; existing and new content inherits it."""
    code = _set_label(adv, k32, folder, sddl)
    if code == _ERROR_ACCESS_DENIED and _grant_self_full_control(k32, adv, folder):
        code = _set_label(adv, k32, folder, sddl)
    if code:
        raise OSError(code, f"cannot set the integrity label: {ctypes.FormatError(code).strip()}", folder)


def shield_app_data(root: str, readable: tuple[str, ...] = ()) -> None:
    """Hide ``root`` from low-integrity commands, except the ``readable`` folders.

    ``root`` gets a no-read-up label that its content inherits, including
    files created later. Each folder in ``readable`` that lies inside ``root``
    gets a plain label of its own, so commands can still read it. A folder that
    already carries its own label, such as a prepared workspace, is left alone.
    Cheap when everything is labelled already.

    :raises OSError: a label could not be set. Nothing may run until it can.
    """
    k32, adv = _api()
    root = os.path.realpath(root)
    if "NR" not in _label_text(k32, adv, root):
        _set_folder_label(k32, adv, root, _SHIELD_LABEL_DIR)
    for folder in readable:
        # A link is skipped: it could point the exemption at protected state.
        if not folder or os.path.islink(folder) or not os.path.isdir(folder):
            continue
        folder = os.path.realpath(folder)
        try:
            inside = folder != root and os.path.commonpath([root, folder]) == root
        except ValueError:  # another drive
            inside = False
        if not inside:
            continue
        text = _label_text(k32, adv, folder)
        # "ID" among the entry's flags marks a label inherited from the parent.
        own_label = "(ML;" in text and "ID" not in text.partition("(ML;")[2].partition(";")[0]
        if not own_label:
            _set_folder_label(k32, adv, folder, _PLAIN_LABEL_DIR)


def _label_tree(adv, k32, root: str) -> int:
    """Label ``root`` and everything under it low. Returns the first error code, or 0."""
    code = _set_label(adv, k32, root, _LOW_LABEL_DIR)
    if code:
        return code
    for folder, dirs, files in os.walk(root):
        for name in dirs:
            code = _set_label(adv, k32, os.path.join(folder, name), _LOW_LABEL_DIR)
            if code:
                return code
        for name in files:
            code = _set_label(adv, k32, os.path.join(folder, name), _LOW_LABEL_FILE)
            if code:
                return code
    return 0


def prepare_workspace(path: str, *, force: bool = False) -> None:
    """Make ``path`` writable for a low-integrity child by labelling it low.

    A labelled root is taken to mean the tree was done before; new files
    inherit the label. Pass ``force`` to relabel after files were moved in.

    Changing a label needs full control. Where the folder only grants "modify"
    (the default on a second drive), the current user is granted full control
    on it first. That needs ownership of the folder.

    :raises OSError: the workspace cannot be labelled. Nothing may run in it.
    """
    root = os.path.abspath(path)
    if not force and has_low_label(root):
        return
    k32, adv = _api()
    code = _label_tree(adv, k32, root)
    if code == _ERROR_ACCESS_DENIED and _grant_self_full_control(k32, adv, root):
        code = _label_tree(adv, k32, root)
    if code:
        raise OSError(code, f"cannot label the workspace for contained execution: "
                            f"{ctypes.FormatError(code).strip()}", root)


def private_shell(bash: str, dest_root: str) -> tuple[str, str]:
    """Return ``(bash, bin_dir)`` for a Bash with its own runtime namespace.

    Git Bash keeps shared state in a named kernel object whose name is derived
    from where its runtime DLL is installed. Any normal Git Bash process on the
    machine creates that object at medium integrity, and a low-integrity Bash
    from the same install then dies at start. A copy of the runtime in another
    folder gets its own name, so the copy is what contained commands use.

    The copy is made on first use and again when the installed runtime
    changed. ``bin_dir`` must come first on the command's PATH so the tools
    Bash starts are the copied ones. A Bash that is not Git Bash is returned
    unchanged with an empty ``bin_dir``.

    :raises OSError: the copy could not be made or refreshed.
    """
    here = os.path.dirname(os.path.abspath(bash))
    source = next((folder for folder in (here, os.path.join(here, os.pardir, "usr", "bin"))
                   if os.path.isfile(os.path.join(folder, "msys-2.0.dll"))), None)
    if source is None:
        return bash, ""
    source = os.path.abspath(source)
    runtime = os.stat(os.path.join(source, "msys-2.0.dll"))
    # The leading number is the layout version of the copy; raise it to force a refresh.
    stamp = f"2|{source}|{runtime.st_size}|{runtime.st_mtime_ns}"
    target = os.path.join(dest_root, "usr", "bin")
    marker = os.path.join(dest_root, "copied-from.txt")
    try:
        with open(marker, encoding="utf-8") as handle:
            current = handle.read() == stamp
    except OSError:
        current = False
    if not current:
        import shutil
        if os.path.exists(marker):
            os.remove(marker)
        shutil.copytree(source, target, dirs_exist_ok=True)
        os.makedirs(os.path.join(dest_root, "tmp"), exist_ok=True)
        etc = os.path.join(dest_root, "etc")
        os.makedirs(etc, exist_ok=True)
        source_etc = os.path.join(os.path.dirname(os.path.dirname(source)), "etc")
        for name in ("fstab", "nsswitch.conf"):
            if os.path.isfile(os.path.join(source_etc, name)):
                shutil.copyfile(os.path.join(source_etc, name), os.path.join(etc, name))
        if not os.path.isfile(os.path.join(etc, "fstab")):
            # Without a mount table drives answer only to /cygdrive/c, not to /c.
            with open(os.path.join(etc, "fstab"), "w", encoding="ascii") as handle:
                handle.write("none / cygdrive binary,posix=0,noacl,user 0 0\n")
        # Written last: an interrupted copy has no marker and is redone.
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write(stamp)
    return os.path.join(target, "bash.exe"), target


def launcher_argv(interpreter: str, tmp_dir: str, command: list[str], *, path_first: str = "") -> list[str]:
    """The argv that runs ``command`` inside the boundary."""
    extra = ["--path", path_first] if path_first else []
    # Named explicitly: in a packaged build ``__file__`` ends in ``.pyc``, and the
    # packaged interpreter only maps a ``.py`` path onto its bundled module.
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "containment_win.py")
    # -I keeps the folder of this file, and the environment, out of the launcher's imports.
    return [interpreter, "-I", script, "--tmp", tmp_dir, *extra, "--", *command]


# ── Launcher half ───────────────────────────────────────────────────────────
def _enter_job(k32) -> _HANDLE:
    """Put this process into a new job that dies with its last handle.

    The handle is never closed: it lives exactly as long as this process, and
    the system then terminates every remaining member.
    """
    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise _fail("CreateJobObjectW")
    limits = _ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not k32.SetInformationJobObject(job, _JOB_EXTENDED_LIMIT_INFORMATION, byref(limits), sizeof(limits)):
        raise _fail("SetInformationJobObject")
    if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
        raise _fail("AssignProcessToJobObject")
    return job


def _lower_integrity(k32, adv) -> None:
    """Drop this process's token to low integrity. It cannot be raised again."""
    token = _HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), _TOKEN_QUERY | _TOKEN_ADJUST_DEFAULT, byref(token)):
        raise _fail("OpenProcessToken")
    try:
        sid = _VP()
        if not adv.ConvertStringSidToSidW(_LOW_SID, byref(sid)):
            raise _fail("ConvertStringSidToSidW")
        try:
            label = _SidAndAttributes(sid, _SE_GROUP_INTEGRITY)
            if not adv.SetTokenInformation(token, _TOKEN_INTEGRITY_LEVEL, byref(label),
                                           sizeof(label) + adv.GetLengthSid(sid)):
                raise _fail("SetTokenInformation")
        finally:
            k32.LocalFree(sid)
    finally:
        k32.CloseHandle(token)


def main(argv: list[str]) -> int:
    path_first = ""
    if len(argv) >= 6 and argv[2] == "--path":
        path_first, argv = argv[3], argv[:2] + argv[4:]
    if len(argv) < 4 or argv[0] != "--tmp" or argv[2] != "--":
        print("launcher: usage: --tmp <dir> [--path <dir>] -- <command...>; command not executed",
              file=sys.stderr)
        return EXIT_NO_BOUNDARY
    tmp_dir, command = argv[1], argv[3:]
    if path_first:
        os.environ["PATH"] = path_first + os.pathsep + os.environ.get("PATH", "")
    try:
        # Made before the drop, so it inherits the workspace's low label.
        os.makedirs(tmp_dir, exist_ok=True)
        k32, adv = _api()
        job = _enter_job(k32)  # noqa: F841 - held open until this process exits
        _lower_integrity(k32, adv)
    except OSError as error:
        print(f"launcher: boundary not established ({error}); command not executed", file=sys.stderr)
        return EXIT_NO_BOUNDARY
    # The user's own temp and cache folders are not writable from low integrity.
    os.environ.update({
        "TEMP": tmp_dir, "TMP": tmp_dir,
        "PIP_CACHE_DIR": os.path.join(tmp_dir, "pip-cache"),
        "npm_config_cache": os.path.join(tmp_dir, "npm-cache"),
    })
    try:
        return subprocess.call(command)
    except OSError as error:
        print(f"launcher: cannot start the command ({error})", file=sys.stderr)
        return EXIT_NOT_STARTED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
