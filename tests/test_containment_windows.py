"""The Windows execution boundary: Job Object plus low integrity, end to end.

These run real processes, so the Windows cases are skipped elsewhere. The one
case that runs everywhere checks the platform split in the requirement set.
"""
import os
import sys
import time

import pytest

from core.platform_compat import IS_WINDOWS, find_bash, pid_alive
from src import containment

WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="Windows job boundary")

# Only these variables are passed to contained commands. Python needs the
# system roots to start, and Git Bash needs the profile and PATH.
_ENV_KEYS = ("SystemRoot", "SystemDrive", "windir", "COMSPEC", "PATHEXT", "PATH", "USERPROFILE")


def _env():
    return {key: os.environ[key] for key in _ENV_KEYS if key in os.environ}


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    """Keep grant records and integrity labels inside the test's own folder."""
    monkeypatch.setattr(containment, "_store_path", lambda: tmp_path / "containment_grants.json")
    data = tmp_path / "data"
    (data / "uploads").mkdir(parents=True)
    monkeypatch.setattr(containment, "_app_data_layout",
                        lambda: (str(data), (str(data / "agent_workspace"), str(data / "uploads"))))
    return data


@pytest.fixture
def workspace(tmp_path):
    path = tmp_path / "ws"
    path.mkdir()
    return str(path)


@pytest.fixture
def outside(tmp_path):
    path = tmp_path / "outside"
    path.mkdir()
    return str(path)


@WINDOWS_ONLY
def test_a_probe_reports_job_mechanism_and_write_confinement(workspace):
    result = containment.probe(containment.agent_spec(workspace, _env(), 60))
    assert result.mechanism == "windows_job"
    assert result.enforced == frozenset({"filesystem_write", "process_tree", "wall_clock"})
    assert result.unenforced_required == ()
    assert "filesystem" in result.degraded


@WINDOWS_ONLY
async def test_b_argv_command_writes_inside_the_workspace(workspace):
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    command = [sys.executable, "-I", "-c", "open('made.txt', 'w').write('x')"]
    result = await containment.run(grant, command, argv=True)
    assert result.exit_code == 0, result.stderr
    assert os.path.exists(os.path.join(workspace, "made.txt"))


@WINDOWS_ONLY
async def test_c_argv_command_cannot_write_outside_the_workspace(workspace, outside):
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    target = os.path.join(outside, "escaped.txt")
    command = [sys.executable, "-I", "-c", f"open({target!r}, 'w').write('x')"]
    result = await containment.run(grant, command, argv=True)
    assert not os.path.exists(target)
    assert result.exit_code != 0


@WINDOWS_ONLY
async def test_d_existing_workspace_file_can_be_appended_to(workspace):
    log = os.path.join(workspace, "log.txt")
    with open(log, "w") as handle:
        handle.write("before\n")
    before = os.path.getsize(log)
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    command = [sys.executable, "-I", "-c", f"open({log!r}, 'a').write('after\\n')"]
    result = await containment.run(grant, command, argv=True)
    assert result.exit_code == 0, result.stderr
    assert os.path.getsize(log) > before


@WINDOWS_ONLY
@pytest.mark.skipif(find_bash() is None, reason="Git Bash not installed")
async def test_e_shell_command_returns_output_and_exit_code(workspace):
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    result = await containment.run(grant, "echo hi; exit 3")
    assert "hi" in result.stdout
    assert result.exit_code == 3


@WINDOWS_ONLY
@pytest.mark.skipif(find_bash() is None, reason="Git Bash not installed")
async def test_n_drive_paths_resolve_in_the_private_shell(workspace):
    """The shell copy keeps Git Bash's mount table, so ``/c/...`` still means ``C:\\...``."""
    drive = os.environ["SystemDrive"][0].lower()
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    result = await containment.run(grant, f"test -d /{drive}/Windows && echo drive-ok")
    assert "drive-ok" in result.stdout, result.stderr


@WINDOWS_ONLY
async def test_f_wall_clock_kills_a_grandchild(workspace):
    pid_file = os.path.join(workspace, "pid.txt")
    child_code = "import time; time.sleep(60)"
    parent_code = (
        "import subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-I', '-c', {child_code!r}])\n"
        f"open({pid_file!r}, 'w').write(str(child.pid))\n"
        "time.sleep(60)\n"
    )
    spec = containment.agent_spec(workspace, _env(), 3)
    grant = containment.acquire(spec, owner="windows-test")
    result = await containment.run(grant, [sys.executable, "-I", "-c", parent_code], argv=True)
    assert result.timed_out is True
    with open(pid_file) as handle:
        grandchild = int(handle.read().strip())
    deadline = time.monotonic() + 5
    while pid_alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not pid_alive(grandchild)


def test_g_required_is_a_subset_of_requested(tmp_path):
    spec = containment.agent_spec(str(tmp_path), {}, 60)
    assert spec.required <= spec.requested
    if not IS_WINDOWS:
        assert containment.DEFAULT_REQUIRED == {"filesystem", "process_tree", "wall_clock"}


@WINDOWS_ONLY
async def test_h_grant_record_reports_write_confinement_and_degraded_reads(workspace):
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    result = await containment.run(
        grant, [sys.executable, "-I", "-c", "open('h.txt', 'w').write('x')"], argv=True,
    )
    assert result.exit_code == 0, result.stderr
    data = result.grant.to_dict()
    assert "filesystem_write" in data["enforced"]
    assert data["contained"] is True
    assert "filesystem" in data["degraded"]


@WINDOWS_ONLY
async def test_i_a_process_left_behind_dies_when_the_command_ends(workspace):
    """Nothing outlives the launcher: its Job Object closes when it exits."""
    pid_file = os.path.join(workspace, "left.txt")
    code = (
        "import subprocess, sys\n"
        "quiet = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'], **quiet)\n"
        f"open({pid_file!r}, 'w').write(str(child.pid))\n"
    )
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    result = await containment.run(grant, [sys.executable, "-I", "-c", code], argv=True)
    assert result.exit_code == 0, result.stderr
    with open(pid_file) as handle:
        left_behind = int(handle.read().strip())
    deadline = time.monotonic() + 5
    while pid_alive(left_behind) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not pid_alive(left_behind)


@WINDOWS_ONLY
async def test_l_app_data_is_hidden_but_readable_parts_stay_readable(workspace, _isolated_store):
    data = _isolated_store
    (data / "app.db").write_text("secret")
    (data / "uploads" / "doc.txt").write_text("shared")
    code = (
        "import sys\n"
        "print(open(sys.argv[2]).read())\n"
        "try:\n"
        "    open(sys.argv[1]).read()\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('hidden')\n"
    )
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    result = await containment.run(
        grant, [sys.executable, "-I", "-c", code, str(data / "app.db"), str(data / "uploads" / "doc.txt")],
        argv=True,
    )
    assert result.exit_code == 0, result.stderr
    assert "shared" in result.stdout
    assert "hidden" in result.stdout
    assert "LEAK" not in result.stdout
    # The application itself is not affected.
    assert (data / "app.db").read_text() == "secret"


@WINDOWS_ONLY
async def test_m_a_workspace_inside_the_data_folder_stays_usable(_isolated_store):
    data = _isolated_store
    inner = data / "agent_workspace"
    inner.mkdir()
    (data / "settings.json").write_text("secret")
    code = (
        "import sys\n"
        "open('made.txt', 'w').write('x')\n"
        "try:\n"
        "    open(sys.argv[1]).read()\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('hidden')\n"
    )
    for _repeat in range(2):  # the second run goes through the already-labelled path
        spec = containment.agent_spec(str(inner), _env(), 60)
        grant = containment.acquire(spec, owner="windows-test")
        result = await containment.run(
            grant, [sys.executable, "-I", "-c", code, str(data / "settings.json")], argv=True,
        )
        assert result.exit_code == 0, result.stderr
        assert "hidden" in result.stdout
        assert "LEAK" not in result.stdout
    assert (inner / "made.txt").exists()


@WINDOWS_ONLY
@pytest.mark.skipif(find_bash() is None, reason="Git Bash not installed")
async def test_o_first_shell_command_runs_with_the_shell_copy_in_the_data_folder(
        workspace, _isolated_store, monkeypatch):
    """The shell copy is made inside the shielded folder on first use and must stay readable."""
    from src import constants
    data = _isolated_store
    shell = data / "agent_shell"
    monkeypatch.setattr(constants, "AGENT_SHELL_DIR", str(shell))
    monkeypatch.setattr(containment, "_app_data_layout",
                        lambda: (str(data), (str(data / "uploads"), str(shell))))
    spec = containment.agent_spec(workspace, _env(), 60)
    grant = containment.acquire(spec, owner="windows-test")
    result = await containment.run(grant, "echo first-run-ok")
    assert result.exit_code == 0, result.stderr
    assert "first-run-ok" in result.stdout


@pytest.fixture
def native_tools(tmp_path, monkeypatch):
    """The real Bash and Python tools bound to a workspace, as a chat turn has them."""
    from src import tool_execution
    from src.agent_runtime import process_resources
    from tests.process_resource_helpers import install_native_authority
    path = tmp_path / "tool-ws"
    path.mkdir()
    monkeypatch.setattr(tool_execution, "agent_cwd", lambda: str(path))
    monkeypatch.setattr(process_resources, "_LAUNCH_DIR", tmp_path / "private" / "launches")
    install_native_authority(monkeypatch, path)
    return path


@WINDOWS_ONLY
@pytest.mark.skipif(find_bash() is None, reason="Git Bash not installed")
async def test_j_the_bash_tool_runs_a_command(native_tools):
    from src.agent_tools import subprocess_tools
    result = await subprocess_tools.BashTool().execute("echo tool-ok > made.txt; cat made.txt", {})
    assert result.get("exit_code") == 0, result
    assert "tool-ok" in result["output"]
    assert (native_tools / "made.txt").exists()
    assert result["containment"]["mechanism"] == "windows_job"
    assert result["containment"]["executed"] is True
    assert "filesystem_write" in result["containment"]["enforced"]
    assert "filesystem" in result["containment"]["degraded"]
    assert result["teardown"]["dead"] is True


@WINDOWS_ONLY
async def test_k_the_python_tool_runs_code(native_tools):
    from src.agent_tools import subprocess_tools
    result = await subprocess_tools.PythonTool().execute("print(6 * 7)", {})
    assert result.get("exit_code") == 0, result
    assert "42" in result["output"]
    assert result["containment"]["mechanism"] == "windows_job"
    assert result["teardown"]["dead"] is True
