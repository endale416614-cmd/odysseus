"""Code execution asks for approval from the first call on hosts that cannot confine reads."""

import sys

import pytest

from src import containment
from src import tool_capabilities
from src.tool_capabilities import (
    UNCONFINED_READS_REASON,
    ToolRunSecurityContext,
    host_reads_unconfined,
)


@pytest.fixture
def gate_on(monkeypatch):
    monkeypatch.setattr(tool_capabilities, "TOOL_APPROVAL_GATE_ENABLED", True)


def test_default_context_allows_shell_command_before_untrusted_content(gate_on):
    assert ToolRunSecurityContext().decision_for("bash", "echo hi").allowed is True


def test_unconfined_reads_block_code_execution_from_first_call(gate_on):
    context = ToolRunSecurityContext(reads_unconfined=True)

    shell = context.decision_for("bash", "echo hi")
    assert shell.allowed is False
    assert shell.reason == UNCONFINED_READS_REASON

    assert context.decision_for("python", "print(1)").allowed is False


def test_unconfined_reads_leave_non_executing_tools_allowed(gate_on):
    context = ToolRunSecurityContext(reads_unconfined=True)

    assert context.decision_for("read_file", "notes.txt").allowed is True
    assert context.decision_for("web_search", "weather").allowed is True


def test_approval_bypass_lifts_unconfined_reads_block(gate_on):
    context = ToolRunSecurityContext(reads_unconfined=True, approval_gate_bypassed=True)

    assert context.decision_for("bash", "echo hi").allowed is True


def test_unattended_tool_lifts_unconfined_reads_block(gate_on):
    context = ToolRunSecurityContext(
        reads_unconfined=True, unattended_tools=frozenset({"bash"}),
    )

    assert context.decision_for("bash", "echo hi").allowed is True


def test_gate_off_lifts_unconfined_reads_block(monkeypatch):
    monkeypatch.setattr(tool_capabilities, "TOOL_APPROVAL_GATE_ENABLED", False)
    context = ToolRunSecurityContext(reads_unconfined=True)

    assert context.decision_for("bash", "echo hi").allowed is True


def test_host_reads_unconfined_matches_containment_policy():
    expected = containment.FILESYSTEM not in containment.DEFAULT_REQUIRED

    assert host_reads_unconfined() is expected
    if sys.platform == "win32":
        assert host_reads_unconfined() is True
