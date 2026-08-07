"""Tests for tools/remote_terminal_tool.py — mocked subprocess, no live SSH."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tools import remote_terminal_tool as rt


def _completed(stdout="ok\n", stderr="", returncode=0):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


@pytest.fixture
def mock_run():
    with patch.object(rt.subprocess, "run") as m:
        m.return_value = _completed()
        yield m


@pytest.fixture(autouse=True)
def no_guard(monkeypatch):
    """Bypass the legacy guard pipeline; strict approval lives in dispatch."""
    guard = MagicMock(return_value={"approved": True, "message": None})
    monkeypatch.setattr("tools.approval.check_all_command_guards", guard)
    return guard


@pytest.fixture(autouse=True)
def no_strict_gate(monkeypatch):
    """Most unit tests exercise legacy behavior outside strict mode."""
    gate = MagicMock(return_value=False)
    monkeypatch.setattr("tools.strict_approval.ensure_handler_approval", gate)
    return gate


class TestArgvConstruction:
    def test_default_uses_ssh_key_discovery(self, mock_run):
        rt.remote_terminal_tool(command="ls", host="example.com")
        argv = mock_run.call_args.args[0]
        assert argv[0] == "ssh"
        assert "-i" not in argv  # default ssh key discovery, no explicit key
        assert "-p" not in argv  # default port 22 is not passed explicitly
        assert "BatchMode=yes" in argv
        assert "StrictHostKeyChecking=accept-new" in argv
        assert argv[argv.index("--") + 1] == "example.com"
        assert argv[-2:] == ["bash", "-s"]

    def test_explicit_key_and_port(self, mock_run):
        rt.remote_terminal_tool(
            command="ls", host="deploy@example.com", port=2222,
            key_path="/keys/id_ed25519",
        )
        argv = mock_run.call_args.args[0]
        assert argv[argv.index("-i") + 1] == "/keys/id_ed25519"
        assert argv[argv.index("-p") + 1] == "2222"
        assert argv[argv.index("--") + 1] == "deploy@example.com"

    def test_command_piped_via_stdin(self, mock_run):
        rt.remote_terminal_tool(command="echo $HOME && rm -rf /tmp/x", host="h")
        assert mock_run.call_args.kwargs["input"] == "echo $HOME && rm -rf /tmp/x"

    def test_workdir_prepends_quoted_cd(self, mock_run):
        rt.remote_terminal_tool(command="ls", host="h", workdir="/opt/my app")
        assert mock_run.call_args.kwargs["input"] == "cd '/opt/my app'\nls"


class TestValidation:
    def test_empty_command_rejected(self, mock_run):
        out = json.loads(rt.remote_terminal_tool(command="  ", host="h"))
        assert out["success"] is False
        mock_run.assert_not_called()

    def test_empty_host_rejected(self, mock_run):
        out = json.loads(rt.remote_terminal_tool(command="ls", host=""))
        assert out["success"] is False
        mock_run.assert_not_called()

    @pytest.mark.parametrize("host", ["-oProxyCommand=evil", "evil host", "h;rm"])
    def test_malicious_host_rejected(self, mock_run, host):
        out = json.loads(rt.remote_terminal_tool(command="ls", host=host))
        assert out["success"] is False
        mock_run.assert_not_called()

    @pytest.mark.parametrize("host", ["example.com", "u@10.0.0.1", "u@fe80::1", "my-host.internal"])
    def test_valid_hosts_accepted(self, mock_run, host):
        out = json.loads(rt.remote_terminal_tool(command="ls", host=host))
        assert out["success"] is True

    def test_key_path_option_injection_rejected(self, mock_run):
        out = json.loads(rt.remote_terminal_tool(command="ls", host="h", key_path="-oEvil"))
        assert out["success"] is False
        mock_run.assert_not_called()

    @pytest.mark.parametrize("port", [0, 70000, "abc"])
    def test_invalid_port_rejected(self, mock_run, port):
        out = json.loads(rt.remote_terminal_tool(command="ls", host="h", port=port))
        assert out["success"] is False
        mock_run.assert_not_called()

    def test_timeout_capped(self, mock_run):
        rt.remote_terminal_tool(command="ls", host="h", timeout=rt.MAX_TIMEOUT + 500)
        assert mock_run.call_args.kwargs["timeout"] == rt.MAX_TIMEOUT


class TestResults:
    def test_success_result(self, mock_run):
        mock_run.return_value = _completed(stdout="hello\n", returncode=0)
        out = json.loads(rt.remote_terminal_tool(command="echo hello", host="h"))
        assert out["success"] is True
        assert out["stdout"] == "hello\n"
        assert out["exit_code"] == 0
        assert out["host"] == "h"

    def test_nonzero_exit(self, mock_run):
        mock_run.return_value = _completed(stderr="boom\n", returncode=3)
        out = json.loads(rt.remote_terminal_tool(command="false", host="h"))
        assert out["success"] is False
        assert out["exit_code"] == 3
        assert out["stderr"] == "boom\n"

    def test_timeout_returns_error(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ssh", timeout=1)
        out = json.loads(rt.remote_terminal_tool(command="sleep 99", host="h", timeout=1))
        assert out["success"] is False
        assert out["timed_out"] is True

    def test_missing_ssh_binary(self, mock_run):
        mock_run.side_effect = FileNotFoundError("ssh")
        out = json.loads(rt.remote_terminal_tool(command="ls", host="h"))
        assert out["success"] is False
        assert "ssh" in out["error"]

    def test_guard_denial_blocks_execution(self, mock_run, no_guard):
        no_guard.return_value = {"approved": False, "message": "denied"}
        out = json.loads(rt.remote_terminal_tool(command="rm -rf /", host="h"))
        assert out["success"] is False
        assert out["blocked"] is True
        mock_run.assert_not_called()

    def test_strict_scope_skips_second_legacy_prompt(
        self, mock_run, no_guard, no_strict_gate
    ):
        no_strict_gate.return_value = True

        out = json.loads(rt.remote_terminal_tool(command="systemctl status ssh", host="h"))

        assert out["success"] is True
        no_guard.assert_not_called()
        mock_run.assert_called_once()

    def test_direct_call_fails_closed_when_strict_gate_breaks(
        self, mock_run, no_strict_gate
    ):
        no_strict_gate.side_effect = RuntimeError("approval unavailable")

        out = json.loads(rt.remote_terminal_tool(command="id", host="h"))

        assert out["success"] is False
        assert "Global approval blocked" in out["error"]
        mock_run.assert_not_called()


class TestCheckFn:
    def test_requirements_ok_when_ssh_present(self):
        with patch.object(rt.shutil, "which", return_value="/usr/bin/ssh"):
            assert rt._check_requirements() is True

    def test_requirements_fail_without_ssh(self):
        with patch.object(rt.shutil, "which", return_value=None):
            assert rt._check_requirements() is False
