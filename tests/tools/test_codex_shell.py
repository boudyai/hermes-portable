from pathlib import Path

import pytest

from tools.codex_shell import is_ops_guarded_codex_command
from tools.readonly_shell import is_readonly_shell_command


@pytest.fixture()
def boundaries(tmp_path):
    hermes_home = tmp_path / "hermes-private"
    workdir = tmp_path / "project"
    hermes_home.mkdir()
    workdir.mkdir()
    return hermes_home, workdir


def _args(command: str, workdir: Path | None = None, **extra):
    result = {"command": command, **extra}
    if workdir is not None:
        result["workdir"] = str(workdir)
    return result


def test_safe_codex_exec_requires_workspace_sandbox(boundaries):
    hermes_home, workdir = boundaries
    command = (
        "codex exec --sandbox workspace-write --ephemeral "
        "--ignore-user-config --ignore-rules -m gpt-5.6-sol "
        "-c model_reasoning_effort=medium 'review this code; do not edit'"
    )

    assert is_ops_guarded_codex_command(_args(command, workdir, pty=True), hermes_home)
    assert is_ops_guarded_codex_command(
        _args(
            "codex exec --sandbox workspace-write -m gpt-5.6-sol "
            "-c model_reasoning_effort=high 'review this code'",
            workdir,
        ),
        hermes_home,
    )
    assert is_ops_guarded_codex_command(
        _args(
            "codex --sandbox workspace-write -m gpt-5.6-sol "
            "-c model_reasoning_effort=medium exec 'review this code'",
            workdir,
        ),
        hermes_home,
    )


@pytest.mark.parametrize(
    "command",
    [
        "codex exec --sandbox danger-full-access 'review this code'",
        "codex exec 'review'",
        "codex exec --sandbox workspace-write -m gpt-5.6-sol 'review'",
        "codex exec --sandbox workspace-write -m gpt-5.6-terra "
        "-c model_reasoning_effort=medium 'review'",
        "codex exec --sandbox workspace-write -m gpt-5.6-sol "
        "-c sandbox_permissions='[\"disk-full-read-access\"]' 'review'",
        "codex exec --sandbox workspace-write --ephemeral --ignore-user-config "
        "--ignore-rules --add-dir ~/.hermes 'review'",
        "codex exec --sandbox workspace-write --ephemeral --ignore-user-config "
        "--ignore-rules 'review' && cat ~/.hermes/wiki/private.md",
        "codex exec --dangerously-bypass-approvals-and-sandbox 'review'",
    ],
)
def test_unsafe_codex_exec_shapes_are_not_auto_approved(boundaries, command):
    hermes_home, workdir = boundaries
    assert not is_ops_guarded_codex_command(_args(command, workdir), hermes_home)


def test_codex_exec_rejects_workdir_that_contains_hermes_home(boundaries):
    hermes_home, _workdir = boundaries
    command = (
        "codex exec --sandbox workspace-write --ephemeral "
        "--ignore-user-config --ignore-rules -m gpt-5.6-sol "
        "-c model_reasoning_effort=medium 'review'"
    )
    assert not is_ops_guarded_codex_command(
        _args(command, hermes_home.parent), hermes_home
    )


def test_exact_server_scratch_shape_is_auto_approved(boundaries):
    hermes_home, _workdir = boundaries
    assert is_ops_guarded_codex_command(
        _args(
            "cd $(mktemp -d) && git init && "
            "codex exec --sandbox workspace-write -m gpt-5.6-sol "
            "-c model_reasoning_effort=high 'consult about this algorithm'"
        ),
        hermes_home,
    )
    assert not is_ops_guarded_codex_command(
        _args(
            "cd $(mktemp -d) && git init && "
            "codex exec --sandbox danger-full-access 'read the wiki'"
        ),
        hermes_home,
    )


@pytest.mark.parametrize(
    "command",
    [
        "codex --version",
        "codex login --device-auth",
        "codex login status",
        "mktemp -d",
        "ln -sf ~/.codex/auth.account1.json ~/.codex/auth.json",
        "ln -sf ~/.codex/auth.account-team.json ~/.codex/auth.json",
    ],
)
def test_exact_codex_control_commands_are_allowed(boundaries, command):
    hermes_home, _workdir = boundaries
    assert is_ops_guarded_codex_command(_args(command), hermes_home)


@pytest.mark.parametrize(
    "command",
    [
        "ln -sf ~/.codex/auth.account*.json ~/.codex/auth.json",
        "ln -sf /tmp/attacker.json ~/.codex/auth.json",
        "ln -sf ~/.codex/auth.account1.json ~/.codex/auth.json; id",
        "cat ~/.codex/auth.json",
    ],
)
def test_broad_or_secret_account_commands_are_not_codex_allowlisted(boundaries, command):
    hermes_home, _workdir = boundaries
    assert not is_ops_guarded_codex_command(_args(command), hermes_home)


def test_auth_contents_are_not_generic_readonly_but_metadata_is():
    assert not is_readonly_shell_command("cat ~/.codex/auth.json")
    assert not is_readonly_shell_command("cat ~/.codex/auth.account1.json")
    assert not is_readonly_shell_command("cat ~/.codex/*")
    assert not is_readonly_shell_command("grep token ~/.codex/auth.json")
    assert is_readonly_shell_command("ls -la ~/.codex/auth*")
    assert is_readonly_shell_command("readlink ~/.codex/auth.json")
    assert is_readonly_shell_command("pgrep -a codex")


def test_git_init_only_allowed_in_explicit_tmp_workdir(boundaries, tmp_path):
    hermes_home, workdir = boundaries
    assert is_ops_guarded_codex_command(_args("git init", Path("/tmp")), hermes_home)
    assert not is_ops_guarded_codex_command(_args("git init", workdir), hermes_home)
    assert not is_ops_guarded_codex_command(_args("git init"), hermes_home)
