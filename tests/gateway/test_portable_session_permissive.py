"""Opt-in OS switch: keep launch state opaque, adapt only execution cwd."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.gateway.test_portable_session_paths import portable
from tests.gateway.test_portable_session_contract import WINDOWS_CWD


def enable(authority):
    path = Path(authority.db.db_path).parent / 'portable-sessions.json'
    data = json.loads(path.read_text())
    data['os_switch'] = 'permissive'
    path.write_text(json.dumps(data))


@pytest.mark.asyncio
async def test_permissive_opaque_windows_policy_resumes_unchanged(portable):
    from gateway.session_policy import restore_policy
    from gateway.session_portability import durable_policy
    from gateway.session_policy_credentials import policy_identity
    authority, _, _, saved, workspace = portable
    enable(authority)
    data = dict(saved['policy'])
    data['config_json'] = json.dumps({'mcp_servers': {'win': {'command': r'C:\tools\server.exe'}},
                                    'hooks': {'on_start': r'C:\tools\hook.exe'}})
    data['client_env_json'] = json.dumps({'EDITOR': r'C:\tools\editor.exe'})
    runtime = restore_policy(data, authority=authority, runtime=True)
    assert runtime.cwd == str(workspace)
    assert runtime.config_json == data['config_json']
    assert runtime.client_env_json == data['client_env_json']
    assert json.loads(json.dumps(durable_policy(runtime))) == data
    assert policy_identity(runtime) == policy_identity(restore_policy(data, authority=authority))


@pytest.mark.asyncio
@pytest.mark.parametrize('foreign_cwd', [r'D:\missing\project', WINDOWS_CWD + r'\missing'])
async def test_permissive_unavailable_cwd_uses_actual_local_home(portable, foreign_cwd):
    from gateway.session_policy import restore_policy, policy_scope
    from agent.runtime_cwd import resolve_agent_cwd
    from gateway.session_portability import durable_policy
    authority, _, _, saved, _ = portable
    enable(authority)
    data = dict(saved['policy'], cwd=foreign_cwd)
    terminal = json.loads(data['terminal_json'])
    terminal['TERMINAL_CWD'] = foreign_cwd
    data['terminal_json'] = json.dumps(terminal)
    runtime = restore_policy(data, authority=authority, runtime=True)
    assert runtime.cwd == str(Path.home())
    assert Path(runtime.cwd).is_dir()
    with policy_scope(runtime, authority=authority):
        assert resolve_agent_cwd() == Path.home()
    assert json.loads(json.dumps(durable_policy(runtime))) == data


@pytest.mark.asyncio
async def test_os_switch_notice_rides_new_turn_not_stored_prompt(portable):
    import platform
    from gateway.session_policy import restore_policy, policy_scope
    from gateway.session_surface import arm_surface_turn
    from gateway.session_portability import execution_policy
    from agent.turn_context import consume_gateway_turn_context_notes
    authority, _, _, saved, _ = portable
    enable(authority)
    runtime = restore_policy(saved['policy'], authority=authority, runtime=True)
    for policy in (runtime, restore_policy(execution_policy(runtime))):
        agent = SimpleNamespace(_cached_system_prompt='Frozen Windows system prompt')
        with policy_scope(policy, authority=authority):
            arm_surface_turn(agent, ['existing note'])
        note = consume_gateway_turn_context_notes(agent)
        assert 'OS changed' in note
        assert platform.system() in note
        assert str(Path.home()) in note
        assert WINDOWS_CWD in note
        assert 'existing note' in note
        assert agent._cached_system_prompt == 'Frozen Windows system prompt'
        assert consume_gateway_turn_context_notes(agent) == ''


@pytest.mark.asyncio
async def test_permissive_preserves_explicit_ssh_backend(portable):
    from gateway.session_policy import restore_policy
    authority, _, _, saved, _ = portable
    enable(authority)
    data = dict(saved['policy'])
    terminal = json.loads(data['terminal_json'])
    terminal.update(TERMINAL_ENV='ssh', TERMINAL_CWD='/srv/remote-project',
                    TERMINAL_SSH_HOST='fixture.invalid')
    data['terminal_json'] = json.dumps(terminal)
    runtime = restore_policy(data, authority=authority, runtime=True)
    assert json.loads(runtime.terminal_json) == terminal


@pytest.mark.asyncio
async def test_permissive_cold_attach_unmapped_windows_receipt(tmp_path, monkeypatch):
    from gateway import run
    from gateway.session_authority import initialize_session_authority
    from gateway.session_contract import Principal, SessionRef
    from hermes_state_runtime import begin_runtime_epoch
    from hermes_state_local import local_receipt
    from tests.gateway.test_portable_session_contract import _enroll, _runner, _windows_receipt, CAPS
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setattr(run, '_load_gateway_config', lambda *a: {})
    # Enrollment intentionally has no mapping for the receipt workspace.
    _enroll(tmp_path, tmp_path / 'mapped')
    path = tmp_path / 'portable-sessions.json'
    data = json.loads(path.read_text())
    data.update(os_switch='permissive', roots=[{'windows': r'Z:\other', 'posix': str(tmp_path / 'mapped')}])
    path.write_text(json.dumps(data))
    runner = _runner(tmp_path)
    try:
        saved = _windows_receipt(runner._session_db, begin_runtime_epoch(runner._session_db,
            instance_id='windows'), workspace=tmp_path, config={
                'terminal': {'backend': 'local', 'cwd': WINDOWS_CWD},
                'mcp_servers': {'win': {'command': r'C:\tools\mcp.exe'}},
                'browser': {'browserbase': False}})
        authority = await initialize_session_authority(runner, profile_id=str(tmp_path), instance_id='linux')
        actor = Principal('uid:1000', str(tmp_path), CAPS, 'socket')
        snapshot = await authority.attach(actor, SessionRef(str(tmp_path), saved['session_id']))
        assert snapshot.history[0]['content'] == 'Windows history'
        from gateway.config import Platform
        runtime = runner.adapters[Platform.LOCAL].policies[saved['session_id']]
        assert runtime.cwd == str(Path.home())
        assert runtime.config_json == saved['policy']['config_json']
        assert local_receipt(runner._session_db, saved['session_id']) == saved
    finally:
        runner.session_store.close_all_db_handles()


@pytest.mark.asyncio
async def test_old_windows_command_fails_naturally_after_resume(portable):
    from gateway.session_policy import restore_policy, policy_scope
    from tools.terminal_tool import terminal_tool, cleanup_all_environments
    authority, _, _, saved, _ = portable
    enable(authority)
    runtime = restore_policy(saved['policy'], authority=authority, runtime=True)
    command = r'"C:\hermes-portability-missing\program.exe" --version'
    try:
        with policy_scope(runtime, authority=authority):
            result = json.loads(terminal_tool(command, task_id='portable-natural-failure', timeout=5))
        assert result['exit_code'] != 0
        assert 'C:' in result['output']
    finally:
        cleanup_all_environments()
