"""Real portable mutation/picker paths; Windows receipts on a Linux executor."""
import json
from dataclasses import asdict

import pytest
import pytest_asyncio

from tests.gateway.test_portable_session_contract import (
    CAPS, WINDOWS_CWD, _enroll, _runner, _windows_receipt,
)


@pytest_asyncio.fixture
async def portable(tmp_path, monkeypatch, request):
    from gateway import run
    from gateway.session_authority import initialize_session_authority
    from gateway.session_contract import Principal, SessionRef
    from hermes_state_runtime import begin_runtime_epoch
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setattr(run, '_load_gateway_config', lambda *a: {'platform_toolsets': {'cli': []}})
    workspace = tmp_path / 'work'
    workspace.mkdir()
    _enroll(tmp_path, workspace)
    runner = _runner(tmp_path)
    saved = _windows_receipt(runner._session_db, begin_runtime_epoch(
        runner._session_db, instance_id='windows'), workspace=workspace,
        config={'compression': {'in_place': getattr(request, 'param', True)}})
    runner._resolve_session_agent_runtime = lambda **kw: ('fixture', {})
    authority = await initialize_session_authority(runner, profile_id=str(tmp_path), instance_id='linux')
    actor = Principal('uid:1000', str(tmp_path), CAPS, 'socket')
    ref = SessionRef(str(tmp_path), saved['session_id'])
    try:
        await authority.attach(actor, ref)
        yield authority, actor, ref, saved, workspace
    finally:
        runner.session_store.close_all_db_handles()


async def mutate(portable, operation, payload):
    from gateway.session_mutations import mutate_session
    authority, actor, ref, *_ = portable
    row = authority.db.get_session(ref.session_id)
    return await mutate_session(authority, actor, ref, {
        'session_id': ref.session_id, 'request_id': 'linux-' + operation, 'operation': operation,
        'expected_revision': row['runtime_revision'], 'expected_generation': row['runtime_generation'],
        'payload': payload})


@pytest.mark.asyncio
async def test_portable_model_mutation_keeps_durable_paths(portable, monkeypatch):
    from hermes_cli import model_switch
    from hermes_state_local import local_receipt
    monkeypatch.setattr(model_switch, 'switch_model', lambda **kw: model_switch.ModelSwitchResult(
        success=True, new_model='changed', target_provider='custom', base_url='http://127.0.0.1:9/v1'))
    monkeypatch.setattr('hermes_cli.model_selection_guards.selection_warnings', lambda *a, **kw: [])
    await mutate(portable, 'model', {'model': 'changed'})
    authority, _, ref, saved, workspace = portable
    policy = local_receipt(authority.db, ref.session_id)['policy']
    assert policy['model'] == 'changed'
    assert policy['cwd'] == WINDOWS_CWD
    assert policy['request_json'] == saved['policy']['request_json']
    from gateway.config import Platform
    assert authority.runner.adapters[Platform.LOCAL].policies[ref.session_id].cwd == str(workspace)


@pytest.mark.asyncio
async def test_portable_branch_copies_history_and_keeps_identity(portable):
    from gateway.session_contract import SessionRef
    from hermes_state_local import local_receipt
    authority, actor, _ref, saved, _ = portable
    result = await mutate(portable, 'branch', {})
    child = result['branched_session_id']
    snapshot = await authority.attach(actor, SessionRef(authority.profile_id, child))
    assert snapshot.history[0]['content'] == 'Windows history'
    receipt = local_receipt(authority.db, child)
    assert receipt['profile_id'] == saved['profile_id']
    assert receipt['principal_id'] == saved['principal_id']
    assert receipt['policy']['cwd'] == WINDOWS_CWD


@pytest.mark.asyncio
async def test_portable_closed_picker_does_not_restore(portable):
    from gateway.session_listing import stored_picker_sessions
    authority, actor, ref, saved, _ = portable
    authority._native_legacy_transports = {actor.transport_id: actor}
    authority.db.end_session(ref.session_id, 'user')
    authority.sessions.pop(ref.session_id, None)
    result = stored_picker_sessions(authority, actor, limit=20)
    assert ref.session_id in [row['id'] for row in result['sessions']]
    assert ref.session_id not in authority.sessions
    from hermes_state_local import local_receipt
    assert local_receipt(authority.db, ref.session_id) == saved


@pytest.mark.asyncio
async def test_portable_ancillary_servers_reads_policy(portable):
    from gateway.session_ancillary import _session_servers
    authority, _, ref, *_ = portable
    assert _session_servers(authority, ref.session_id, []) == []


@pytest.mark.asyncio
async def test_runtime_replace_preserves_original_policy_identity(portable):
    from dataclasses import replace
    from gateway.session_policy import restore_policy
    from gateway.session_policy_credentials import policy_identity
    from gateway.session_portability import durable_policy
    authority, _, _, saved, _ = portable
    original = restore_policy(saved['policy'], authority=authority)
    runtime = restore_policy(saved['policy'], authority=authority, runtime=True)
    copied = replace(runtime, toolsets=('web',))
    assert policy_identity(copied) == policy_identity(original)
    assert durable_policy(copied) == durable_policy(original)
    changed = replace(original, model='new-durable-model')
    assert durable_policy(changed)['model'] == 'new-durable-model'
    assert policy_identity(changed) != policy_identity(original)
    # Actual follows-profile scope makes a runtime dataclasses.replace every turn.
    from gateway.session_policy import active_policy, policy_scope
    followed = replace(original, request_json=json.dumps({**json.loads(original.request_json),
                                                        'follow_profile_config': True}))
    runtime = restore_policy(asdict(followed), authority=authority, runtime=True)
    with policy_scope(runtime, authority=authority):
        assert active_policy().cwd == runtime.cwd
        assert policy_identity(active_policy()) == policy_identity(followed)


@pytest.mark.asyncio
@pytest.mark.parametrize('section', [
    {'mcp_servers': {'win': {'command': 'C:\\tools\\server.exe', 'args': ['--serve'], 'env': {'X': 'Y'}}}},
    {'hooks': {'on_start': 'C:\\tools\\hook.exe'}},
])
async def test_portable_refuses_host_bound_config(portable, section):
    from gateway.session_policy import restore_policy
    from hermes_state_runtime import RuntimeStoreError
    authority, _, _, saved, _ = portable
    data = dict(saved['policy'])
    data['config_json'] = json.dumps({**json.loads(data['config_json']), **section})
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        restore_policy(data, authority=authority, runtime=True)


@pytest.mark.asyncio
async def test_workspace_mutation_maps_destination_to_original_host(portable):
    from gateway.session_policy import restore_policy
    from hermes_state_local import local_receipt
    authority, _, ref, saved, workspace = portable
    target = workspace / 'project'
    target.mkdir()
    await mutate(portable, 'workspace', {'cwd': str(target)})
    policy = local_receipt(authority.db, ref.session_id)['policy']
    assert policy['cwd'] == WINDOWS_CWD + '\\project'
    assert json.loads(policy['terminal_json'])['TERMINAL_CWD'] == policy['cwd']
    # Creation request stays immutable in its original host namespace.
    assert policy['request_json'] == saved['policy']['request_json']
    assert restore_policy(policy, authority=authority, runtime=True).cwd == str(target)


@pytest.mark.asyncio
async def test_workspace_unmapped_destination_refuses_without_mutation(portable, tmp_path):
    from hermes_state_local import local_receipt
    from hermes_state_runtime import RuntimeStoreError
    authority, _, ref, saved, _ = portable
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        await mutate(portable, 'workspace', {'cwd': str(tmp_path)})
    assert local_receipt(authority.db, ref.session_id) == saved


@pytest.mark.asyncio
async def test_unsupported_profile_refresh_does_not_commit(portable, monkeypatch):
    from gateway.session_policy_refresh import commit_refresh
    from hermes_state_local import local_receipt
    from hermes_state_runtime import RuntimeStoreError
    authority, _, ref, saved, _ = portable
    monkeypatch.setattr('gateway.run._load_gateway_config', lambda *a: {
        'mcp_servers': {'win': {'command': 'C:\\tools\\mcp.exe'}}})
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        await commit_refresh(authority, ref, mcp_only=True)
    assert local_receipt(authority.db, ref.session_id) == saved


@pytest.mark.asyncio
async def test_worker_wire_keeps_runtime_paths_not_provenance(portable):
    from dataclasses import replace
    from gateway.session_policy import restore_policy
    from gateway.session_portability import execution_policy
    authority, _, _, saved, workspace = portable
    runtime = restore_policy(saved['policy'], authority=authority, runtime=True)
    wire = execution_policy(replace(runtime, credential_ref=None, config_secret_ref=None))
    assert '_durable_policy' not in wire
    assert restore_policy(wire).cwd == str(workspace)


@pytest.mark.asyncio
async def test_portable_editor_discovery_refuses_before_launch(portable, monkeypatch):
    from gateway.session_local_mcp import rebind_editor_mcp
    from gateway.session_policy import restore_policy
    from hermes_state_runtime import RuntimeStoreError
    authority, _, ref, saved, _ = portable
    original = restore_policy(saved['policy'], authority=authority)
    def unexpected(*a, **kw):
        pytest.fail('foreign executable discovery must not launch')
    monkeypatch.setattr('gateway.session_local_mcp._borrowed', unexpected)
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        rebind_editor_mcp(authority, ref.session_id, original, [{'name': 'win', 'command': 'cmd.exe', 'args': []}])


@pytest.mark.asyncio
async def test_portable_refuses_opaque_terminal_environment(portable):
    from gateway.session_policy import restore_policy
    from hermes_state_runtime import RuntimeStoreError
    authority, _, _, saved, _ = portable
    data = dict(saved['policy'])
    terminal = json.loads(data['terminal_json'])
    terminal['TERMINAL_ENV_VARS'] = '{"PATH":"C:\\\\tools"}'
    data['terminal_json'] = json.dumps(terminal)
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        restore_policy(data, authority=authority, runtime=True)


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_only', [True, False])
async def test_portable_profile_refresh_preserves_durable_workspace(portable, monkeypatch, mcp_only):
    from gateway.session_policy_refresh import commit_refresh
    from hermes_state_local import local_receipt
    authority, _, ref, *_ = portable
    monkeypatch.setattr('gateway.run._load_gateway_config', lambda *a: {
        'agent': {'max_turns': 11}, 'mcp_servers': {'disabled': {'enabled': False}}})
    assert await commit_refresh(authority, ref, mcp_only=mcp_only)
    policy = local_receipt(authority.db, ref.session_id)['policy']
    assert policy['cwd'] == WINDOWS_CWD
    assert json.loads(policy['terminal_json'])['TERMINAL_CWD'] == WINDOWS_CWD
    assert json.loads(policy['config_json'])['mcp_servers'] == {'disabled': {'enabled': False}}
    if not mcp_only:
        assert json.loads(policy['config_json'])['agent']['max_turns'] == 11


@pytest.mark.asyncio
@pytest.mark.parametrize('portable', [True, False], indirect=True)
async def test_portable_compression_publishes_real_summary(portable, monkeypatch):
    from agent.context_compressor import ContextCompressor
    from gateway.session_policy import LocalSessionPolicy
    from hermes_state_local import local_receipt
    authority, actor, ref, saved, _ = portable
    # Exercise the real prepare/commit/publication, replacing inference only.
    monkeypatch.setattr(ContextCompressor, 'compress', lambda self, messages, **kw: [
        {'role': 'user', 'content': 'summary', '_compressed_summary': True}])
    in_place = json.loads(saved['policy']['config_json'])['compression']['in_place']
    result = await mutate(portable, 'compress', {})
    assert result['target_session_id'] == ref.session_id if in_place else result['target_session_id'] != ref.session_id
    assert authority.db.get_messages_as_conversation(result['target_session_id'])[0]['content'] == 'summary'
    assert local_receipt(authority.db, ref.session_id)['policy']['cwd'] == WINDOWS_CWD
    await authority.attach(actor, ref)
