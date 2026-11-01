"""Dual-boot acceptance contract and security characterization.

Windows identity/path data is a fixture, committed through the real receipt
transaction without changing host probes. This is not a Windows execution test.
"""
import json
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

WINDOWS_HOME = r'C:\Users\portable\AppData\Local\hermes'
WINDOWS_USER = 'sid:S-1-5-21-111111111-222222222-333333333-1001'
WINDOWS_CWD = r'C:\Users\portable\work'
CAPS = frozenset({'session:create', 'session:read', 'session:submit', 'session:control'})


def _runner(home):
    from gateway.config import GatewayConfig
    from gateway.session import SessionStore
    store = SessionStore(home / 'sessions', GatewayConfig())
    # Pin the actual fixture database: DEFAULT_DB_PATH can have been imported
    # under the autouse hermes_test home before this test changes HERMES_HOME.
    store._db = store._open_session_db_for_active_scope(db_path=home / 'state.db')
    assert str(store._db.db_path) == str(home / 'state.db')
    runner = SimpleNamespace(session_store=store, _session_db=store._db,
                             adapters={}, _draining=False, _evict_cached_agent=lambda *a: None,
                             _cached_agent_for=lambda *a: None, _set_session_reasoning_override=lambda *a: None)
    runner._adapter_for_source = lambda source: runner.adapters.get(source.platform)
    return runner


def _windows_receipt(db, epoch, *, workspace, windows_policy=True, config=None):
    from gateway.config import Platform
    from gateway.session import SessionEntry, SessionSource
    from gateway.session_lifecycle import _now
    from gateway.session_policy import build_policy
    from hermes_state_keys import local_identity
    from hermes_state_local import commit_local_session
    sid = local_identity(WINDOWS_HOME, WINDOWS_USER, 'windows-created')
    source = SessionSource(platform=Platform.LOCAL, chat_id=sid,
                           user_id=WINDOWS_USER, chat_type='dm')
    route = 'agent:main:local:dm:' + sid
    now = _now()
    entry = SessionEntry(route, sid, now, now, origin=source, platform=Platform.LOCAL)
    policy = build_policy({'source': 'gui', 'cwd': str(workspace),
                           'model': 'fixture', 'toolsets': []}, config or {})
    if windows_policy:
        terminal = json.loads(policy.terminal_json)
        terminal['TERMINAL_CWD'] = WINDOWS_CWD
        request = json.loads(policy.request_json)
        request['cwd'] = WINDOWS_CWD
        policy = replace(policy, cwd=WINDOWS_CWD, terminal_json=json.dumps(terminal),
                         request_json=json.dumps(request))
    receipt = {'profile_id': WINDOWS_HOME, 'principal_id': WINDOWS_USER,
               'request_id': 'windows-created', 'session_id': sid, 'route': route,
               'entry': entry.to_dict(), 'policy': asdict(policy)}
    commit_local_session(db, epoch=epoch, receipt=receipt)
    db.append_message(sid, 'user', 'Windows history')
    # JSON round-trip: the durable policy has lists, not build_policy's tuples.
    from hermes_state_local import local_receipt
    return local_receipt(db, sid)


def _enroll(home, workspace):
    # Proposed contract, not a currently supported setting. No real profile is edited.
    (home / 'portable-sessions.json').write_text(json.dumps({
        'version': 1,
        'hosts': [
            {'profile_id': WINDOWS_HOME, 'principal_id': WINDOWS_USER},
            {'profile_id': str(home), 'principal_id': 'uid:1000'}],
        'roots': [{'windows': WINDOWS_CWD, 'posix': str(workspace)}],
    }))


@pytest.mark.platforms('linux')

@pytest.mark.asyncio
async def test_enrolled_windows_receipt_restores_writes_and_restarts(tmp_path, monkeypatch):
    from gateway import run
    from gateway.session_authority import initialize_session_authority
    from gateway.session_contract import Principal, SessionRef, Submission
    from gateway.session_mutations import mutate_session
    from hermes_state_local import local_receipt
    from hermes_state_runtime import begin_runtime_epoch, list_session_admissions

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setattr(run, '_load_gateway_config', lambda *a: {'platform_toolsets': {'cli': []}})
    workspace = tmp_path / 'work'
    workspace.mkdir()
    _enroll(tmp_path, workspace)
    runner = _runner(tmp_path)
    db = runner._session_db
    saved = _windows_receipt(db, begin_runtime_epoch(db, instance_id='fixture-windows'), workspace=workspace)
    sid = saved['session_id']
    executed = []

    async def execute(authority, ref, row):
        # This replaces inference only; SQLite admission/claim/settlement are real.
        executed.append((row['principal_id'], row['payload']['text']))
        authority.db.append_message(ref.session_id, 'assistant', row['payload']['text'])
        return 'fixture result'

    monkeypatch.setattr('gateway.session_finite.execute_finite_admission', execute)
    try:
        authority = await initialize_session_authority(runner, profile_id=str(tmp_path), instance_id='linux')
        actor = Principal('uid:1000', str(tmp_path), CAPS, 'socket')
        ref = SessionRef(str(tmp_path), sid)
        snapshot = await authority.attach(actor, ref)
        assert snapshot.history[0]['content'] == 'Windows history'
        from gateway.config import Platform
        policy = runner.adapters[Platform.LOCAL].policies[sid]
        assert policy.cwd == str(workspace)
        assert json.loads(policy.terminal_json)['TERMINAL_CWD'] == str(workspace)
        assert local_receipt(db, sid) == saved
        from gateway.session_policy_credentials import policy_identity
        from gateway.session_portability import durable_policy
        from gateway.session_policy import LocalSessionPolicy
        assert json.loads(json.dumps(durable_policy(policy))) == saved['policy']
        assert policy_identity(policy) == policy_identity(LocalSessionPolicy(**saved['policy']))
        from gateway.session_mutation_compress import prepare_compress
        runner._resolve_session_agent_runtime = lambda **kw: ('fixture', {})
        preview = await prepare_compress(authority, authority.sessions[sid], {'preview': True},
                                         {'snapshot': {'receipt': saved, 'target': sid}})
        assert preview['status'] == 'preview'
        await mutate_session(authority, actor, ref, {
            'session_id': sid, 'request_id': 'linux-reasoning', 'operation': 'reasoning',
            'expected_revision': 0, 'expected_generation': 0, 'payload': {'effort': 'high'}})
        assert local_receipt(db, sid)['policy']['cwd'] == WINDOWS_CWD
        await mutate_session(authority, actor, ref, {
            'session_id': sid, 'request_id': 'linux-rename', 'operation': 'rename',
            'expected_revision': 1, 'expected_generation': 1, 'payload': {'title': 'Portable'}})
        await authority.submit(actor, Submission('linux-input', ref, {'text': 'Linux continuation'}, 'queue'))
        await authority.sessions[sid].task
        assert executed == [('uid:1000', 'Linux continuation')]
        rows = list_session_admissions(db, session_id=sid, pending_only=False)
        assert [(r['principal_id'], r['status']) for r in rows] == [('uid:1000', 'terminal')]
        # New handles, same actual database: exercise a cold load, not an in-memory registry.
        runner.session_store.close_all_db_handles()
        cold_runner = _runner(tmp_path)
        cold = await initialize_session_authority(cold_runner, profile_id=str(tmp_path), instance_id='linux-restart')
        try:
            restored = await cold.attach(actor, ref)
            assert [r['content'] for r in restored.history] == ['Windows history', 'Linux continuation']
            durable = local_receipt(cold.db, sid)
            assert {k: durable[k] for k in ('profile_id', 'principal_id', 'request_id', 'session_id')} == {
                k: saved[k] for k in ('profile_id', 'principal_id', 'request_id', 'session_id')}
            assert cold.db.get_session(sid)['title'] == 'Portable'
        finally:
            cold_runner.session_store.close_all_db_handles()
    finally:
        runner.session_store.close_all_db_handles()


@pytest.mark.asyncio
async def test_unenrolled_cross_profile_receipt_fails_closed(tmp_path, monkeypatch):
    from gateway import run
    from gateway.session_authority import initialize_session_authority
    from gateway.session_contract import Principal, SessionRef
    from hermes_state_local import local_receipt
    from hermes_state_runtime import RuntimeStoreError, begin_runtime_epoch
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setattr(run, '_load_gateway_config', lambda *a: {})
    runner = _runner(tmp_path)
    try:
        saved = _windows_receipt(runner._session_db, begin_runtime_epoch(runner._session_db,
                                  instance_id='fixture-windows'), workspace=tmp_path, windows_policy=False)
        authority = await initialize_session_authority(runner, profile_id=str(tmp_path), instance_id='linux')
        with pytest.raises(RuntimeStoreError, match='profile_mismatch'):
            await authority.attach(Principal('uid:1000', str(tmp_path), CAPS, 'socket'),
                                   SessionRef(str(tmp_path), saved['session_id']))
        assert local_receipt(authority.db, saved['session_id']) == saved
    finally:
        runner.session_store.close_all_db_handles()


def test_projecting_cwd_changes_legacy_credential_binding(tmp_path):
    from gateway.session_policy import build_policy
    from gateway.session_policy_credentials import _check_scope, policy_identity
    from hermes_state_runtime import RuntimeStoreError
    policy = build_policy({'source': 'gui', 'cwd': str(tmp_path), 'model': 'fixture'}, {})
    terminal = json.loads(policy.terminal_json)
    terminal['TERMINAL_CWD'] = WINDOWS_CWD
    projected = replace(policy, cwd=WINDOWS_CWD, terminal_json=json.dumps(terminal))
    assert policy_identity(projected) != policy_identity(policy)
    source = {'home': str(tmp_path), 'profile': str(tmp_path), 'policy': policy_identity(policy)}
    authority = SimpleNamespace(profile_id=str(tmp_path))
    _check_scope(authority, source, policy, tmp_path, ())
    with pytest.raises(RuntimeStoreError, match='launch_credentials_unavailable'):
        _check_scope(authority, source, projected, tmp_path, ())


@pytest.mark.platforms('linux')
def test_raw_windows_policy_is_rejected_on_real_linux(tmp_path):
    from gateway.session_policy import build_policy, restore_policy
    from hermes_state_runtime import RuntimeStoreError
    policy = build_policy({'source': 'gui', 'cwd': str(tmp_path), 'model': 'fixture'}, {})
    terminal = json.loads(policy.terminal_json)
    terminal['TERMINAL_CWD'] = WINDOWS_CWD
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        restore_policy(asdict(replace(policy, cwd=WINDOWS_CWD, terminal_json=json.dumps(terminal))))
