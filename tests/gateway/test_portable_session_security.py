"""Enrollment and execution projection security, using only disposable homes."""
import json
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from gateway.session_policy import LocalSessionPolicy, build_policy, restore_policy
from gateway.session_policy_credentials import _check_scope, policy_identity
from gateway.session_portability import enrollment, paired, project_path, durable_policy
from hermes_state_runtime import RuntimeStoreError

WIN = r'C:\Users\portable\AppData\Local\hermes'
SID = 'sid:S-1-5-21-111111111-222222222-333333333-1001'
ROOT = r'C:\Users\portable'


def fixture(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    from gateway.owner_identity import host_owner_subject
    owner = host_owner_subject()
    authority = SimpleNamespace(profile_id=str(tmp_path), db=SimpleNamespace(db_path=str(tmp_path / 'state.db')))
    data = {'version': 1, 'hosts': [{'profile_id': WIN, 'principal_id': SID},
            {'profile_id': str(tmp_path), 'principal_id': owner}],
            'roots': [{'windows': ROOT, 'posix': str(tmp_path)}]}
    (tmp_path / 'portable-sessions.json').write_text(json.dumps(data))
    return authority, data, owner


def test_legacy_credentials_accept_exact_enrolled_scope_and_original_hash(tmp_path, monkeypatch):
    authority, _data, _owner = fixture(tmp_path, monkeypatch)
    policy = build_policy({'source': 'gui', 'cwd': str(tmp_path), 'model': 'fixture'}, {})
    terminal = json.loads(policy.terminal_json)
    terminal['TERMINAL_CWD'] = ROOT
    request = json.loads(policy.request_json)
    request['cwd'] = ROOT
    policy = replace(policy, cwd=ROOT, terminal_json=json.dumps(terminal), request_json=json.dumps(request))
    from tests.gateway.test_portable_session_contract import _runner, _windows_receipt
    from hermes_state_runtime import begin_runtime_epoch
    runner = _runner(tmp_path)
    authority.db = runner._session_db
    saved = _windows_receipt(authority.db, begin_runtime_epoch(authority.db, instance_id='fixture'),
                             workspace=tmp_path)
    policy = LocalSessionPolicy(**saved['policy'])
    source = {'home': WIN, 'profile': WIN, 'policy': policy_identity(policy), 'session': saved['session_id']}
    projected = restore_policy(asdict(policy), authority=authority, runtime=True)
    _check_scope(authority, source, projected, tmp_path, ())
    assert policy_identity(projected) == source['policy']
    for altered in ({**source, 'home': r'C:\other'}, {**source, 'profile': str(tmp_path)},
                    {**source, 'policy': 'bad'}):
        with pytest.raises(RuntimeStoreError, match='launch_credentials_unavailable'):
            _check_scope(authority, altered, projected, tmp_path, ())


@pytest.mark.parametrize('change', ['owner', 'profile', 'extra_host', 'unknown_key', 'overlap', 'traversal'])
def test_invalid_enrollment_refused(tmp_path, monkeypatch, change):
    authority, data, _owner = fixture(tmp_path, monkeypatch)
    if change == 'owner':
        data['hosts'][1]['principal_id'] = 'uid:999999'
    elif change == 'profile':
        data['hosts'][1]['profile_id'] += '/profiles/other'
    elif change == 'extra_host':
        data['hosts'].append(data['hosts'][0])
    elif change == 'unknown_key':
        data['allow_all'] = True
    elif change == 'overlap':
        data['roots'].append({'windows': ROOT + r'\work', 'posix': str(tmp_path / 'work')})
    else:
        data['roots'][0]['windows'] += r'\..\other'
    (tmp_path / 'portable-sessions.json').write_text(json.dumps(data))
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        enrollment(authority)


@pytest.mark.parametrize('path', [r'D:\work', r'C:\Users\portable-other\work', r'C:\Users\portable\..\other',
                                   r'\\server\share', r'C:work', r'C:\Users\portable\file:stream'])
def test_unmapped_and_unsafe_paths_refused(tmp_path, monkeypatch, path):
    authority, _, _ = fixture(tmp_path, monkeypatch)
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        project_path(authority, path)


def test_symlink_suffix_and_enrollment_refused(tmp_path, monkeypatch):
    authority, _, _ = fixture(tmp_path, monkeypatch)
    (tmp_path / 'escape').symlink_to(tmp_path.parent, target_is_directory=True)
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        project_path(authority, ROOT + r'\escape\outside')
    path = tmp_path / 'portable-sessions.json'
    path.rename(tmp_path / 'elsewhere.json')
    path.symlink_to(tmp_path / 'elsewhere.json')
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        enrollment(authority)


def test_pair_is_exact_and_not_general_owner_equivalence(tmp_path, monkeypatch):
    authority, _, owner = fixture(tmp_path, monkeypatch)
    from gateway.owner_identity import same_owner
    assert paired(authority, WIN, SID, actor=owner)
    assert not paired(authority, WIN, owner, actor=owner)
    assert not paired(authority, WIN, SID, actor='uid:999999')
    assert not paired(authority, WIN + r'\profiles\other', SID, actor=owner)
    assert not same_owner(SID, owner)
