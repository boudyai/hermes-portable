"""Real Linux CLI transport and authenticated Desktop route, with Windows receipts.

Only inference is a loopback fixture; this is NOT native Windows verification.
"""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.gateway.fixtures.local_recovery_probe import child_env, daemon, rpc, websocket


@pytest.fixture
def portable_owner(tmp_path, model_peer):
    root = Path(__file__).resolve().parents[2]
    home, user = tmp_path / 'state', tmp_path / 'user'
    home.mkdir()
    user.mkdir()
    url = f'http://127.0.0.1:{model_peer.server_port}/v1'
    config = {'gateway': {'multiplex_profiles': False},
              'model': {'provider': 'custom', 'default': 'local-wire-stub', 'base_url': url},
              'auxiliary': {'title_generation': {'enabled': False}},
              'platform_toolsets': {'cli': []},
              'mcp_servers': {'old-windows': {'enabled': False, 'command': r'C:\missing-portable\server.exe'}}}
    (home / 'config.yaml').write_text(json.dumps(config))
    env = child_env()
    env.update(HOME=str(user), USERPROFILE=str(user), HERMES_HOME=str(home),
               PYTHONPATH=str(root), PYTHONUNBUFFERED='1', OPENAI_API_KEY='loopback-only',
               OPENAI_BASE_URL=url, NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
    seed = '''
import json, os
from pathlib import Path
from tests.gateway.test_portable_session_contract import _runner, _enroll, _windows_receipt
from gateway.owner_identity import host_owner_subject
from hermes_state_runtime import begin_runtime_epoch
home = Path(os.environ['HERMES_HOME'])
runner = _runner(home)
_enroll(home, home / 'unavailable-work')
path = home / 'portable-sessions.json'
data = json.loads(path.read_text())
data['hosts'][1]['principal_id'] = host_owner_subject()
data['os_switch'] = 'permissive'
path.write_text(json.dumps(data))
saved = _windows_receipt(runner._session_db, begin_runtime_epoch(runner._session_db, instance_id='windows-fixture'), workspace=home,
    config={'model': {'provider': 'custom', 'default': 'local-wire-stub', 'base_url': os.environ['OPENAI_BASE_URL']},
            'mcp_servers': {'old-windows': {'enabled': False, 'command': r'C:\\missing-portable\\server.exe'}}})
sid = saved['session_id']
runner._session_db.append_message(sid, 'assistant', 'Frozen Windows answer')
runner._session_db.update_system_prompt(sid, 'Frozen Windows system prefix')
(home / 'seed.json').write_text(json.dumps(saved))
runner.session_store.close_all_db_handles()
'''
    result = subprocess.run([sys.executable, '-c', seed], cwd=root, env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    saved = json.loads((home / 'seed.json').read_text())
    with daemon(root, home, env, barrier=False) as (_, descriptor):
        yield root, home, env, saved, descriptor


def assert_preserved(home, saved, model_peer, text):
    from hermes_state import SessionDB
    from hermes_state_local import local_receipt
    db = SessionDB(db_path=home / 'state.db', read_only=True)
    try:
        assert local_receipt(db, saved['session_id']) == saved
        assert db.get_session(saved['session_id'])['system_prompt'] == 'Frozen Windows system prefix'
        history = db.get_messages(saved['session_id'])
        assert [row['content'] for row in history[:2]] == ['Windows history', 'Frozen Windows answer']
        assert any(row['content'] == text for row in history)
        assert all('OS changed' not in str(row['content']) for row in history)
    finally:
        db.close()
    messages = model_peer.requests[-1]['messages']
    wire = json.dumps(messages)
    assert messages[0]['content'] == 'Frozen Windows system prefix'
    assert 'Windows history' in wire and 'Frozen Windows answer' in wire
    assert 'OS changed' in wire and 'Linux' in wire
    assert str(Path(home).parent / 'user') in wire
    assert 'Old paths/programs are not rewritten' in wire


@pytest.mark.platforms('linux')
def test_cli_transport_resumes_permissive_windows_receipt(portable_owner, model_peer):
    root, home, env, saved, _ = portable_owner
    result = subprocess.run([sys.executable, '-m', 'hermes_cli.main', '--cli', 'chat',
                             '--resume', saved['session_id'], '-q', 'WS_SHARED portable CLI', '-Q'],
                            cwd=root, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'LOCAL_ACK_WS_SHARED' in result.stdout
    assert_preserved(home, saved, model_peer, 'WS_SHARED portable CLI')


@pytest.mark.platforms('linux')
def test_desktop_authenticated_route_resumes_permissive_windows_receipt(portable_owner, model_peer):
    _, home, _, saved, descriptor = portable_owner
    sid = saved['session_id']

    async def desktop():
        async with websocket(home, descriptor, proxy=None) as ws:
            resumed = await rpc(ws, 'session.resume', session_id=sid)
            assert 'result' in resumed, resumed
            assert 'Windows history' in json.dumps(resumed['result'])
            submitted = await rpc(ws, 'prompt.submit', session_id=sid,
                                  input_id='desktop-portable', text='WS_SHARED portable Desktop')
            assert submitted.get('result', {}).get('status') == 'queued', submitted
            async def settled():
                reply = await rpc(ws, 'prompt.receipt', session_id=sid, admission_id=submitted['result']['admission_id'])
                return reply.get('result', {}).get('status') == 'terminal'
            async with asyncio.timeout(60):
                while not await settled():
                    await asyncio.sleep(.05)
    asyncio.run(desktop())
    assert_preserved(home, saved, model_peer, 'WS_SHARED portable Desktop')
