"""Portable credential rebinding remains an explicit exact-fingerprint operation."""
import pytest

from tests.gateway.test_portable_session_paths import portable


@pytest.mark.asyncio
async def test_portable_resume_key_refuses_unlaunched_key(portable):
    from gateway.session_policy import rebind_launch_key
    from hermes_state_runtime import RuntimeStoreError
    authority, _, ref, *_ = portable
    with pytest.raises(RuntimeStoreError, match='admission_conflict'):
        rebind_launch_key(authority, ref, 'not-a-real-secret')


@pytest.mark.asyncio
async def test_portable_picker_refuses_unenrolled_actor(portable):
    from dataclasses import replace
    from gateway.session_listing import stored_picker_sessions
    authority, actor, ref, *_ = portable
    actor = replace(actor, subject='uid:99999')
    authority._native_legacy_transports = {actor.transport_id: actor}
    authority.db.end_session(ref.session_id, 'user')
    authority.sessions.pop(ref.session_id, None)
    assert stored_picker_sessions(authority, actor, limit=20)['sessions'] == []
