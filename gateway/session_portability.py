"""Explicit, profile-local dual-boot enrollment; never general owner equivalence.

Only the authority's database home is consulted. No environment/home fallback.
The durable policy remains the source of truth; projections are execution-only.
"""
import json
import os
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path, PureWindowsPath, PurePosixPath

from hermes_state_runtime import RuntimeStoreError


def _home(authority):
    return Path(authority.db.db_path).resolve().parent


def enrollment(authority):
    path = _home(authority) / 'portable-sessions.json'
    if not path.exists():
        return None
    try:
        if path.is_symlink():
            raise ValueError('symlink enrollment')
        data = json.loads(path.read_text(encoding='utf-8'))
        if (set(data) - {'version', 'hosts', 'roots', 'os_switch'}
                or not {'version', 'hosts', 'roots'} <= set(data)
                or type(data['version']) is not int or data['version'] != 1
                or data.get('os_switch', 'strict') not in ('strict', 'permissive')):
            raise ValueError('schema')
        hosts = data['hosts']
        if not isinstance(hosts, list) or len(hosts) != 2:
            raise ValueError('exactly two hosts required')
        for host in hosts:
            if not isinstance(host, dict) or set(host) != {'profile_id', 'principal_id'}:
                raise ValueError('host')
            if not all(isinstance(v, str) and v and not any(c in v for c in '\x00\r\n') for v in host.values()):
                raise ValueError('identity')
        windows = [h for h in hosts if re.fullmatch(r'sid:S-1-\d+(?:-\d+)+', h['principal_id'])]
        posix = [h for h in hosts if re.fullmatch(r'uid:\d+', h['principal_id'])]
        if len(windows) != 1 or len(posix) != 1:
            raise ValueError('one SID and one UID required')
        _parts(windows[0]['profile_id'], True)
        _parts(posix[0]['profile_id'], False)
        current = windows[0] if os.name == 'nt' else posix[0]
        from gateway.owner_identity import host_owner_subject
        if (current['profile_id'] != authority.profile_id or current['profile_id'] != str(_home(authority))
                or current['principal_id'] != host_owner_subject()):
            raise ValueError('current host not enrolled')
        roots = data['roots']
        if not isinstance(roots, list) or not roots:
            raise ValueError('roots')
        for root in roots:
            if not isinstance(root, dict) or set(root) != {'windows', 'posix'}:
                raise ValueError('root')
            _parts(root['windows'], True)
            _parts(root['posix'], False)
        # Overlapping roots have ambiguous meaning in either direction: refuse, do not pick one.
        for key, win in (('windows', True), ('posix', False)):
            paths = [_parts(r[key], win) for r in roots]
            for i, a in enumerate(paths):
                for b in paths[i + 1:]:
                    if a[:len(b)] == b or b[:len(a)] == a:
                        raise ValueError('overlapping roots')
        return data
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise RuntimeStoreError('storage_unavailable', field='portable_sessions', detail=str(exc)) from exc


def _parts(value, windows):
    if not isinstance(value, str) or not value or any(c in value for c in '\x00\r\n'):
        raise ValueError('invalid path')
    p = PureWindowsPath(value) if windows else PurePosixPath(value)
    if not p.is_absolute() or '..' in p.parts or '.' in re.split(r'[\\/]', value):
        raise ValueError('nonabsolute or traversing path')
    if windows and (not re.fullmatch(r'[A-Za-z]:', p.drive) or ':' in ''.join(p.parts[1:])):
        raise ValueError('unsupported Windows path')
    if not windows and ('\\' in value or value.startswith('//')):
        raise ValueError('unsupported POSIX path')
    return p.parts  # exact spelling, deliberately no case-folded enrollment aliases


def paired(authority, profile, principal, *, actor=None):
    data = enrollment(authority)
    if data is None:
        return False
    current = next(h for h in data['hosts'] if h['profile_id'] == authority.profile_id)
    if actor is not None and actor != current['principal_id']:
        return False
    return {'profile_id': profile, 'principal_id': principal} in data['hosts']


def receipt_access(authority, receipt, subject):
    return paired(authority, receipt.get('profile_id'), receipt.get('principal_id'), actor=subject)


def credential_scope(authority, source):
    """An original reference may cross only with its original receipt and enrolled owner."""
    if source.get('home') == source.get('profile') == authority.profile_id:
        return False  # ordinary exact-scope path does not need enrollment
    try:
        from hermes_state_local import local_receipt
        receipt = local_receipt(authority.db, source['session'])
        return (source.get('home') == source.get('profile') == receipt['profile_id']
                and paired(authority, receipt['profile_id'], receipt['principal_id']))
    except (RuntimeStoreError, KeyError, AttributeError):
        return False


def project_path(authority, value, *, reverse=False):
    data = enrollment(authority)
    if data is None:
        raise RuntimeStoreError('storage_unavailable', field='cwd', detail='portable path not enrolled')
    target_win = (os.name == 'nt') != reverse
    source_key, target_key = ('posix', 'windows') if target_win else ('windows', 'posix')
    try:
        parts = _parts(value, not target_win)
        for root in data['roots']:
            prefix = _parts(root[source_key], not target_win)
            if parts[:len(prefix)] != prefix:
                continue
            if reverse:
                # Validate the local destination before encoding it in the original host namespace.
                local = Path(value)
                base = Path(root[source_key])
                for candidate in (local, *local.parents, base, *base.parents):
                    if candidate.is_symlink():
                        raise ValueError('symlink in workspace destination')
                local.resolve().relative_to(base.resolve())
                cls = PureWindowsPath if target_win else PurePosixPath
                return str(cls(root[target_key]).joinpath(*parts[len(prefix):]))
            target = Path(root[target_key]).joinpath(*parts[len(prefix):])
            # A mapped suffix may not escape through an existing symlink (including dangling ones).
            base = Path(root[target_key])
            for candidate in (base, *base.parents, target, *target.parents):
                if candidate.is_symlink():
                    raise ValueError('symlink in projected path')
            target.resolve().relative_to(base.resolve())
            return str(target)
        raise ValueError('unmapped path')
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeStoreError('storage_unavailable', field='cwd', detail=str(exc)) from exc


def durable_policy(policy):
    """Serialize original values, never the execution-only projection."""
    return asdict(getattr(policy, '_durable_policy', policy))


def local_cwd(authority, value):
    """Validate the foreign namespace; opt-in falls back only for workspace availability."""
    data = enrollment(authority)
    permissive = (data or {}).get('os_switch') == 'permissive'
    if permissive:
        _parts(value, os.name != 'nt')
    try:
        cwd = project_path(authority, value)
    except RuntimeStoreError:
        if not permissive:
            raise
        cwd = None
    if permissive and (cwd is None or not Path(cwd).is_dir()):
        cwd = str(Path.home())
    return cwd


def runtime_policy(authority, policy):
    """Execution-only cwd adaptation; executable state is never translated."""
    if Path(policy.cwd).is_absolute():
        return policy
    cwd = local_cwd(authority, policy.cwd)
    # Opt-in accepts ordinary OS command failures, without translating executable state.
    if (enrollment(authority) or {}).get('os_switch') == 'permissive':
        terminal = json.loads(policy.terminal_json)
        from gateway.session_policy import terminal_uses_host_cwd
        if terminal_uses_host_cwd(terminal):
            terminal['TERMINAL_CWD'] = cwd
        request = json.loads(policy.request_json)
        request['_os_switch_workspace'] = policy.cwd
        return RuntimeSessionPolicy(
            **{**asdict(policy), 'cwd': cwd, 'terminal_json': json.dumps(terminal),
               'request_json': json.dumps(request)},
            _durable_policy=policy)
    # These carry arbitrary scripts, executable paths or environment; translating them would guess.
    if policy.client_env_json or policy.editor_mcp_json or policy.kanban_json:
        raise RuntimeStoreError('storage_unavailable', field='portable_sessions', detail='host-bound launch state')
    config = json.loads(policy.config_json)
    # Commands, hooks, transport env and external launchers are opaque executable state.
    # Even a seemingly portable command can resolve to a different executable after boot.
    servers = config.get('mcp_servers') or {}
    inert_servers = isinstance(servers, dict) and all(spec == {'enabled': False} for spec in servers.values())
    if (not inert_servers or any(config.get(key) for key in ('hooks', 'plugins', 'terminal', 'browser'))):
        raise RuntimeStoreError('storage_unavailable', field='portable_sessions', detail='host-bound config')
    terminal = json.loads(policy.terminal_json)
    from tools.terminal_scope import default_terminal_scope
    defaults = {**default_terminal_scope(), 'TERMINAL_DOCKER_IMAGE_PINNED': '0'}
    # Frozen terminal defaults are known; arbitrary env, shell and toolchain additions aren't.
    if any(key != 'TERMINAL_CWD' and (key not in defaults or value != defaults[key])
           for key, value in terminal.items()):
        raise RuntimeStoreError('storage_unavailable', field='portable_sessions', detail='host-bound terminal state')
    from gateway.session_policy import terminal_uses_host_cwd
    if not terminal_uses_host_cwd(terminal):
        raise RuntimeStoreError('storage_unavailable', field='portable_sessions', detail='non-host terminal')
    terminal['TERMINAL_CWD'] = cwd
    request = json.loads(policy.request_json)
    for key in ('cwd', 'row_cwd'):
        if request.get(key):
            request[key] = project_path(authority, request[key])
    return RuntimeSessionPolicy(
        **{**asdict(policy), 'cwd': cwd, 'terminal_json': json.dumps(terminal),
           'request_json': json.dumps(request)}, _durable_policy=policy)


from gateway.session_policy import LocalSessionPolicy


@dataclass(frozen=True)
class RuntimeSessionPolicy(LocalSessionPolicy):
    """Execution-only view: dataclasses.replace preserves the durable provenance.

    Mutations must start from restore_policy(runtime=False), never from this view.
    This subclass is never a durable receipt schema.
    """
    _durable_policy: LocalSessionPolicy | None = None


def os_switch_note():
    """New-turn context only; preserve the frozen system prefix and durable history."""
    import platform
    from gateway.session_policy import active_policy
    policy = active_policy()
    original = json.loads(policy.request_json).get('_os_switch_workspace') if policy else None
    if not original:
        return ''
    backend = json.loads(policy.terminal_json).get('TERMINAL_ENV') or 'local'
    return (f'OS changed since this session was created. Current Hermes host: {platform.system()}; '
            f'home: {Path.home()}; local workspace: {policy.cwd}; original workspace: {original}. '
            f'Terminal backend remains {backend} (remote backends keep their own OS/home/cwd). '
            'Earlier environment hints may be stale. Old paths/programs are not rewritten; '
            'if a tool fails, adapt to the current environment.')


def execution_policy(policy):
    """Worker wire schema: runtime values without private provenance metadata."""
    return {field.name: getattr(policy, field.name) for field in fields(LocalSessionPolicy)}
