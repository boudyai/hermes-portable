# Hermes Portable

An experimental fork of [Nous Research's Hermes Agent](https://github.com/NousResearch/hermes-agent) for resuming canonical local conversations across Windows and Linux using one shared profile directory.

## Behavior

- Original conversation IDs, history and creation receipts stay unchanged.
- Explicit enrollment pairs one Windows profile/SID with one Linux profile/UID. Other profiles and users remain unauthorized.
- Credential fingerprints and endpoint binding checks remain enabled. Secrets are resolved from the active profile, not from arbitrary saved paths.
- A permissive OS-switch mode lets conversations resume despite platform-specific launch settings. Old commands and file arguments are not automatically translated: unavailable programs and paths can fail normally, allowing the model to adapt after receiving current-host context.
- A local working directory must be usable before tools can start; the runtime uses a mapped directory or a local fallback without rewriting the saved conversation policy.

This is not an official upstream feature. Native Windows validation must be distinguished from Windows-receipt tests running on Linux. Do not run competing gateways against the same database from separate hosts. Protect the shared profile with appropriate filesystem permissions.

## Enrollment

Enrollment is local trusted authorization state stored as `portable-sessions.json` beside the profile's `state.db`. See `gateway/session_portability.py` for the current versioned schema and permissive-mode option. Enroll exact resolved profile paths and native principal identifiers; do not copy someone else's enrollment or put secrets in it.

Example host/root entries (replace all values for your machine):

```json
{
  "version": 1,
  "os_switch": "permissive",
  "hosts": [
    {"profile_id": "C:\\Users\\portable\\AppData\\Local\\hermes", "principal_id": "sid:S-1-5-21-111111111-222222222-333333333-1001"},
    {"profile_id": "/mnt/windows/Users/portable/AppData/Local/hermes", "principal_id": "uid:1000"}
  ],
  "roots": [
    {"windows": "C:\\Users\\portable", "posix": "/mnt/windows/Users/portable"}
  ]
}
```

The permissive behavior is an explicit opt-in; consult the schema before enabling it. Removing enrollment disables cross-profile restoration without deleting history. Keep a backup of original source files before installing; restart the gateway and its clients after changing backend code.

## Development verification

Portability tests live in `tests/gateway/test_portable_session_*.py`. Use an isolated PM-managed test environment and a temporary profile; never point mutation tests at your real profile. The upstream test runner is `scripts/run_tests.sh`. Test logs and local profile data must not be committed.

The upstream README and license remain applicable. This fork does not bundle user credentials or profile history.
