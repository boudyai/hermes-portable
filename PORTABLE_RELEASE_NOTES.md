# Hermes Portable: experimental dual-boot support

This fork adds opt-in paired-owner session access between Windows and Linux for a shared Hermes profile. See README_PORTABLE.md for behavior and enrollment.

Implemented backend paths include session restoration and listing, runtime working-directory projection, model/workspace mutations, policy refresh, branching and compression. Original receipt identities and stored prompt/history are not rewritten for an OS switch. Current-host context is delivered to the model through the existing turn-context mechanism.

The optional permissive mode allows otherwise opaque launch settings to survive restoration: tools may report missing paths or programs normally. This is a usability trade-off, not automatic portability of executables, hooks or MCP servers. Only enable it for trusted profile settings. Credential and endpoint checks remain enforced.

Validation is performed with isolated profiles and loopback model fixtures. Windows-format receipts tested on Linux are not native Windows execution. Native Windows and full graphical Desktop testing remain separate validation requirements; passing an authenticated Desktop backend route is not a claim that Electron rendering was exercised.

Changes to active source trees require restarting the gateway and clients. Keep backups and never run competing gateways against a shared database.
