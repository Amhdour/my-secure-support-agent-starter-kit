# tools/

Secure tooling layer with centralized registration and mediated routing.

Phase 4 adds:
- `InMemoryToolRegistry` as centralized registry for tool descriptors.
- `SecureToolRouter` to mediate every tool invocation.
- Explicit router decisions: `allow`, `deny`, `require_confirmation`.
- Support for allowlists, forbidden actions, forbidden fields, and per-tool rate limits.
- Input validation before execution and mediated execution helper (`mediate_and_execute`).

Important:
- No direct tool execution path should bypass the router.
- Router is policy-ready and deny-first when uncertain.
