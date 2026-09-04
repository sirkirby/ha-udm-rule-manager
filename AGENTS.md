# UniFi Network Rules

This repository contains a Home Assistant custom integration for managing UniFi Network rules and related entities.

## Architecture

- Support the current Home Assistant release on Python 3.14.2 or newer.
- Use the coordinator as the canonical polling and state-management path.
- Model API responses with typed classes in `models/` before adding API methods in `udm/` or entities in `switches/`.
- Build switch entities on the shared base class and keep service orchestration in `services/`.
- Preserve compatibility across supported UniFi controller versions through capability detection, not version guesses.

## Code Standards

- Type hints are required.
- Follow Ruff lint + format rules defined in `pyproject.toml`. Do not disable rules inline without reason.
- Google-style docstrings on public functions and classes.
- Do not swallow exceptions silently; log with context. Never put secrets, tokens, or session data in logs or error messages.

## Quality Gates

Before claiming work is done, run:

```
make lint
make test
```

Both MUST pass. Do not use `--no-verify` or skip hooks.

## Working Style

- Fix root causes, not symptoms.
- Prefer editing existing files over creating new ones.
- Default to no comments; add one only when the *why* is non-obvious.
- New dependencies require explicit approval — do not add them unprompted.

<!-- myco:managed:start -->
## Myco Managed Guidance

- When `capture.ignore_plan_dirs_in_git` is enabled, custom directories in `capture.plan_dirs` may be intentionally gitignored after capture into Myco.
- Do not force-add files from intentionally gitignored custom plan directories unless the user explicitly asks.
- When orienting in this codebase — finding a feature, locating files relevant to a change, or understanding an unfamiliar subsystem — use Myco first: call `myco tool call myco_cortex --json --input '{"op":"canopy_map"}'` as the CLI path, or `myco_cortex({"op":"canopy_map"})` via MCP when the host exposes Myco tools cleanly, before falling back to Glob/Grep.
<!-- myco:managed:end -->
