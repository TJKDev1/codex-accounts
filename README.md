# Codex Accounts

Pi extension for multiple OpenAI Codex OAuth accounts.

## Install

This repo is a pi package:

```bash
pi install git:https://github.com/TJKDev1/codex-accounts.git
```

Run `/reload` in pi after install or update.

## Commands

```text
/codex-accounts
/codex-accounts add <name>
/codex-accounts import-codex [name]
/codex-accounts usage [name-or-provider]
/codex-accounts list
/codex-accounts switch <name-or-provider>
/codex-accounts default <name-or-provider>
/codex-accounts refresh <name-or-provider>
/codex-accounts rename <name-or-provider>
/codex-accounts remove <name-or-provider>
```

Each account becomes its own provider, for example:

```text
openai-codex-work/gpt-5.1-codex-max
openai-codex-personal/gpt-5.1-codex-max
```

Credentials stay in `~/.pi/agent/auth.json` under those provider IDs. Account labels stay in `~/.pi/agent/multi-codex-accounts.json`.

## Notes

- Built-in `openai-codex` remains unchanged.
- Existing Codex CLI auth can be imported from `~/.codex/auth.json` with `/codex-accounts import-codex`.
- Usage is shown with `/codex-accounts usage`. For imported Codex CLI accounts, it calls `codex app-server` → `account/rateLimits/read` for live 5h/weekly limits. For pi-only accounts, it shows cached `x-codex-*` response headers after the next model response.
- `/login openai-codex-<name>` also works after an account provider exists.
- `/codex-accounts add <name>` starts OpenAI OAuth and attempts to open browser.
