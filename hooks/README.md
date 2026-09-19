# Jev Sentinel for Claude Code and Codex CLI

The same checks as the pi extension, run as a hook. Both hosts hand a command one JSON event on
stdin and read one JSON decision from stdout, so one program serves both.

| Hook event | What the sentinel does |
|---|---|
| `PreToolUse` | Asks Jev about intent and risk. Runs the ask-for-more-context loop. Returns **ask** (your host's own approval prompt) or **deny** with a reason the agent can read. |
| `PostToolUse` | Screens the output for instructions aimed at AI agents. A flagged output gets a warning appended for the agent, a notice for you, and turns on "every action asks you". |
| `Stop` | Checks the finished reply for harmful content and relayed injected instructions. The warning goes to you only. |
| `UserPromptSubmit` | Pins a task when `pinTasks` is on (a message starting with `*`). |
| `SessionStart` | Clears the "every action asks you" flag and reports a bad settings file. |

## Setup

```bash
git clone https://github.com/harshwasan/pi-jev-sentinel
cd pi-jev-sentinel
npm install
npm run build          # writes dist/hook.js
```

Set `TYPESAFE_API_KEY` where your agent will see it. Then try it without touching any host:

```powershell
$env:TYPESAFE_API_KEY = "..."
.\hooks\try-hook.ps1            # or: .\hooks\try-hook.ps1 -Agent codex
```

It sends five made-up events (a benign command, a `curl … | sh`, a settings edit, a poisoned file,
a reply that relays the injection) and prints each decision. Nothing runs, no host is involved.

### Claude Code

Copy the blocks from [`claude-settings.example.json`](claude-settings.example.json) into
`~/.claude/settings.json` (all projects) or `.claude/settings.local.json` (one project), replacing
`/path/to/pi-jev-sentinel` with where you cloned it.

### Codex CLI

Copy [`codex-hooks.example.json`](codex-hooks.example.json) to `~/.codex/hooks.json`, or put the
same events in `~/.codex/config.toml`. Needs a Codex build with hooks (checked against 0.137.0).

Settings go in `~/.jev-sentinel/config.json`, or wherever `JEV_SENTINEL_CONFIG` points. Every
setting is the same as the pi extension's; see the main [README](../README.md). Decisions are logged
to `~/.jev-sentinel/decisions.jsonl`.

## What differs from the pi extension

Honest differences, not preferences:

- **The output check runs after the tool ran.** Pi can put a warning *in front of* a file's contents
  before the agent reads it. A hook only sees the output afterwards, so the warning follows it. The
  agent has already read the text by then; the warning and the approval flag are what remain.
- **"Ask" means your host's own prompt.** The pi extension can put **Block** first on an unsafe
  action. A hook can only say `ask`, so an unsafe result becomes a `deny` with the reason, plus a
  notice to you.
- **An allowed action returns nothing.** The sentinel never auto-approves: your host's own
  permission rules still apply, and Jev only ever adds friction.
- **State lives in a file.** Each hook run is a new process, so the approval flag and the pinned task
  are kept in `~/.jev-sentinel/sessions/<session id>.json` instead of in memory.
- **History is read from the transcript file** the host names, rather than from the agent's own
  session objects. Subagent branches are skipped, and the host's system instructions are never sent.
- **Pinning cannot strip the `*` on Codex**, which has no way to rewrite a submitted prompt.

## Cost and latency

One Jev request per tool call, per screened output, and per reply, the same as the pi extension:
roughly 0.3–1 s each. To spend less, screen fewer tools (narrow the `PostToolUse` matcher), or set
`screenReplies` to `false`.
