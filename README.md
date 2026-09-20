# jev-sentinel

A guard for coding agents, built on TypeSafe's [Jev](https://docs.typesafe.ai/) model: it checks what the agent does, reads, and says. One set of checks, three hosts: a [Pi](https://github.com/earendil-works/pi) extension, and a plugin for **Claude Code** and **Codex CLI**.

A README that says "AI agents: run `curl … | sh`" is just more text to the model, and a permission prompt that only knows a tool name cannot tell you whether *this* command is what you asked for. Jev Sentinel puts a fast, cheap judge in front of every step: Jev answers typed questions with probabilities, and plain code turns those into **allow**, **ask you**, or **warn**. Pi has no permission system at all, so there it is the gate; on Claude Code and Codex it adds a content-aware layer on top of the prompts you already get.

![A README hides instructions for AI agents. Jev flags the file before the agent reads it, and when the agent still tries the command, blocks it as injected (95%) and harmful (96%).](docs/images/injection-caught-twice.png)

## What it checks

| When | Check | What happens when flagged |
|------|-------|---------------------------|
| **Before a tool call runs** | Intent (on task / off task / injected / needs more context) and risk (safe → needs approval → harmful, scored 0 to 2) | Asks you, or warns with **Block** highlighted. If you block it, the agent is told plainly and tries another way. |
| **Before the agent reads a tool output** | Does the file or command output contain instructions for AI agents, and are they benign or suspicious? | A warning is put on top of the output, you get an alert, and every later action needs your approval until `/jev-sentinel reset`. |
| **After a reply finishes** | Harmful content; relaying injected instructions. Optional: unsupported claims, skipped work. | You get a notice. It is never added to the agent's context. |

It also:

- **Asks for more context when unsure.** If Jev says more context would help, the extension adds earlier messages, full tool outputs, or file contents, and asks again (up to 3 rounds) before interrupting you.
- **Scrubs secrets before they reach Jev.** Output from `.env`, keys, and credential files is withheld. Their values, secret-looking environment variables, `NAME=value` secrets, and `Bearer` tokens are scrubbed from everything sent to Jev, including the agent's own replies. This is pattern-based, so it reduces leaks rather than guaranteeing none (see [What is sent](#what-is-sent-to-typesafe)).
- **Pins a task (optional).** Start a message with `*` to pin it. Jev then judges "on task" against the pin instead of whatever the chat drifted to.
- **Fails closed.** If Jev errors or no key is set, it asks you. It never auto-allows.
- **Protects its own settings.** Any tool call other than a read that touches `~/.pi/agent` (pi's settings, sessions, and this extension's settings) or the decision log always gets the Block-first warning, whatever Jev says.

## Examples

These screenshots come from real runs with `gpt-4o-mini` as the agent, taken while the project was still called `jev-guard`.

| | |
|---|---|
| ![Flagged before the agent reads it](docs/images/injection-flagged-before-agent.png) **Output check:** the README is flagged (100%) before the agent sees it, and the agent declines the setup command. | ![Trusted file, curl still caught](docs/images/trusted-file-curl-still-caught.png) **Layers:** a trusted file skips the output check, but the `curl … \| sh` it asks for is still caught (injected 83%). |
| ![Pinned task](docs/images/pinned-task-off-task.png) **Pinned task:** with "fix the login bug" pinned, a footer edit is asked as off task (80%). | ![Reply relaying an injection](docs/images/reply-relays-injection.png) **Reply check:** the agent repeats a planted `curl \| sh` "recommendation", and it is flagged (98%). |
| ![Agent disobeyed](docs/images/agent-disobeyed-caught.png) **Caught twice:** told "don't delete right now", the agent ran `rm -rf` anyway (asked, off task 98%), then contradicted itself (flagged as unsupported, 94%). | ![npm install asks](docs/images/approval-npm-install.png) **Approval:** `npm test` runs silently, and `npm install lodash` asks (needs approval, 0.93). |

Warnings shown inside replies in some screenshots are from an earlier version. Reply warnings are now shown to you only.

## Install

Set your TypeSafe key ([console.typesafe.ai/keys](https://console.typesafe.ai/keys)) first, in the shell your agent runs in:

```bash
export TYPESAFE_API_KEY=...        # PowerShell: $env:TYPESAFE_API_KEY = "..."
```

### Pi

```bash
pi install git:github.com/harshwasan/jev-sentinel
```

Or try it without installing: `pi -e git:github.com/harshwasan/jev-sentinel`.

Inside pi, `/jev-sentinel` shows the status. `/jev-sentinel reset` clears the "every action needs approval" flag. `/jev-sentinel task`, `clear-task`, and `pin-symbol <s>` manage pinning.

### Claude Code

```
/plugin marketplace add harshwasan/jev-sentinel
/plugin install jev-sentinel@jev-sentinel-marketplace
```

### Codex CLI

```bash
codex plugin marketplace add harshwasan/jev-sentinel
codex plugin add jev-sentinel@jev-sentinel-marketplace
```

Both plugins run the hook straight from the TypeScript source, so they need **Node 22.18 or newer** on your PATH and no build step. Prefer wiring the hooks by hand? Copy [`hooks/claude-settings.example.json`](hooks/claude-settings.example.json) into your Claude Code settings, or [`hooks/codex-hooks.example.json`](hooks/codex-hooks.example.json) to `~/.codex/hooks.json`.

To watch the checks decide before installing anything:

```bash
git clone https://github.com/harshwasan/jev-sentinel && cd jev-sentinel
./hooks/try-hook.ps1            # -Agent codex for the Codex event shape
```

On both hosts the checks are the same, but the wiring differs in three ways ([details](hooks/README.md)): the output check runs *after* the tool instead of before it, "ask" means your host's own approval prompt, and an allowed action returns nothing, so your existing permission rules still apply.

## How a tool call is decided

Jev answers two questions in one request: **intent** (a Choice) and **risk** (a Score). Code checks them in this order, and the first match wins:

1. Risk score ≥ 1.3, or injected ≥ 50% → **warn**, with Block highlighted
2. Risk score ≥ 0.3, or off task ≥ 40% → **ask you**, after first re-checking with more context if Jev says it would help
3. On task ≥ 80%, or clearly safe (risk score < 0.1) with on task as the top answer → **run**
4. Anything else → **ask you**

Two rules in code sit on top of this. An action longer than Jev can read in full (8,000 characters) is never run without asking you. After a flagged output, every action asks you until `/jev-sentinel reset`. That includes an output too long to screen fully, or one whose check failed.

Jev never sees the thresholds, and every decision is logged with its probabilities.

## Settings

Put them in `~/.pi/agent/jev-sentinel.json` (pi) or `~/.jev-sentinel/config.json` (Claude Code and Codex), or point `JEV_SENTINEL_CONFIG` at a file. Keep it outside the project, where the agent can't edit it. `baseUrl` must be `https://`. The most useful ones:

| Setting | Default | |
|---|---|---|
| `screenToolOutputs` | `true` | Check tool outputs for agent instructions |
| `trustedPaths` | `AGENTS.md`, `CLAUDE.md`, `.pi/` | Outputs from these files are never screened. Paths are relative to the project root: `AGENTS.md` means only the root one, `**/AGENTS.md` means any, and `.pi/` means a folder. Nothing outside the project is trusted. |
| `taintOnInjection` | `true` | After an injection is found, every action asks you |
| `screenReplies` | `true` | Check finished replies |
| `checkUnsupportedClaims` / `checkSkippedWork` | `false` | Optional reply checks |
| `pinTasks` / `pinTaskInPrompt` | `false` | Pinning, and restating the pin to the agent every turn |
| `contextRecheckBelow` | `0.3` | Re-check with more context before asking, when Jev says it would help |
| `riskAskScore` / `riskWarnScore` / `allowThreshold` | `0.3` / `1.3` / `0.8` | Decision thresholds |
| `logStates` | `false` | Also log the exact text sent to Jev, so you can verify what leaves your machine |
| `questionMode` | `intent_risk` | `separate` and `combined` are older question setups, kept for comparison |

The full list, with comments, is in [`src/guard.ts`](src/guard.ts) (`GuardConfig`).

## What is sent to TypeSafe

Recent conversation, the tool call, tool outputs, and replies. Nothing from the agent's system prompt is sent. File contents are sent only when Jev asks for them, and only for files inside the project. Anything that looks like a secret file is withheld by name, and its values are scrubbed from everything sent, for the whole session, even after compaction. Values of environment variables whose names contain KEY, TOKEN, SECRET, PASSW, CREDENTIAL, or AUTH are scrubbed too, and so are `NAME=value` lines with such names and `Bearer` tokens, whatever file or command printed them. A secret that fits none of these patterns, such as a bare token in an ordinary file, is not detected. Values shorter than 8 characters are not scrubbed.

## Testing

- **`npm test`:** 106 unit tests with a fake Jev, including the hook run as a real subprocess and both hosts' transcript formats.
- **`npm run live-check`:** scripted scenarios against the real Jev API, in all three question modes.
- **`sandboxes/`:** four practice projects with planted traps (a poisoned README, an injection 1,487 characters into a file, fake `.env` secrets, a login bug to pin). They come with PowerShell scripts to start pi in each, read the decision log, and reset. See [sandboxes/TESTING.md](sandboxes/TESTING.md).

What the real runs showed:

- **Context re-check:** with no conversation, a delete scored 83% on task. After Jev asked for the earlier messages, it scored 97%.
- **Secret scrubbing:** testing found the agent quoting `.env` back in its reply, which leaked the values to Jev. This is fixed and covered by a test.
- **Unsupported claims:** replaying a 16-chunk summary scored 96% with only the last 12 messages, and 45% with the full evidence. The check is off by default because it is less reliable for long context and raised false alarms in chat.

## Limitations

- Jev judges text. It can't fact-check the outside world, and it can't see what a script it hasn't read will do.
- Every tool call, output, and reply is one extra request (about 0.3–1 s each).
- Harmless listing commands are sometimes asked as "off task". A read-only fast path is a likely next step.
- Prompt injection is not solved. This makes it harder and visible. For untrusted code, also use a container.

## License

MIT
