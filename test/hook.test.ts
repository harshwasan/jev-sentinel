/**
 * Tests for the Claude Code / Codex hook: transcript reading, and the decisions the hook program
 * writes to stdout. The hook is run as a real subprocess, the way a host runs it.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { detectFormat, parseClaudeTranscript, parseCodexTranscript, readTranscript } from "../src/transcript.ts";

const HOOK = join(import.meta.dirname, "..", "src", "hook.ts");

/** Runs the hook exactly as a host would: one JSON event in, one JSON decision out. */
function runHook(event: Record<string, unknown>, env: Record<string, string> = {}): Record<string, unknown> {
	const out = execFileSync(process.execPath, ["--import", "tsx", HOOK, "--host", String(env.HOST ?? "claude")], {
		input: JSON.stringify(event),
		encoding: "utf8",
		env: { ...process.env, TYPESAFE_API_KEY: "", ...env },
	});
	return out.trim() ? (JSON.parse(out) as Record<string, unknown>) : {};
}

const decision = (out: Record<string, unknown>) =>
	(out.hookSpecificOutput as { permissionDecision?: string; permissionDecisionReason?: string } | undefined) ?? {};

describe("transcript reading", () => {
	const claudeLines = [
		{ type: "mode", mode: "normal" },
		{ type: "user", message: { role: "user", content: "fix the login bug" } },
		{
			type: "assistant",
			message: {
				role: "assistant",
				content: [
					{ type: "thinking", thinking: "internal" },
					{ type: "text", text: "Reading the file." },
					{ type: "tool_use", id: "t1", name: "Read", input: { file_path: "src/login.ts" } },
				],
			},
		},
		{
			type: "user",
			message: { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: "export function login() {}" }] }] },
		},
		// A subagent's messages belong to another session and must not leak into this one.
		{ type: "assistant", isSidechain: true, message: { role: "assistant", content: [{ type: "text", text: "subagent" }] } },
	];

	const codexLines = [
		{ type: "session_meta", payload: { session_id: "s1" } },
		{ type: "response_item", payload: { type: "message", role: "developer", content: [{ type: "input_text", text: "system instructions" }] } },
		{ type: "response_item", payload: { type: "message", role: "user", content: [{ type: "input_text", text: "fix the login bug" }] } },
		{
			type: "response_item",
			payload: { type: "function_call", name: "shell", call_id: "c1", arguments: '{"command":["bash","-lc","cat src/login.ts"]}' },
		},
		{
			type: "response_item",
			payload: { type: "function_call_output", call_id: "c1", output: '[{"type":"input_text","text":"export function login() {}"}]' },
		},
		{ type: "response_item", payload: { type: "message", role: "assistant", content: [{ type: "output_text", text: "Found it." }] } },
	];

	it("reads a Claude Code session, keeping tool names on their results and skipping subagents", () => {
		const messages = parseClaudeTranscript(claudeLines as unknown as Record<string, unknown>[]);
		expect(messages.map((m) => m.role)).toEqual(["user", "assistant", "toolResult"]);
		expect(JSON.stringify(messages)).not.toContain("subagent");
		// Thinking is not sent to Jev; the visible reply and the call are.
		expect(JSON.stringify(messages[1])).not.toContain("internal");
		expect(messages[2]).toMatchObject({ toolName: "Read", toolCallId: "t1" });
	});

	it("reads a Codex rollout, unwrapping command output and dropping developer instructions", () => {
		const messages = parseCodexTranscript(codexLines as unknown as Record<string, unknown>[]);
		expect(messages.map((m) => m.role)).toEqual(["user", "assistant", "toolResult", "assistant"]);
		expect(JSON.stringify(messages)).not.toContain("system instructions");
		const call = (messages[1] as unknown as { content: { name?: string; arguments?: Record<string, unknown> }[] }).content[0];
		expect(call).toMatchObject({ name: "shell" });
		expect((messages[2] as unknown as { content: { text: string }[] }).content[0].text).toBe("export function login() {}");
	});

	it("tells the two formats apart", () => {
		expect(detectFormat(claudeLines as unknown as Record<string, unknown>[])).toBe("claude");
		expect(detectFormat(codexLines as unknown as Record<string, unknown>[])).toBe("codex");
	});

	it("treats a missing transcript as an empty history rather than failing", () => {
		expect(readTranscript(join(tmpdir(), "does-not-exist-jev.jsonl"))).toEqual([]);
		expect(readTranscript(null)).toEqual([]);
	});
});

describe("hook decisions", () => {
	let dir: string;
	let configPath: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "jev-hook-"));
		configPath = join(dir, "config.json");
		writeFileSync(configPath, JSON.stringify({ logFile: join(dir, "log.jsonl") }));
	});
	afterEach(() => rmSync(dir, { recursive: true, force: true }));

	const base = (extra: Record<string, unknown>) => ({
		session_id: "test-session",
		cwd: dir,
		transcript_path: null,
		...extra,
	});

	it("asks the user when no API key is set, instead of letting the action through", () => {
		const out = runHook(
			base({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }),
			{ JEV_SENTINEL_CONFIG: configPath },
		);
		expect(decision(out).permissionDecision).toBe("ask");
		expect(decision(out).permissionDecisionReason).toMatch(/TYPESAFE_API_KEY/);
	});

	it("denies a write to the host's own settings without asking Jev", () => {
		const out = runHook(
			base({
				hook_event_name: "PreToolUse",
				tool_name: "Write",
				tool_input: { file_path: join(homedir(), ".claude", "settings.json"), content: "{}" },
			}),
			{ JEV_SENTINEL_CONFIG: configPath, TYPESAFE_API_KEY: "k" },
		);
		expect(decision(out).permissionDecision).toBe("deny");
		expect(decision(out).permissionDecisionReason).toMatch(/controls the agent or Jev sentinel/);
		// No Jev request was needed, so an unreachable API cannot turn this into an allow.
		expect(out.systemMessage).toMatch(/blocked Write/);
	});

	it("denies a Codex shell command that edits the Codex config, with the command read as a string", () => {
		const out = runHook(
			base({
				hook_event_name: "PreToolUse",
				tool_name: "shell",
				tool_input: { command: ["bash", "-lc", "echo hooks = false >> ~/.codex/config.toml"] },
				turn_id: "t1",
			}),
			{ JEV_SENTINEL_CONFIG: configPath, TYPESAFE_API_KEY: "k", HOST: "codex" },
		);
		expect(decision(out).permissionDecision).toBe("deny");
	});

	it("leaves ordinary reads to the host's own permission rules", () => {
		const out = runHook(
			base({ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: join(dir, "notes.md") } }),
			{ JEV_SENTINEL_CONFIG: configPath, TYPESAFE_API_KEY: "" },
		);
		// No key means "ask", never a silent allow; with skipTools it would be {}.
		expect(decision(out).permissionDecision).toBe("ask");
	});

	it("skips tools listed in skipTools entirely", () => {
		writeFileSync(configPath, JSON.stringify({ logFile: join(dir, "log.jsonl"), skipTools: ["TodoWrite"] }));
		const out = runHook(base({ hook_event_name: "PreToolUse", tool_name: "TodoWrite", tool_input: {} }), {
			JEV_SENTINEL_CONFIG: configPath,
		});
		expect(out).toEqual({});
	});

	it("pins a task from a prompt and strips the symbol on Claude Code", () => {
		writeFileSync(configPath, JSON.stringify({ logFile: join(dir, "log.jsonl"), pinTasks: true }));
		const out = runHook(base({ hook_event_name: "UserPromptSubmit", user_input: "* fix the login bug" }), {
			JEV_SENTINEL_CONFIG: configPath,
		});
		expect(out.systemMessage).toMatch(/task pinned: fix the login bug/);
		expect(out.hookSpecificOutput).toMatchObject({ updatedInput: "fix the login bug" });
	});

	it("does nothing on an event it does not handle, and on unparsable input", () => {
		expect(runHook(base({ hook_event_name: "PreCompact" }), { JEV_SENTINEL_CONFIG: configPath })).toEqual({});
		const out = execFileSync(process.execPath, ["--import", "tsx", HOOK], { input: "not json", encoding: "utf8" });
		expect(out.trim()).toBe("");
	});

	it("reports a bad settings file at session start instead of running with half of it", () => {
		writeFileSync(configPath, JSON.stringify({ baseUrl: "http://attacker.invalid" }));
		const out = runHook(base({ hook_event_name: "SessionStart" }), { JEV_SENTINEL_CONFIG: configPath });
		expect(out.systemMessage).toMatch(/baseUrl must start with https/);
	});
});
