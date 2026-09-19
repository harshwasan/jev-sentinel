/**
 * Reading a host's transcript file into the message shape the core checks use.
 *
 * The pi extension gets the conversation from pi itself. Claude Code and Codex hand a hook only a
 * path to the session file, so the same history has to be recovered from disk:
 *
 * - Claude Code writes one JSON object per line: `{type:"user"|"assistant", message:{role, content}}`,
 *   where content is a string or a list of text / tool_use / tool_result blocks.
 * - Codex writes rollout lines: `{type:"response_item", payload:{…}}` in Responses API shape
 *   (message, function_call, function_call_output, custom_tool_call, custom_tool_call_output).
 *
 * Both are read as data, never trusted: everything here ends up inside a Jev question, not executed.
 */

import { closeSync, openSync, readSync, statSync } from "node:fs";
import type { AgentMessage } from "@earendil-works/pi-agent-core";

export type TranscriptFormat = "claude" | "codex";

/** Transcripts grow without bound; only the tail is read, since the checks use recent messages. */
const MAX_TRANSCRIPT_BYTES = 4_000_000;

/** Reads the last MAX_TRANSCRIPT_BYTES of a file, dropping a partial first line. */
function readTail(path: string): string[] {
	const size = statSync(path).size;
	const from = Math.max(0, size - MAX_TRANSCRIPT_BYTES);
	const length = size - from;
	const buffer = Buffer.alloc(length);
	const fd = openSync(path, "r");
	try {
		readSync(fd, buffer, 0, length, from);
	} finally {
		closeSync(fd);
	}
	const lines = buffer.toString("utf8").split("\n");
	return from > 0 ? lines.slice(1) : lines;
}

function jsonLines(text: string[]): Record<string, unknown>[] {
	const out: Record<string, unknown>[] = [];
	for (const line of text) {
		const trimmed = line.trim();
		if (!trimmed.startsWith("{")) continue;
		try {
			out.push(JSON.parse(trimmed) as Record<string, unknown>);
		} catch {
			// A half-written last line is normal while the host is still running.
		}
	}
	return out;
}

export function detectFormat(entries: Record<string, unknown>[]): TranscriptFormat {
	for (const entry of entries) {
		if (entry.type === "response_item" || entry.type === "session_meta" || entry.type === "turn_context") {
			return "codex";
		}
		if (entry.type === "user" || entry.type === "assistant" || entry.type === "file-history-snapshot") {
			return "claude";
		}
	}
	return "claude";
}

const text = (value: unknown): string => (typeof value === "string" ? value : "");

function assistantMessage(parts: { type: string; text?: string }[], toolCalls: unknown[]): AgentMessage | undefined {
	const content = [...parts.filter((p) => p.text), ...toolCalls];
	if (content.length === 0) return undefined;
	return { role: "assistant", content, timestamp: 0 } as unknown as AgentMessage;
}

/** Claude Code session JSONL → messages. Sidechain (subagent) entries belong to another session. */
export function parseClaudeTranscript(entries: Record<string, unknown>[]): AgentMessage[] {
	const messages: AgentMessage[] = [];
	// tool_result blocks name the call, not the tool, so the tool name is remembered from the call.
	const toolNames = new Map<string, string>();
	for (const entry of entries) {
		if (entry.isSidechain === true) continue;
		const message = entry.message as { role?: string; content?: unknown } | undefined;
		if (!message || (entry.type !== "user" && entry.type !== "assistant")) continue;

		if (typeof message.content === "string") {
			if (entry.type === "user") messages.push({ role: "user", content: message.content, timestamp: 0 } as AgentMessage);
			continue;
		}
		if (!Array.isArray(message.content)) continue;
		const blocks = message.content as Record<string, unknown>[];

		if (entry.type === "user") {
			const said = blocks.filter((b) => b.type === "text").map((b) => text(b.text));
			if (said.length > 0) {
				messages.push({ role: "user", content: said.join("\n"), timestamp: 0 } as AgentMessage);
			}
			for (const block of blocks) {
				if (block.type !== "tool_result") continue;
				const id = text(block.tool_use_id);
				messages.push({
					role: "toolResult",
					toolCallId: id,
					toolName: toolNames.get(id) ?? "unknown",
					content: [{ type: "text", text: contentToText(block.content) }],
					isError: block.is_error === true,
					timestamp: 0,
				} as unknown as AgentMessage);
			}
			continue;
		}

		const parts = blocks
			.filter((b) => b.type === "text")
			.map((b) => ({ type: "text", text: text(b.text) }) as { type: string; text?: string });
		const calls = blocks
			.filter((b) => b.type === "tool_use")
			.map((b) => {
				const id = text(b.id);
				const name = text(b.name);
				toolNames.set(id, name);
				return { type: "toolCall", id, name, arguments: (b.input ?? {}) as Record<string, unknown> };
			});
		const assistant = assistantMessage(parts, calls);
		if (assistant) messages.push(assistant);
	}
	return messages;
}

/** A Claude tool_result's content is a string or a list of blocks. */
function contentToText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((block) => {
			const b = block as Record<string, unknown>;
			if (b.type === "text") return text(b.text);
			return `[${text(b.type) || "content"}]`;
		})
		.join("\n");
}

/**
 * Some Codex tools store their output as a JSON-encoded list of content parts
 * (`[{"type":"input_text","text":"…"}]`). Jev should see the text, not the encoding.
 */
function unwrapCodexOutput(output: string): string {
	if (!output.startsWith("[")) return output;
	try {
		const parsed = JSON.parse(output) as unknown;
		if (!Array.isArray(parsed)) return output;
		const parts = parsed.map((part) => text((part as Record<string, unknown>)?.text)).filter(Boolean);
		return parts.length > 0 ? parts.join("\n") : output;
	} catch {
		return output;
	}
}

/** Codex rollout JSONL → messages. */
export function parseCodexTranscript(entries: Record<string, unknown>[]): AgentMessage[] {
	const messages: AgentMessage[] = [];
	const toolNames = new Map<string, string>();
	for (const entry of entries) {
		if (entry.type !== "response_item") continue;
		const payload = entry.payload as Record<string, unknown> | undefined;
		if (!payload) continue;

		switch (payload.type) {
			case "message": {
				// "developer" and "system" carry the host's own instructions, which are never sent to Jev.
				const role = payload.role;
				if (role !== "user" && role !== "assistant") break;
				const said = Array.isArray(payload.content)
					? (payload.content as Record<string, unknown>[]).map((part) => text(part.text)).join("\n")
					: text(payload.content);
				if (!said.trim()) break;
				if (role === "user") messages.push({ role: "user", content: said, timestamp: 0 } as AgentMessage);
				else messages.push(assistantMessage([{ type: "text", text: said }], []) as AgentMessage);
				break;
			}
			case "function_call":
			case "custom_tool_call": {
				const id = text(payload.call_id) || text(payload.id);
				const name = text(payload.name);
				toolNames.set(id, name);
				let args: Record<string, unknown> = {};
				if (payload.type === "function_call") {
					try {
						const parsed = JSON.parse(text(payload.arguments) || "{}") as unknown;
						if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
							args = parsed as Record<string, unknown>;
						}
					} catch {
						args = { arguments: text(payload.arguments) };
					}
				} else {
					args = { input: text(payload.input) };
				}
				messages.push(
					assistantMessage([], [{ type: "toolCall", id, name, arguments: args }]) as AgentMessage,
				);
				break;
			}
			case "function_call_output":
			case "custom_tool_call_output": {
				const id = text(payload.call_id);
				const output = payload.output;
				const body =
					typeof output === "string"
						? unwrapCodexOutput(output)
						: text((output as Record<string, unknown> | undefined)?.output) || JSON.stringify(output ?? "");
				messages.push({
					role: "toolResult",
					toolCallId: id,
					toolName: toolNames.get(id) ?? "unknown",
					content: [{ type: "text", text: body }],
					isError: false,
					timestamp: 0,
				} as unknown as AgentMessage);
				break;
			}
			default:
				break;
		}
	}
	return messages;
}

/**
 * Reads a host transcript. A missing or unreadable file gives an empty history: the checks then run
 * on the action alone, which is stricter, not looser.
 */
export function readTranscript(path: string | null | undefined, format?: TranscriptFormat): AgentMessage[] {
	if (!path) return [];
	let entries: Record<string, unknown>[];
	try {
		entries = jsonLines(readTail(path));
	} catch {
		return [];
	}
	const kind = format ?? detectFormat(entries);
	return kind === "codex" ? parseCodexTranscript(entries) : parseClaudeTranscript(entries);
}
