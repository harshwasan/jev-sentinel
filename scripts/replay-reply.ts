/**
 * Replays a reply check from a saved pi session, comparing the old context rule (last
 * replyContextMessages messages) with the current one (everything since the user's last
 * message first). Shows what evidence each sent, and with TYPESAFE_API_KEY set, Jev's scores.
 *
 * Usage (from the repo root):
 *   npx tsx scripts/replay-reply.ts <session.jsonl> "<text in the reply>"
 */

import { readFileSync } from "node:fs";
import type { AgentMessage } from "@earendil-works/pi-agent-core";
import {
	contentText,
	createJevRequest,
	DEFAULT_CONFIG,
	describeUserRequest,
	type GuardConfig,
	type JevRequest,
	renderConversation,
	truncate,
} from "../src/guard.ts";
import { REPLY_QUESTIONS, screenReply } from "../src/screens.ts";

const [sessionPath, replyText] = process.argv.slice(2);
if (!sessionPath || !replyText) {
	console.error('Usage: replay-reply.ts <session.jsonl> "<text that appears in the reply>"');
	process.exit(2);
}

const messages: AgentMessage[] = readFileSync(sessionPath, "utf8")
	.split("\n")
	.filter((line) => line.trim())
	.map((line) => JSON.parse(line) as { type?: string; message?: AgentMessage })
	.filter((entry) => entry.type === "message" && entry.message)
	.map((entry) => entry.message as AgentMessage);

const replyIndex = messages.findIndex((m) => m.role === "assistant" && contentText(m.content).includes(replyText));
if (replyIndex < 0) {
	console.error(`No assistant reply containing "${replyText}" in ${sessionPath}`);
	process.exit(2);
}
const reply = messages[replyIndex];
const prior = messages.slice(0, replyIndex);
const replyBody = reply.role === "assistant" ? contentText(reply.content) : "";
const config: GuardConfig = { ...DEFAULT_CONFIG, logFile: null };

/** The rule used before the fix: the last replyContextMessages rendered messages, oldest dropped to fit. */
function oldState(): Record<string, unknown> {
	const base = { user_request: describeUserRequest(prior, undefined), reply: truncate(replyBody, 20_000) };
	let context = renderConversation(prior, config.fullToolOutputChars)
		.slice(-config.replyContextMessages)
		.map((r) => r.entry);
	while (JSON.stringify({ ...base, context }).length > config.maxStateChars && context.length > 0) {
		context = context.slice(1);
	}
	return { ...base, context };
}

/** The current rule, captured by running screenReply with a request that records the state. */
async function newState(): Promise<{ state: Record<string, unknown>; evidenceComplete: boolean }> {
	let captured: Record<string, unknown> = {};
	const capture: JevRequest = async (state) => {
		captured = state;
		return { answers: Object.fromEntries(Object.keys(REPLY_QUESTIONS).map((k) => [k, { noul: 0 }])) };
	};
	const result = await screenReply(replyBody, prior, undefined, config, capture, undefined);
	return { state: captured, evidenceComplete: result?.evidenceComplete ?? true };
}

/** Which tool calls' outputs made it into the context, described by their read ranges. */
function describeEvidence(state: Record<string, unknown>): string {
	const context = (state.context as Record<string, unknown>[]) ?? [];
	const outputs = context.filter((c) => c.from === "tool_output").length;
	const calls = context
		.flatMap((c) => (c.tool_calls as { tool: string; input: string }[] | undefined) ?? [])
		.map((c) => {
			const input = JSON.parse(c.input) as { path?: string; offset?: number; limit?: number; command?: string };
			return input.path ? `${input.path.split(/[\\/]/).pop()}:${input.offset ?? 1}+${input.limit ?? "all"}` : c.tool;
		});
	return `${context.length} messages, ${outputs} tool outputs, ${JSON.stringify(state).length} chars. Calls seen: ${calls.join(", ") || "(none)"}`;
}

const turnStart = prior.map((m) => m.role).lastIndexOf("user");
const turnReads = prior
	.slice(turnStart)
	.flatMap((m) => (m.role === "assistant" ? m.content : []))
	.filter((b) => b.type === "toolCall").length;

console.log(`Reply: ${truncate(replyBody.replace(/\s+/g, " "), 160)}`);
console.log(`The user's last message was followed by ${turnReads} tool calls before this reply.\n`);

const old = oldState();
const current = await newState();
console.log(`OLD rule (last ${config.replyContextMessages} messages): ${describeEvidence(old)}`);
console.log(`NEW rule (current turn first):  ${describeEvidence(current.state)}`);
console.log(`NEW rule evidence complete: ${current.evidenceComplete}\n`);

const apiKey = process.env.TYPESAFE_API_KEY?.trim();
if (!apiKey) {
	console.log("Set TYPESAFE_API_KEY to also send both versions to Jev and compare the scores.");
	process.exit(0);
}
const request = createJevRequest(apiKey, config);
for (const [label, state] of [
	["OLD", old],
	["NEW", current.state],
] as const) {
	const body = (await request(state, REPLY_QUESTIONS, undefined)) as { answers: Record<string, { noul: number }> };
	const scores = Object.entries(body.answers)
		.map(([k, v]) => `${k} ${Math.round(v.noul * 100)}%`)
		.join(", ");
	console.log(`Jev on ${label}: ${scores}`);
}
