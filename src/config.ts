/**
 * Settings loading, shared by every host (pi extension, Claude Code hook, Codex hook).
 *
 * The file is read from outside the project on purpose: a settings file the agent can edit is a
 * settings file an injected instruction can turn off.
 */

import { existsSync, readFileSync } from "node:fs";
import { DEFAULT_CONFIG, type GuardConfig, QUESTION_MODES, type QuestionMode } from "./guard.ts";

const STRING_ARRAY_KEYS = new Set<keyof GuardConfig>(["skipTools", "trustedPaths"]);

/**
 * Reads `path` over the defaults. A bad file is never half-applied: the defaults are used and the
 * caller shows the error, so a typo cannot silently switch a check off.
 */
export function loadConfigFile(path: string, defaults: GuardConfig): { config: GuardConfig; error?: string } {
	if (!existsSync(path)) return { config: defaults };
	try {
		// Strip a UTF-8 byte-order mark (Windows PowerShell 5.1 writes one).
		const text = readFileSync(path, "utf8");
		const raw = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) as Record<string, unknown>;
		if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
			return { config: defaults, error: `${path}: expected a JSON object; using defaults` };
		}
		const config: GuardConfig = { ...defaults };
		for (const key of Object.keys(defaults) as (keyof GuardConfig)[]) {
			if (!(key in raw)) continue;
			const value = raw[key];
			const expected = typeof defaults[key];
			const ok =
				key === "logFile"
					? value === null || typeof value === "string"
					: STRING_ARRAY_KEYS.has(key)
						? Array.isArray(value) && value.every((v) => typeof v === "string")
						: key === "questionMode"
							? QUESTION_MODES.includes(value as QuestionMode)
							: typeof value === expected;
			if (!ok) return { config: defaults, error: `${path}: invalid value for "${key}"; using defaults` };
			(config as unknown as Record<string, unknown>)[key] = value;
		}
		// Every Jev request carries conversation data, so only ever send it over TLS.
		if (!/^https:\/\//i.test(config.baseUrl)) {
			return { config: defaults, error: `${path}: baseUrl must start with https://; using defaults` };
		}
		return { config };
	} catch (err) {
		return { config: defaults, error: `${path}: ${(err as Error).message}; using defaults` };
	}
}

export { DEFAULT_CONFIG };
