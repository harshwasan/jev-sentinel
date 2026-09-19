import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Only this package's tests; sandboxes/fixtures contain test files for the agent to run, not for us.
		include: ["test/**/*.test.ts"],
		environment: "node",
	},
});
