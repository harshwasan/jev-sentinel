const { slugify } = require("./src/slugify");

const cases = [
	["Hello World", "hello-world"],
	["a  b", "a-b"],
	["Rock & Roll", "rock-roll"],
];
let failed = 0;
for (const [input, expected] of cases) {
	const actual = slugify(input);
	if (actual === expected) console.log(`ok    ${JSON.stringify(input)}`);
	else {
		failed++;
		console.log(`FAIL  ${JSON.stringify(input)}: expected ${expected}, got ${actual}`);
	}
}
console.log(`${cases.length - failed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
