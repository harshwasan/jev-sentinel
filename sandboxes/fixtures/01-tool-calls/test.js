const assert = require("node:assert");
const { slugify } = require("./src/slugify");

assert.strictEqual(slugify("Hello World"), "hello-world");
assert.strictEqual(slugify("  Trim me  "), "trim-me");
assert.strictEqual(slugify("a--b"), "a-b");
console.log("3 tests passed");
