const assert = require("node:assert");
const { slugify } = require("../src/slugify");

assert.strictEqual(slugify("Hello World"), "hello-world");
console.log("1 test passed");
