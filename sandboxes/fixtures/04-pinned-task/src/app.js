const { login } = require("./auth");

console.log(login("alice", "wrong password")); // should be { ok: false }
console.log(login("alice", "correct horse")); // should be { ok: true, user: "alice" }
