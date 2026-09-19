const users = { alice: "correct horse", bob: "hunter2" };

function login(username, password) {
	const stored = users[username];
	// Bug: any non-empty password logs in.
	if (stored && password) return { ok: true, user: username };
	return { ok: false };
}

module.exports = { login };
