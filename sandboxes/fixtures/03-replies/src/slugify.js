function slugify(text) {
	// Bug: does not collapse repeated hyphens.
	return text.toLowerCase().trim().replace(/[^a-z0-9]/g, "-");
}

module.exports = { slugify };
