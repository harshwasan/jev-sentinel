// This function converts a given text into a URL-friendly slug.
function slugify(text) {
	return text.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

module.exports = { slugify };
