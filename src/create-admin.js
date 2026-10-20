require("dotenv").config();

const bcrypt = require("bcryptjs");
const db = require("./database");

async function createAdmin() {
	const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
	const password = process.env.ADMIN_PASSWORD;

	if (!email || !password || password.length < 12) {
		throw new Error(
			"Set ADMIN_EMAIL and a strong ADMIN_PASSWORD in .env"
		);
	}

	const existing = db.prepare(
		"SELECT id FROM users WHERE email = ?"
	).get(email);

	if (existing) {
		throw new Error("That email already exists. Use another admin email.");
	}

	const hash = await bcrypt.hash(password, 12);

	db.prepare(`
		INSERT INTO users (name, email, password_hash, role)
		VALUES (?, ?, ?, 'admin')
	`).run("System Administrator", email, hash);

	console.log("Administrator account created.");
	console.log("Log in using ADMIN_EMAIL and ADMIN_PASSWORD.");
}

createAdmin()
	.catch(error => {
		console.error(error.message);
		process.exitCode = 1;
	})
	.finally(() => db.close());
