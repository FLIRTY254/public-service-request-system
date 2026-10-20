const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const dataDir = path.join(__dirname, "../data");
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "services.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'citizen'
			CHECK (role IN ('citizen', 'admin')),
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		category TEXT NOT NULL,
		location TEXT NOT NULL,
		description TEXT NOT NULL,
		image_path TEXT,
		status TEXT NOT NULL DEFAULT 'Pending'
			CHECK (status IN ('Pending', 'In Progress', 'Resolved')),
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
`);

module.exports = db;
