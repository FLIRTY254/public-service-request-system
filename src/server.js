require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set a SESSION_SECRET of at least 32 characters.");
}

const uploadDir = path.join(__dirname, "../uploads");
fs.mkdirSync(uploadDir, { recursive: true });

app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: "service.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 2
  }
}));

// Serve static assets (HTML, CSS, JS) from src/public
app.use(express.static(path.join(__dirname, "public")));

// Explicitly serve index.html on the root route '/'
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    cb(null, crypto.randomUUID() +
      path.extname(file.originalname).toLowerCase());
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    cb(null, allowed.includes(file.mimetype));
  }
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please log in." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Administrator access required." });
  }
  next();
}

const categories = [
  "Broken Streetlight",
  "Water Issue",
  "Garbage Collection",
  "Road Damage",
  "Drainage",
  "Other"
];

const statuses = ["Pending", "In Progress", "Resolved"];

// Registration
app.post("/api/register", async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (typeof name !== "string" || name.trim().length < 2 ||
        name.trim().length > 100 ||
        typeof email !== "string" ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        typeof password !== "string" ||
        password.length < 10 || password.length > 72) {
      return res.status(400).json({
        error: "Enter a valid name, email and password (10–72 characters)."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(name.trim(), email.trim().toLowerCase(), hash);

    res.status(201).json({
      message: "Registration successful.",
      userId: result.lastInsertRowid
    });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Email already registered." });
    }
    next(err);
  }
});

// Login
app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (typeof email !== "string" ||
        typeof password !== "string") {
      return res.status(400).json({ error: "Email and password required." });
    }

    const user = db.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).get(email.trim().toLowerCase());

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    req.session.regenerate(err => {
      if (err) return next(err);

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      res.json({ user: req.session.user });
    });
  } catch (err) {
    next(err);
  }
});

// Current logged-in user
app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// Logout
app.post("/api/logout", requireLogin, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("service.sid");
    res.json({ message: "Logged out." });
  });
});

// Submit a service request
app.post("/api/requests", requireLogin, (req, res, next) => {
  upload.single("image")(req, res, err => {
    if (err) {
      return res.status(400).json({
        error: "Image upload failed. Use JPEG, PNG or WebP up to 2 MB."
      });
    }

    try {
      const { category, location, description } = req.body;

      if (!categories.includes(category) ||
          typeof location !== "string" ||
          location.trim().length < 3 ||
          location.length > 200 ||
          typeof description !== "string" ||
          description.trim().length < 10 ||
          description.length > 2000) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({
          error: "Check the category, location and description."
        });
      }

      const result = db.prepare(`
        INSERT INTO requests
          (user_id, category, location, description, image_path)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        req.session.user.id,
        category,
        location.trim(),
        description.trim(),
        req.file ? req.file.filename : null
      );

      res.status(201).json({
        message: "Request submitted successfully.",
        id: result.lastInsertRowid,
        status: "Pending"
      });
    } catch (error) {
      next(error);
    }
  });
});

// Citizens see their own requests; admins can see all.
app.get("/api/requests", requireLogin, (req, res) => {
  const requests = req.session.user.role === "admin"
    ? db.prepare(`
        SELECT r.*, u.name AS citizen_name, u.email AS citizen_email
        FROM requests r JOIN users u ON u.id = r.user_id
        ORDER BY r.created_at DESC
      `).all()
    : db.prepare(`
        SELECT * FROM requests
        WHERE user_id = ?
        ORDER BY created_at DESC
      `).all(req.session.user.id);

  res.json({ requests });
});

// Serve uploaded images only to authenticated users.
app.get("/api/images/:filename", requireLogin, (req, res) => {
  const filename = req.params.filename;

  if (!/^[0-9a-f-]{36}\.(jpg|jpeg|png|webp)$/i.test(filename)) {
    return res.sendStatus(404);
  }

  const record = db.prepare(
    "SELECT user_id FROM requests WHERE image_path = ?"
  ).get(filename);

  if (!record ||
      (req.session.user.role !== "admin" &&
       record.user_id !== req.session.user.id)) {
    return res.sendStatus(404);
  }

  res.sendFile(path.join(uploadDir, filename));
});

// Admin analytics
app.get("/api/admin/analytics", requireAdmin, (req, res) => {
  const counts = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN status != 'Resolved' THEN 1 ELSE 0 END) AS open,
      SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS inProgress,
      SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) AS resolved
    FROM requests
  `).get();

  res.json({
    total: counts.total,
    open: counts.open || 0,
    pending: counts.pending || 0,
    inProgress: counts.inProgress || 0,
    resolved: counts.resolved || 0
  });
});

// Admin changes a request status
app.patch("/api/admin/requests/:id/status", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body;

  if (!Number.isSafeInteger(id) || id < 1 ||
      !statuses.includes(status)) {
    return res.status(400).json({ error: "Invalid request or status." });
  }

  const result = db.prepare(`
    UPDATE requests
    SET status = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(status, id);

  if (!result.changes) {
    return res.status(404).json({ error: "Request not found." });
  }

  res.json({ message: "Status updated.", status });
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

app.listen(PORT, () => {
  console.log(`Public Service Request System running on http://localhost:${PORT}`);
});