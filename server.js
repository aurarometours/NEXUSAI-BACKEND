import express from "express";
import cors from "cors";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import dotenv from "dotenv";
import Anthropic from "@anthropic-ai/sdk";

dotenv.config();

const app = express();
const { Pool } = pg;

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || "claude-3-5-haiku-latest";

if (!DATABASE_URL) throw new Error("DATABASE_URL missing");
if (!JWT_SECRET) throw new Error("JWT_SECRET missing");
if (!ANTHROPIC_API_KEY) throw new Error("ANTHROPIC_API_KEY missing");

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(morgan("tiny"));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

/* ================= DB INIT ================= */

async function initDb() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      credits INT DEFAULT 60
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID,
      title TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      conversation_id UUID,
      role TEXT,
      content TEXT,
      artifact JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  console.log("✅ DB ready");
}

/* ================= AUTH ================= */

function sign(user) {
  return jwt.sign(user, JWT_SECRET, { expiresIn: "30d" });
}

async function auth(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
}

/* ================= ROUTES ================= */

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

/* REGISTER */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users(name,email,password)
       VALUES($1,$2,$3)
       RETURNING id,name,email,credits`,
      [name, email, hash]
    );

    res.json({ user: rows[0] });
  } catch (e) {
    res.status(400).json({ message: "Errore registrazione" });
  }
});

/* LOGIN */
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const { rows } = await pool.query(
    `SELECT * FROM users WHERE email=$1`,
    [email]
  );

  if (!rows[0]) return res.status(401).json({ message: "Credenziali errate" });

  const ok = await bcrypt.compare(password, rows[0].password);
  if (!ok) return res.status(401).json({ message: "Credenziali errate" });

  const token = sign({
    id: rows[0].id,
    email: rows[0].email
  });

  res.json({
    token,
    user: {
      id: rows[0].id,
      email: rows[0].email,
      credits: rows[0].credits
    }
  });
});

/* ME */
app.get("/api/me", auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,email,credits FROM users WHERE id=$1`,
    [req.user.id]
  );
  res.json({ user: rows[0] });
});

/* CONVERSATIONS */
app.get("/api/conversations", auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM conversations WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.user.id]
  );
  res.json({ conversations: rows });
});

app.post("/api/conversations", auth, async (req, res) => {
  const { title } = req.body;

  const { rows } = await pool.query(
    `INSERT INTO conversations(user_id,title)
     VALUES($1,$2)
     RETURNING *`,
    [req.user.id, title]
  );

  res.json({ conversation: rows[0] });
});

/* ================= CHAT ================= */

function detectHTML(text) {
  return text.includes("<html");
}

app.post("/api/chat", auth, async (req, res) => {
  try {
    const { message, conversationId } = req.body;

    const completion = await anthropic.messages.create({
      model: ANTHROPIC_MODEL,
      max_tokens: 2000,
      messages: [
        {
          role: "user",
          content: `Sei Nexus, AI business premium. Rispondi in modo professionale e operativo.\n\n${message}`
        }
      ]
    });

    let reply = completion.content[0].text;

    let artifact = null;

    if (detectHTML(reply)) {
      artifact = {
        filename: "nexus-landing.html",
        mime: "text/html",
        content: reply
      };

      reply = "Ho creato la landing completa. Scaricala qui sotto.";
    }

    await pool.query(
      `INSERT INTO messages(conversation_id,role,content,artifact)
       VALUES($1,$2,$3,$4)`,
      [conversationId, "assistant", reply, artifact]
    );

    res.json({ reply, artifact });
  } catch (e) {
    console.log(e);
    res.status(500).json({
      message: "Nexus non è riuscito a generare la risposta."
    });
  }
});

/* ================= START ================= */

initDb().then(() => {
  app.listen(PORT, () => {
    console.log("🚀 Nexus backend live");
  });
});
