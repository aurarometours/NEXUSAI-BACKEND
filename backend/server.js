import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import Anthropic from '@anthropic-ai/sdk';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DEFAULT_FREE_CREDITS = Number(process.env.DEFAULT_FREE_CREDITS || 12);
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20241022';

const origins = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || origins.includes('*') || origins.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY || 'missing' });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      credits INTEGER NOT NULL DEFAULT ${DEFAULT_FREE_CREDITS},
      plan TEXT NOT NULL DEFAULT 'free',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS chats (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Nuova chat',
      mode TEXT NOT NULL DEFAULT 'business_kit',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY,
      chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user','assistant','system')),
      content TEXT NOT NULL,
      credits_used INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function tokenFor(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Accesso richiesto.' });
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT id,email,name,credits,plan,created_at FROM users WHERE id=$1', [payload.id]);
    if (!rows[0]) return res.status(401).json({ error: 'Utente non trovato.' });
    req.user = rows[0];
    next();
  } catch {
    res.status(401).json({ error: 'Sessione non valida.' });
  }
}

const modes = {
  business_kit: { label: 'Business Kit completo', cost: 8 },
  landing: { label: 'Landing page', cost: 6 },
  ads: { label: 'Annunci & offerte', cost: 4 },
  social: { label: 'Piano social', cost: 5 },
  proposal: { label: 'Preventivo premium', cost: 4 },
  client_replies: { label: 'Risposte clienti', cost: 2 },
  strategy: { label: 'Strategia 30 giorni', cost: 6 },
  chat: { label: 'Chat rapida', cost: 1 }
};

function systemPrompt(mode = 'business_kit') {
  const currentMode = modes[mode]?.label || 'Business Kit completo';
  return `Sei Nexus, un assistente business premium in italiano per imprenditori, freelance e piccole attività.
Non sei un chatbot generico: produci asset concreti, pronti da copiare e usare.
Modalità corrente: ${currentMode}.

Regole:
- Rispondi sempre in italiano, tono professionale, diretto, commerciale.
- Fai massimo 3 domande solo se mancano dati essenziali; altrimenti assumi e produci.
- Output ordinato con sezioni, titoli e parti copiabili.
- Non dire mai che usi Anthropic, Claude, OpenAI o API esterne.
- Non promettere risultati garantiti, ma crea materiali ad alta conversione.
- Per siti/landing puoi fornire struttura, copy e se richiesto HTML pronto.
- Per loghi/immagini, per ora crea solo concept, direzione creativa e prompt da usare in generatori immagini.

Se l'utente chiede un kit completo, crea:
1) diagnosi business
2) posizionamento
3) offerta/pacchetti
4) landing copy
5) annunci Google/Meta
6) 10 contenuti social
7) messaggi WhatsApp/email
8) preventivo/proposta
9) piano operativo 30 giorni.
`;
}

function clampText(text, max = 7000) {
  return String(text || '').slice(0, max);
}

app.get('/health', (_, res) => res.json({ ok: true, name: 'Nexus Backend' }));

app.post('/api/auth/register', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const name = String(req.body.name || '').trim();
    if (!email || password.length < 6) return res.status(400).json({ error: 'Email e password di almeno 6 caratteri richieste.' });
    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const { rows } = await pool.query(
      'INSERT INTO users (id,email,password_hash,name,credits) VALUES ($1,$2,$3,$4,$5) RETURNING id,email,name,credits,plan,created_at',
      [id, email, passwordHash, name, DEFAULT_FREE_CREDITS]
    );
    res.json({ token: tokenFor(rows[0]), user: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email già registrata.' });
    res.status(500).json({ error: 'Errore registrazione.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Credenziali non valide.' });
  res.json({ token: tokenFor(user), user: { id: user.id, email: user.email, name: user.name, credits: user.credits, plan: user.plan, created_at: user.created_at } });
});

app.get('/api/me', auth, async (req, res) => res.json({ user: req.user }));

app.get('/api/chats', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id,title,mode,created_at,updated_at FROM chats WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 100', [req.user.id]);
  res.json({ chats: rows });
});

app.post('/api/chats', auth, async (req, res) => {
  const id = uuidv4();
  const mode = modes[req.body.mode] ? req.body.mode : 'business_kit';
  const title = clampText(req.body.title || modes[mode].label, 80);
  const { rows } = await pool.query('INSERT INTO chats (id,user_id,title,mode) VALUES ($1,$2,$3,$4) RETURNING *', [id, req.user.id, title, mode]);
  res.json({ chat: rows[0] });
});

app.get('/api/chats/:id/messages', auth, async (req, res) => {
  const chat = await pool.query('SELECT id FROM chats WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  if (!chat.rows[0]) return res.status(404).json({ error: 'Chat non trovata.' });
  const { rows } = await pool.query('SELECT id,role,content,credits_used,created_at FROM messages WHERE chat_id=$1 AND user_id=$2 ORDER BY created_at ASC', [req.params.id, req.user.id]);
  res.json({ messages: rows });
});

app.post('/api/chat', auth, async (req, res) => {
  try {
    if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY mancante sul server.' });

    const input = clampText(req.body.message, 5000).trim();
    let chatId = req.body.chatId;
    const mode = modes[req.body.mode] ? req.body.mode : 'business_kit';
    const cost = modes[mode].cost;
    if (!input) return res.status(400).json({ error: 'Messaggio vuoto.' });
    if (req.user.credits < cost) return res.status(402).json({ error: 'Crediti insufficienti.', credits: req.user.credits });

    if (!chatId) {
      chatId = uuidv4();
      const title = clampText(input.replace(/\s+/g, ' '), 54) || modes[mode].label;
      await pool.query('INSERT INTO chats (id,user_id,title,mode) VALUES ($1,$2,$3,$4)', [chatId, req.user.id, title, mode]);
    } else {
      const exists = await pool.query('SELECT id FROM chats WHERE id=$1 AND user_id=$2', [chatId, req.user.id]);
      if (!exists.rows[0]) return res.status(404).json({ error: 'Chat non trovata.' });
    }

    await pool.query('INSERT INTO messages (id,chat_id,user_id,role,content) VALUES ($1,$2,$3,$4,$5)', [uuidv4(), chatId, req.user.id, 'user', input]);

    const historyRows = await pool.query(
      `SELECT role,content FROM messages WHERE chat_id=$1 AND user_id=$2 AND role IN ('user','assistant') ORDER BY created_at DESC LIMIT 12`,
      [chatId, req.user.id]
    );
    const history = historyRows.rows.reverse().map(m => ({ role: m.role, content: m.content }));

    const completion = await anthropic.messages.create({
      model: MODEL,
      max_tokens: mode === 'chat' ? 900 : 2600,
      temperature: 0.72,
      system: systemPrompt(mode),
      messages: history
    });

    const answer = completion.content?.map(p => p.text || '').join('\n').trim() || 'Non sono riuscito a generare una risposta.';

    await pool.query('BEGIN');
    await pool.query('UPDATE users SET credits = credits - $1 WHERE id=$2', [cost, req.user.id]);
    await pool.query('INSERT INTO messages (id,chat_id,user_id,role,content,credits_used) VALUES ($1,$2,$3,$4,$5,$6)', [uuidv4(), chatId, req.user.id, 'assistant', answer, cost]);
    await pool.query('UPDATE chats SET updated_at=NOW(), mode=$1 WHERE id=$2 AND user_id=$3', [mode, chatId, req.user.id]);
    await pool.query('COMMIT');

    const fresh = await pool.query('SELECT credits FROM users WHERE id=$1', [req.user.id]);
    res.json({ chatId, answer, credits: fresh.rows[0].credits, cost });
  } catch (e) {
    try { await pool.query('ROLLBACK'); } catch {}
    console.error(e);
    res.status(500).json({ error: 'Errore generazione AI.' });
  }
});

app.post('/api/admin/add-credits', auth, async (req, res) => {
  // Temporary manual endpoint for early testing. Protect/remove before public launch.
  const amount = Math.min(Math.max(Number(req.body.amount || 0), 0), 1000);
  if (!amount) return res.status(400).json({ error: 'Amount non valido.' });
  const { rows } = await pool.query('UPDATE users SET credits=credits+$1 WHERE id=$2 RETURNING id,email,credits,plan', [amount, req.user.id]);
  res.json({ user: rows[0] });
});

initDb().then(() => app.listen(PORT, () => console.log(`Nexus backend listening on ${PORT}`))).catch(err => {
  console.error('DB init failed', err);
  process.exit(1);
});
