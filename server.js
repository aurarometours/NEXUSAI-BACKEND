import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';

const { Pool } = pg;

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20241022';
const DEFAULT_FREE_CREDITS = Number(process.env.DEFAULT_FREE_CREDITS || 20);
const CHAT_CREDIT_COST = Number(process.env.CHAT_CREDIT_COST || 1);

function requireEnv(name, value) {
  if (!value || String(value).trim() === '') {
    throw new Error(`${name} is missing. Add it in Railway service Variables.`);
  }
}

requireEnv('DATABASE_URL', DATABASE_URL);
requireEnv('JWT_SECRET', JWT_SECRET);
requireEnv('ANTHROPIC_API_KEY', ANTHROPIC_API_KEY);

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Railway Postgres normalmente funziona così in produzione.
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

const anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));

const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`));
  },
  credentials: true,
}));

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        credits INTEGER NOT NULL DEFAULT ${DEFAULT_FREE_CREDITS},
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL DEFAULT 'Nuova chat',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('user','assistant','system')),
        content TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS credit_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at ASC);`);
    await client.query('COMMIT');
    console.log('✅ Database initialized');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT id, email, name, credits, created_at FROM users WHERE id=$1', [payload.id]);
    if (!rows[0]) return res.status(401).json({ error: 'User not found' });
    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

const registerSchema = z.object({
  email: z.string().email().max(200),
  password: z.string().min(6).max(200),
  name: z.string().max(100).optional().default(''),
});

const loginSchema = z.object({
  email: z.string().email().max(200),
  password: z.string().min(1).max(200),
});

const chatSchema = z.object({
  conversationId: z.string().uuid().optional().nullable(),
  message: z.string().min(1).max(6000),
  mode: z.enum(['business-kit', 'landing', 'ads', 'social', 'offer', 'strategy', 'general']).optional().default('business-kit'),
});

app.get('/', (req, res) => {
  res.json({ ok: true, app: 'Nexus API', status: 'online' });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, db: 'connected', anthropic: Boolean(ANTHROPIC_API_KEY), model: ANTHROPIC_MODEL });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const data = registerSchema.parse(req.body);
    const passwordHash = await bcrypt.hash(data.password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users(email, password_hash, name, credits) VALUES($1,$2,$3,$4) RETURNING id,email,name,credits,created_at',
      [data.email.toLowerCase(), passwordHash, data.name || '', DEFAULT_FREE_CREDITS]
    );
    const token = signToken(rows[0]);
    res.status(201).json({ token, user: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.errors[0]?.message || 'Invalid input' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const data = loginSchema.parse(req.body);
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [data.email.toLowerCase()]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const ok = await bcrypt.compare(data.password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
    const safeUser = { id: user.id, email: user.email, name: user.name, credits: user.credits, created_at: user.created_at };
    res.json({ token: signToken(user), user: safeUser });
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.errors[0]?.message || 'Invalid input' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/conversations', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,title,created_at,updated_at FROM conversations WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50',
    [req.user.id]
  );
  res.json({ conversations: rows });
});

app.get('/api/conversations/:id/messages', auth, async (req, res) => {
  const { id } = req.params;
  const conv = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [id, req.user.id]);
  if (!conv.rows[0]) return res.status(404).json({ error: 'Conversation not found' });
  const { rows } = await pool.query(
    'SELECT id,role,content,created_at FROM messages WHERE conversation_id=$1 AND user_id=$2 ORDER BY created_at ASC',
    [id, req.user.id]
  );
  res.json({ messages: rows });
});

function systemPrompt(mode) {
  return `Sei Nexus, una piattaforma AI business premium per imprenditori, freelance e attività locali italiane. Non sei un chatbot generico: produci asset pronti da usare.

Regole:
- Rispondi sempre in italiano professionale, concreto, commerciale.
- Se la richiesta è vaga, fai massimo 2 domande solo se indispensabile; altrimenti fai assunzioni ragionevoli e procedi.
- Non dire mai che sei Claude o Anthropic.
- Non inventare dati legali/fiscali specifici; quando serve, segnala che va verificato da un professionista.
- Output ordinato, con sezioni chiare, copy pronto, CTA, esempi pratici.
- Riporta sempre l'utente verso business, vendita, marketing, sito, offerta, contenuti o strategia.

Modalità richiesta: ${mode}.

Quando l'utente chiede un business kit, produci:
1. Diagnosi rapida
2. Posizionamento
3. Offerta/pacchetti
4. Landing copy
5. Annunci Google/Meta
6. Piano social
7. Messaggi WhatsApp/email
8. Piano operativo 7 giorni
9. Prossimo step concreto.`;
}

function titleFromMessage(message) {
  const cleaned = message.replace(/\s+/g, ' ').trim();
  return cleaned.length > 55 ? `${cleaned.slice(0, 55)}...` : cleaned || 'Nuova chat';
}

app.post('/api/chat', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const data = chatSchema.parse(req.body);

    if (req.user.credits < CHAT_CREDIT_COST) {
      return res.status(402).json({ error: 'Crediti insufficienti', credits: req.user.credits });
    }

    let conversationId = data.conversationId;

    await client.query('BEGIN');

    if (conversationId) {
      const existing = await client.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2', [conversationId, req.user.id]);
      if (!existing.rows[0]) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Conversation not found' });
      }
    } else {
      const created = await client.query(
        'INSERT INTO conversations(user_id,title) VALUES($1,$2) RETURNING id',
        [req.user.id, titleFromMessage(data.message)]
      );
      conversationId = created.rows[0].id;
    }

    await client.query(
      'INSERT INTO messages(conversation_id,user_id,role,content) VALUES($1,$2,$3,$4)',
      [conversationId, req.user.id, 'user', data.message]
    );

    const history = await client.query(
      `SELECT role, content FROM messages
       WHERE conversation_id=$1 AND user_id=$2 AND role IN ('user','assistant')
       ORDER BY created_at DESC LIMIT 12`,
      [conversationId, req.user.id]
    );

    const messages = history.rows.reverse().map((m) => ({ role: m.role, content: m.content }));

    const completion = await anthropic.messages.create({
      model: ANTHROPIC_MODEL,
      max_tokens: 3500,
      temperature: 0.65,
      system: systemPrompt(data.mode),
      messages,
    });

    const answer = completion.content
      ?.filter((part) => part.type === 'text')
      ?.map((part) => part.text)
      ?.join('\n')
      ?.trim() || 'Non sono riuscito a generare una risposta. Riprova.';

    await client.query(
      'INSERT INTO messages(conversation_id,user_id,role,content) VALUES($1,$2,$3,$4)',
      [conversationId, req.user.id, 'assistant', answer]
    );

    const updatedCredits = req.user.credits - CHAT_CREDIT_COST;
    await client.query('UPDATE users SET credits=$1, updated_at=NOW() WHERE id=$2', [updatedCredits, req.user.id]);
    await client.query('INSERT INTO credit_events(user_id, amount, reason) VALUES($1,$2,$3)', [req.user.id, -CHAT_CREDIT_COST, 'chat_message']);
    await client.query('UPDATE conversations SET updated_at=NOW() WHERE id=$1', [conversationId]);

    await client.query('COMMIT');

    res.json({ conversationId, answer, credits: updatedCredits });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.errors[0]?.message || 'Invalid input' });
    console.error('CHAT_ERROR', err);
    res.status(500).json({ error: err.message || 'Chat failed' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/add-credits', auth, async (req, res) => {
  // Endpoint temporaneo per test. Disattivalo quando andrai live con Stripe.
  const amount = Math.min(Number(req.body.amount || 0), 1000);
  if (!amount || amount < 1) return res.status(400).json({ error: 'Invalid amount' });
  const { rows } = await pool.query('UPDATE users SET credits=credits+$1 WHERE id=$2 RETURNING credits', [amount, req.user.id]);
  await pool.query('INSERT INTO credit_events(user_id, amount, reason) VALUES($1,$2,$3)', [req.user.id, amount, 'manual_test_topup']);
  res.json({ credits: rows[0].credits });
});

app.use((err, req, res, next) => {
  if (err.message?.startsWith('CORS blocked origin')) {
    return res.status(403).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`✅ Nexus API online on port ${PORT}`));
  })
  .catch((err) => {
    console.error('❌ DB init failed:', err);
    process.exit(1);
  });
