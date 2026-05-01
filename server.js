import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import dotenv from 'dotenv';
import Anthropic from '@anthropic-ai/sdk';
import { Resend } from 'resend';

dotenv.config();

const app = express();
const { Pool } = pg;

const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';
const FREE_CREDITS = Number(process.env.FREE_CREDITS || 60);
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6';

function requireEnv(name){ const v = process.env[name]; if(!v || String(v).trim()==='') throw new Error(`${name} is missing. Add it in Railway service Variables.`); return v; }
requireEnv('DATABASE_URL');
requireEnv('JWT_SECRET');
requireEnv('ANTHROPIC_API_KEY');

const allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map(s=>s.trim()).filter(Boolean);
app.use(helmet({ crossOriginResourcePolicy:false }));
app.use(cors({ origin(origin, cb){ if(!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return cb(null,true); return cb(new Error(`CORS blocked: ${origin}`)); }, credentials:true }));
app.options('*', cors());
app.use(express.json({ limit:'1mb' }));
app.use(morgan('tiny'));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: isProd ? { rejectUnauthorized:false } : false });
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function initDb(){
  await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT DEFAULT '',
      credits INTEGER NOT NULL DEFAULT ${FREE_CREDITS},
      email_verified BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS conversations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Nuova chat',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user','assistant')),
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS verification_codes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at DESC);');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at ASC);');
  console.log('✅ Database initialized');
}

function tokenFor(user){ return jwt.sign({ id:user.id, email:user.email }, process.env.JWT_SECRET, { expiresIn:'30d' }); }
function auth(req,res,next){
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).json({ error:'Sessione scaduta. Accedi di nuovo.' });
  try{ req.user = jwt.verify(token, process.env.JWT_SECRET); next(); } catch { return res.status(401).json({ error:'Sessione non valida. Accedi di nuovo.' }); }
}
function publicUser(row){ return { id:row.id, email:row.email, name:row.name || '', credits:row.credits, emailVerified:row.email_verified }; }

app.get('/health', (_,res)=>res.json({ ok:true, app:'Nexus Backend', model:MODEL, time:new Date().toISOString() }));

app.post('/api/auth/register', async (req,res)=>{
  try{
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const name = String(req.body.name || '').trim();
    if(!email.includes('@')) return res.status(400).json({ error:'Inserisci una email valida.' });
    if(password.length < 8) return res.status(400).json({ error:'La password deve avere almeno 8 caratteri.' });
    const hash = await bcrypt.hash(password, 11);
    const requireVerify = process.env.REQUIRE_EMAIL_VERIFICATION === 'true';
    const { rows } = await pool.query(
      `INSERT INTO users(email,password_hash,name,credits,email_verified) VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [email, hash, name, FREE_CREDITS, !requireVerify]
    );
    const user = rows[0];
    if(requireVerify && resend){
      const code = String(Math.floor(100000 + Math.random()*900000));
      await pool.query('INSERT INTO verification_codes(user_id,code,expires_at) VALUES($1,$2,NOW()+INTERVAL \'15 minutes\')',[user.id, code]);
      await resend.emails.send({ from: process.env.EMAIL_FROM, to: email, subject:'Codice di conferma Nexus', html:`<div style="font-family:Inter,Arial,sans-serif"><h2>Il tuo codice Nexus</h2><p>Inserisci questo codice per confermare l’account:</p><div style="font-size:28px;font-weight:800;letter-spacing:6px">${code}</div></div>` });
    }
    res.status(201).json({ token: tokenFor(user), user: publicUser(user), requiresVerification: requireVerify });
  }catch(e){
    if(e.code === '23505') return res.status(409).json({ error:'Email già registrata. Accedi o usa un’altra email.' });
    console.error('register error', e); res.status(500).json({ error:'Registrazione non riuscita. Riprova.' });
  }
});

app.post('/api/auth/login', async (req,res)=>{
  try{
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    const user = rows[0];
    if(!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error:'Email o password non corretti.' });
    res.json({ token: tokenFor(user), user: publicUser(user) });
  }catch(e){ console.error('login error', e); res.status(500).json({ error:'Login non riuscito. Riprova.' }); }
});

app.post('/api/auth/verify-email', auth, async (req,res)=>{
  const code = String(req.body.code || '').trim();
  const { rows } = await pool.query('SELECT * FROM verification_codes WHERE user_id=$1 AND code=$2 AND used=false AND expires_at>NOW() ORDER BY created_at DESC LIMIT 1',[req.user.id, code]);
  if(!rows[0]) return res.status(400).json({ error:'Codice non valido o scaduto.' });
  await pool.query('UPDATE verification_codes SET used=true WHERE id=$1',[rows[0].id]);
  const u = await pool.query('UPDATE users SET email_verified=true WHERE id=$1 RETURNING *',[req.user.id]);
  res.json({ user: publicUser(u.rows[0]) });
});

app.get('/api/me', auth, async (req,res)=>{
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1',[req.user.id]);
  if(!rows[0]) return res.status(404).json({ error:'Utente non trovato.' });
  res.json({ user: publicUser(rows[0]) });
});

app.get('/api/conversations', auth, async (req,res)=>{
  const { rows } = await pool.query('SELECT id,title,created_at,updated_at FROM conversations WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50',[req.user.id]);
  res.json({ conversations: rows });
});

app.get('/api/conversations/:id/messages', auth, async (req,res)=>{
  const { rows:c } = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2',[req.params.id, req.user.id]);
  if(!c[0]) return res.status(404).json({ error:'Conversazione non trovata.' });
  const { rows } = await pool.query('SELECT role,content,created_at FROM messages WHERE conversation_id=$1 AND user_id=$2 ORDER BY created_at ASC',[req.params.id, req.user.id]);
  res.json({ messages: rows });
});

const SYSTEM_PROMPT = `Sei Nexus, un assistente business AI premium per imprenditori, freelance e piccole attività italiane. Non devi mai dire che sei Claude, Anthropic, GPT o un modello esterno. Produci output concreti e vendibili: business plan, landing copy, ads, social plan, offerte, preventivi, email, WhatsApp e strategie clienti. Se la richiesta è vaga, fai massimo 2 domande brevi oppure procedi con assunzioni ragionevoli. Stile: elegante, diretto, operativo, italiano professionale. Struttura sempre le risposte con sezioni utili e azioni pronte.`;

app.post('/api/chat', auth, async (req,res)=>{
  try{
    const message = String(req.body.message || '').trim();
    let conversationId = req.body.conversationId || null;
    if(!message) return res.status(400).json({ error:'Scrivi un messaggio.' });

    const u = await pool.query('SELECT * FROM users WHERE id=$1',[req.user.id]);
    const user = u.rows[0];
    if(!user) return res.status(404).json({ error:'Utente non trovato.' });
    if(process.env.REQUIRE_EMAIL_VERIFICATION === 'true' && !user.email_verified) return res.status(403).json({ error:'Conferma l’email prima di usare Nexus.' });
    if(user.credits <= 0) return res.status(402).json({ error:'Crediti esauriti. Effettua l’upgrade per continuare.' });

    if(conversationId){
      const ex = await pool.query('SELECT id FROM conversations WHERE id=$1 AND user_id=$2',[conversationId, req.user.id]);
      if(!ex.rows[0]) conversationId = null;
    }
    if(!conversationId){
      const title = message.slice(0,54) || 'Nuova chat';
      const c = await pool.query('INSERT INTO conversations(user_id,title) VALUES($1,$2) RETURNING id,title,created_at,updated_at',[req.user.id, title]);
      conversationId = c.rows[0].id;
    }
    await pool.query('INSERT INTO messages(conversation_id,user_id,role,content) VALUES($1,$2,$3,$4)',[conversationId, req.user.id, 'user', message]);
    const history = await pool.query('SELECT role,content FROM messages WHERE conversation_id=$1 AND user_id=$2 ORDER BY created_at ASC LIMIT 20',[conversationId, req.user.id]);
    const messages = history.rows.map(m=>({ role:m.role, content:m.content }));

    let reply = '';
    try{
      const completion = await anthropic.messages.create({ model: MODEL, max_tokens: 1800, temperature: 0.65, system: SYSTEM_PROMPT, messages });
      reply = completion.content?.map(block => block.type === 'text' ? block.text : '').join('\n').trim();
    }catch(apiErr){
      console.error('Anthropic request failed', { status: apiErr.status, type: apiErr.error?.type, message: apiErr.error?.message, request_id: apiErr.request_id });
      return res.status(502).json({ error:'Nexus non è riuscito a generare la risposta. Controlla ANTHROPIC_MODEL/API key nei log Railway e riprova.' });
    }
    if(!reply) reply = 'Nexus non ha generato contenuto. Riprova con una richiesta più specifica.';

    await pool.query('INSERT INTO messages(conversation_id,user_id,role,content) VALUES($1,$2,$3,$4)',[conversationId, req.user.id, 'assistant', reply]);
    const updated = await pool.query('UPDATE users SET credits=GREATEST(credits-1,0) WHERE id=$1 RETURNING credits',[req.user.id]);
    await pool.query('UPDATE conversations SET updated_at=NOW() WHERE id=$1',[conversationId]);
    res.json({ conversationId, reply, credits: updated.rows[0].credits });
  }catch(e){ console.error('chat route error', e); res.status(500).json({ error:'Errore interno Nexus. Riprova tra poco.' }); }
});

app.use((err, req, res, next)=>{ console.error('Unhandled', err.message); res.status(500).json({ error:'Errore server Nexus.' }); });

initDb().then(()=> app.listen(PORT, ()=> console.log(`✅ Nexus backend running on :${PORT} with ${MODEL}`))).catch(e=>{ console.error('❌ DB init failed:', e); process.exit(1); });
