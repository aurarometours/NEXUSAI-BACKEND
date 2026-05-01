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
const NODE_ENV = process.env.NODE_ENV || "production";
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || "claude-3-5-haiku-latest";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

function requireEnv(name, value) {
  if (!value || String(value).trim() === "") {
    throw new Error(`${name} missing`);
  }
}

requireEnv("DATABASE_URL", DATABASE_URL);
requireEnv("JWT_SECRET", JWT_SECRET);
requireEnv("ANTHROPIC_API_KEY", ANTHROPIC_API_KEY);

const allowedOrigins =
  CORS_ORIGIN === "*"
    ? "*"
    : CORS_ORIGIN.split(",")
        .map((s) => s.trim())
        .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins === "*" || allowedOrigins.includes(origin)) {
        return cb(null, true);
      }

      return cb(null, true);
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "3mb" }));
app.use(morgan("tiny"));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

const anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

async function initDb() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      credits INT NOT NULL DEFAULT 60,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Nuova chat',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      artifact JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_conversations_user 
    ON conversations(user_id, updated_at DESC);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_messages_conversation 
    ON messages(conversation_id, created_at ASC);
  `);

  console.log("✅ Database initialized");
}

function sign(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

async function auth(req, res, next) {
  try {
    const raw = req.headers.authorization || "";
    const token = raw.startsWith("Bearer ") ? raw.slice(7) : "";

    if (!token) {
      return res.status(401).json({ message: "Accesso richiesto." });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const { rows } = await pool.query(
      `SELECT id, name, email, credits FROM users WHERE id=$1`,
      [decoded.id]
    );

    if (!rows[0]) {
      return res.status(401).json({ message: "Sessione non valida." });
    }

    req.user = rows[0];
    next();
  } catch {
    return res
      .status(401)
      .json({ message: "Sessione scaduta. Accedi di nuovo." });
  }
}

function cleanTitle(value) {
  return (
    String(value || "Nuova chat")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 58) || "Nuova chat"
  );
}

function publicChatError(res) {
  return res.status(500).json({
    publicMessage:
      "Nexus non è riuscito a generare la risposta. Riprova tra poco.",
  });
}

/* =========================
   NEXUS MODES
========================= */

function detectMode(message) {
  const text = String(message || "").toLowerCase();

  if (
    text.includes("landing") ||
    text.includes("sito") ||
    text.includes("html") ||
    text.includes("pagina") ||
    text.includes("codice") ||
    text.includes("scaricabile")
  ) {
    return "landing";
  }

  if (
    text.includes("ads") ||
    text.includes("google") ||
    text.includes("meta") ||
    text.includes("campagna") ||
    text.includes("annunci") ||
    text.includes("keyword")
  ) {
    return "ads";
  }

  if (
    text.includes("business plan") ||
    text.includes("strategia") ||
    text.includes("posizionamento") ||
    text.includes("funnel")
  ) {
    return "business";
  }

  if (
    text.includes("instagram") ||
    text.includes("social") ||
    text.includes("post") ||
    text.includes("reel") ||
    text.includes("caption")
  ) {
    return "social";
  }

  if (
    text.includes("email") ||
    text.includes("whatsapp") ||
    text.includes("messaggio") ||
    text.includes("follow-up")
  ) {
    return "sales_message";
  }

  if (
    text.includes("preventivo") ||
    text.includes("offerta") ||
    text.includes("proposta") ||
    text.includes("pacchetti")
  ) {
    return "offer";
  }

  return "general";
}

function getModePrompt(mode) {
  const base = `
Sei Nexus, una piattaforma AI business premium progettata per produrre asset reali pronti alla vendita.

IDENTITÀ:
- Sei Nexus.
- Non sei un assistente generico.
- Non sei un chatbot da intrattenimento.
- Non devi mai dire di essere Claude, Anthropic, Sonnet o un modello esterno.
- Non devi mai mostrare nomi di modelli, API, request_id, log o dettagli tecnici.

REGOLE ASSOLUTE:
1. Non inventare brand, dati, recensioni, numeri o contesto se l'utente li ha già dati o se non li conosci.
2. Non dire mai "ho visitato il sito", "ho controllato online", "ho analizzato il riferimento" se il contenuto non è stato fornito.
3. Se l'utente cita un brand, usa quel brand in modo coerente.
4. Se mancano dati, usa assunzioni professionali e segnala solo i placeholder davvero necessari.
5. Niente stile gaming/neon/SaaS generico se il settore richiede luxury, travel, hospitality, beauty, finance, local business premium.
6. Ogni output deve sembrare vendibile a un cliente reale.
7. Niente fluff, niente poesia inutile, niente scalette vuote.
8. La prima generazione deve essere completa, ordinata, curata e pronta da usare.
9. Margini, gerarchie, sezioni, spaziature e CTA devono essere trattati come se il risultato fosse per un cliente pagante.
10. Se produci codice, deve essere completo e funzionante, non frammenti.

STILE GENERALE:
- premium
- elegante
- concreto
- business-ready
- conversion-first
- italiano professionale
- chiaro e autorevole

PROCESSO INTERNO DA SEGUIRE PRIMA DI RISPONDERE:
- identifica settore
- identifica obiettivo dell'utente
- identifica tono adatto
- evita incoerenze visive o commerciali
- verifica che l'output sia usabile subito
- verifica che il brand sia corretto

Non spiegare questo processo all'utente. Produci direttamente.
`;

  const modes = {
    landing: `
MODALITÀ: LANDING PAGE / WEBSITE BUILDER PREMIUM

Devi comportarti come:
- UX/UI designer senior
- copywriter conversion-first
- frontend developer
- brand strategist

Quando l'utente chiede una landing, sito, pagina, HTML, file scaricabile o codice:
DEVI generare un file HTML completo in un unico blocco:
\`\`\`html
...
\`\`\`

Il file deve includere:
- <!doctype html>
- html/head/body completi
- CSS interno completo
- JS interno solo se utile
- responsive mobile curato
- hero forte
- CTA visibili above the fold
- sezioni conversion-first
- copy professionale
- FAQ
- footer
- struttura pronta da caricare online

QUALITÀ DESIGN:
- layout pulito
- margini coerenti
- spaziature premium
- niente elementi fuori griglia
- niente colori casuali
- niente neon se non richiesto
- niente emoji infantili se il brand è premium
- tipografia moderna
- bottoni chiari
- sezioni leggibili

SE AURA ROME TOURS / AURAROMETOURS:
Il risultato deve parlare di:
- tour privati in golf cart a Roma
- esperienza elegante, privata, confortevole
- clienti internazionali
- booking diretto e WhatsApp
- Roma senza stress e senza folle
- tono luxury travel, non gaming, non verde neon

VIETATO:
- inventare nomi tipo GreenDrive se il brand è Aura Rome Tours
- dire che hai visitato il sito se non hai accesso reale
- generare solo copy senza HTML quando viene richiesto HTML
`,

    ads: `
MODALITÀ: ADS SPECIALIST

Devi comportarti come Google Ads / Meta Ads specialist senior.

Output:
- strategia campagna
- pubblico/target
- angoli creativi
- keyword
- negative keyword
- headline
- description
- sitelink
- callout
- snippet
- landing angle
- test A/B
- metriche da monitorare

Regole:
- niente promesse false
- niente copy generico
- orientamento conversione
- separa search intent alto da awareness
`,

    business: `
MODALITÀ: BUSINESS STRATEGIST

Devi comportarti come consulente business senior.

Output:
- posizionamento
- target
- offerta
- pricing
- funnel
- acquisizione clienti
- upsell
- rischi
- piano operativo 7/30/90 giorni

Regole:
- concreto
- monetizzabile
- niente teoria scolastica
- ogni sezione deve portare ad azione
`,

    social: `
MODALITÀ: SOCIAL CONTENT STRATEGIST

Output:
- idee contenuto
- hook
- caption
- reel script
- caroselli
- CTA
- calendario
- obiettivo del contenuto

Regole:
- niente caption banali
- niente emoji casuali
- contenuti orientati a fiducia, desiderio o vendita
`,

    sales_message: `
MODALITÀ: SALES COPYWRITER

Output:
- email pronta
- messaggio WhatsApp pronto
- follow-up
- subject
- versione breve
- versione premium
- tono alternativo

Regole:
- niente spam
- niente tono disperato
- personalizzazione credibile
- chiusura chiara
`,

    offer: `
MODALITÀ: OFFER BUILDER

Output:
- struttura offerta
- pacchetti
- valore percepito
- condizioni
- CTA
- messaggio accompagnamento
- upsell

Regole:
- premium
- chiaro
- orientato alla chiusura
`,

    general: `
MODALITÀ: GENERAL BUSINESS ASSISTANT

Rispondi come consulente business senior.
Porta sempre l'utente verso un output operativo:
- piano
- testo pronto
- strategia
- file
- checklist
`,
  };

  return `${base}\n${modes[mode] || modes.general}`;
}

function wantsArtifact(message, mode) {
  const text = String(message || "").toLowerCase();

  return (
    mode === "landing" ||
    /(html|landing|sito|pagina|codice|scaricabile|download|file)/i.test(text)
  );
}

function extractArtifact(text) {
  const html = text.match(/```html\s*([\s\S]*?)```/i);

  if (html && html[1].trim().length > 100) {
    return {
      filename: "nexus-output.html",
      mime: "text/html;charset=utf-8",
      content: html[1].trim(),
    };
  }

  const genericCode = text.match(/```(?:[a-zA-Z0-9_-]+)?\s*([\s\S]*?)```/);

  if (
    genericCode &&
    genericCode[1].trim().length > 100 &&
    genericCode[1].includes("<")
  ) {
    return {
      filename: "nexus-output.html",
      mime: "text/html;charset=utf-8",
      content: genericCode[1].trim(),
    };
  }

  return null;
}

function stripCodeBlock(text) {
  return text
    .replace(
      /```html\s*([\s\S]*?)```/i,
      "Ho creato il file HTML completo. Puoi scaricarlo dalla card qui sotto."
    )
    .replace(
      /```(?:[a-zA-Z0-9_-]+)?\s*([\s\S]*?)```/i,
      "Ho preparato il file completo. Puoi scaricarlo dalla card qui sotto."
    );
}

/* =========================
   ROUTES
========================= */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "nexus-backend",
  });
});

/* REGISTER */
app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (name.length < 2) {
      return res.status(400).json({ message: "Inserisci un nome valido." });
    }

    if (!email.includes("@")) {
      return res.status(400).json({ message: "Inserisci un'email valida." });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: "La password deve avere almeno 8 caratteri." });
    }

    const hash = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users(name,email,password_hash)
       VALUES($1,$2,$3)
       RETURNING id,name,email,credits`,
      [name, email, hash]
    );

    res.status(201).json({ user: rows[0] });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({
        message: "Questa email è già registrata. Accedi con il tuo account.",
      });
    }

    console.error("register error", e);
    res.status(400).json({ message: "Errore registrazione." });
  }
});

/* LOGIN */
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const { rows } = await pool.query(`SELECT * FROM users WHERE email=$1`, [
      email,
    ]);

    const found = rows[0];

    if (!found) {
      return res.status(401).json({ message: "Credenziali errate." });
    }

    const ok = await bcrypt.compare(password, found.password_hash);

    if (!ok) {
      return res.status(401).json({ message: "Credenziali errate." });
    }

    const user = {
      id: found.id,
      name: found.name,
      email: found.email,
      credits: found.credits,
    };

    res.json({
      token: sign(user),
      user,
    });
  } catch (e) {
    console.error("login error", e);
    res.status(500).json({ message: "Accesso non riuscito." });
  }
});

/* ME */
app.get("/api/me", auth, async (req, res) => {
  res.json({ user: req.user });
});

/* CONVERSATIONS */
app.get("/api/conversations", auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,title,created_at,updated_at
     FROM conversations
     WHERE user_id=$1
     ORDER BY updated_at DESC
     LIMIT 80`,
    [req.user.id]
  );

  res.json({ conversations: rows });
});

app.post("/api/conversations", auth, async (req, res) => {
  const title = cleanTitle(req.body.title);

  const { rows } = await pool.query(
    `INSERT INTO conversations(user_id,title)
     VALUES($1,$2)
     RETURNING id,title,created_at,updated_at`,
    [req.user.id, title]
  );

  res.status(201).json({ conversation: rows[0] });
});

app.get("/api/conversations/:id/messages", auth, async (req, res) => {
  const { rows: conversationRows } = await pool.query(
    `SELECT id FROM conversations WHERE id=$1 AND user_id=$2`,
    [req.params.id, req.user.id]
  );

  if (!conversationRows[0]) {
    return res.status(404).json({ message: "Chat non trovata." });
  }

  const { rows } = await pool.query(
    `SELECT role,content,artifact,created_at
     FROM messages
     WHERE conversation_id=$1 AND user_id=$2
     ORDER BY created_at ASC
     LIMIT 160`,
    [req.params.id, req.user.id]
  );

  res.json({ messages: rows });
});

/* CHAT */
app.post("/api/chat", auth, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();
    let conversationId = req.body.conversationId;

    if (!message) {
      return res.status(400).json({ message: "Scrivi un messaggio." });
    }

    if (req.user.credits <= 0) {
      return res.status(402).json({
        message: "Crediti terminati. Effettua l'upgrade per continuare.",
      });
    }

    if (!conversationId) {
      const { rows } = await pool.query(
        `INSERT INTO conversations(user_id,title) VALUES($1,$2) RETURNING id`,
        [req.user.id, cleanTitle(message)]
      );

      conversationId = rows[0].id;
    } else {
      const { rows } = await pool.query(
        `SELECT id FROM conversations WHERE id=$1 AND user_id=$2`,
        [conversationId, req.user.id]
      );

      if (!rows[0]) {
        return res.status(404).json({ message: "Chat non trovata." });
      }
    }

    await pool.query(
      `INSERT INTO messages(user_id,conversation_id,role,content)
       VALUES($1,$2,'user',$3)`,
      [req.user.id, conversationId, message]
    );

    const { rows: historyRows } = await pool.query(
      `SELECT role, content
       FROM messages
       WHERE conversation_id=$1 AND user_id=$2
       ORDER BY created_at DESC
       LIMIT 20`,
      [conversationId, req.user.id]
    );

    const history = historyRows.reverse().map((m) => ({
      role: m.role === "assistant" ? "assistant" : "user",
      content: m.content,
    }));

    const mode = detectMode(message);
    const systemPrompt = getModePrompt(mode);
    const artifactExpected = wantsArtifact(message, mode);

    const completion = await anthropic.messages.create({
      model: ANTHROPIC_MODEL,
      max_tokens: artifactExpected ? 5000 : 2800,
      temperature: mode === "landing" ? 0.32 : 0.45,
      system: systemPrompt,
      messages: history,
    });

    let reply =
      completion.content
        ?.map((p) => (p.type === "text" ? p.text : ""))
        .join("\n")
        .trim() || "Nexus ha preparato la risposta.";

    const artifact = extractArtifact(reply);

    if (artifact) {
      reply = stripCodeBlock(reply);
    }

    const cost = artifactExpected ? 8 : 3;

    await pool.query(
      `UPDATE users SET credits=GREATEST(credits-$1,0) WHERE id=$2`,
      [cost, req.user.id]
    );

    await pool.query(
      `INSERT INTO messages(user_id,conversation_id,role,content,artifact)
       VALUES($1,$2,'assistant',$3,$4)`,
      [
        req.user.id,
        conversationId,
        reply,
        artifact ? JSON.stringify(artifact) : null,
      ]
    );

    await pool.query(
      `UPDATE conversations
       SET updated_at=NOW(),
           title=CASE WHEN title='Nuova chat' THEN $3 ELSE title END
       WHERE id=$1 AND user_id=$2`,
      [conversationId, req.user.id, cleanTitle(message)]
    );

    const { rows: users } = await pool.query(
      `SELECT id,name,email,credits FROM users WHERE id=$1`,
      [req.user.id]
    );

    res.json({
      reply,
      artifact,
      conversationId,
      mode,
      user: users[0],
    });
  } catch (e) {
    console.error("Nexus chat error:", {
      name: e.name,
      status: e.status,
      message: e.message,
    });

    return publicChatError(res);
  }
});

/* START */
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`✅ Nexus backend running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ DB init failed:", err);
    process.exit(1);
  });
