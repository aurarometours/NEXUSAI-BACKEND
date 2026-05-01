# Nexus Backend - Railway Ready

Backend Node.js/Express per Nexus con:
- registrazione/login JWT
- PostgreSQL
- chat salvate per utente
- sistema crediti
- chiamata Anthropic lato server
- init automatico tabelle DB

## File importanti

- `server.js` backend completo
- `package.json` dipendenze e start script
- `env.example` variabili da copiare su Railway

## Deploy su Railway

1. Carica questa cartella in un repository GitHub.
2. Crea servizio Railway dal repository.
3. Nel progetto Railway aggiungi PostgreSQL.
4. Nel servizio backend vai su **Variables** e inserisci:

```env
NODE_ENV=production
DATABASE_URL=${{Postgres.DATABASE_URL}}
ANTHROPIC_API_KEY=sk-ant-api03-...
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
JWT_SECRET=metti-una-stringa-lunghissima-random
JWT_EXPIRES_IN=30d
CORS_ORIGIN=https://tuodominio.it,https://www.tuodominio.it,http://localhost:5173,http://localhost:3000
DEFAULT_FREE_CREDITS=20
CHAT_CREDIT_COST=1
```

Se il database Railway non si chiama `Postgres`, usa il nome corretto, ad esempio:

```env
DATABASE_URL=${{PostgreSQL.DATABASE_URL}}
```

Oppure copia direttamente la `DATABASE_URL` dal servizio Postgres.

5. Redeploy.
6. Apri `/health` sul dominio Railway:

```txt
https://tuo-backend.up.railway.app/health
```

Deve rispondere:

```json
{"ok":true,"db":"connected","anthropic":true}
```

## Collegamento frontend

Nel frontend imposta:

```js
const API_BASE_URL = "https://tuo-backend.up.railway.app";
```

## Endpoint principali

### Register
`POST /api/auth/register`

```json
{
  "email": "test@example.com",
  "password": "password123",
  "name": "Riccardo"
}
```

### Login
`POST /api/auth/login`

```json
{
  "email": "test@example.com",
  "password": "password123"
}
```

### Chat
`POST /api/chat`

Header:

```txt
Authorization: Bearer TOKEN
```

Body:

```json
{
  "conversationId": null,
  "mode": "business-kit",
  "message": "Crea un business kit per un centro estetico a Roma"
}
```

## Errori comuni

### `DATABASE_URL is missing`
La variabile non è nel servizio backend Railway.

### `ECONNREFUSED 127.0.0.1:5432`
Stai usando un backend vecchio o hai un fallback localhost. Questo backend non ha fallback.

### `CORS blocked origin`
Aggiungi il dominio del frontend in `CORS_ORIGIN`.

### `ANTHROPIC_API_KEY is missing`
Metti la chiave Anthropic nelle Variables del backend.

### `Crediti insufficienti`
Per test puoi usare endpoint temporaneo:

`POST /api/admin/add-credits`

Body:

```json
{"amount":100}
```

con Authorization Bearer token.
