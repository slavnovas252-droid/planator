
import express from "express";
import crypto from "node:crypto";
import { Pool } from "pg";

const app = express();
app.use(express.json());

const {
  PORT = 3000,
  DATABASE_URL,
  GEMINI_API_KEY,
  TELEGRAM_BOT_TOKEN,
  YOOKASSA_SHOP_ID,
  YOOKASSA_SECRET_KEY,
  APP_URL
} = process.env;

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "Planator API" });
});

function requireUser(req, res, next) {
  const initData = req.get("X-Telegram-Init-Data");

  if (!initData || !TELEGRAM_BOT_TOKEN) {
    return res.status(401).json({ error: "Telegram authorization required" });
  }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    const authDate = Number(params.get("auth_date"));

    if (!hash || !authDate) throw new Error("Missing Telegram fields");

    const age = Math.floor(Date.now() / 1000) - authDate;
    if (age < 0 || age > 300) throw new Error("Expired Telegram data");

    params.delete("hash");
    params.delete("signature");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secret = crypto
      .createHmac("sha256", "WebAppData")
      .update(TELEGRAM_BOT_TOKEN)
      .digest();

    const expected = crypto
      .createHmac("sha256", secret)
      .update(dataCheckString)
      .digest("hex");

    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(expected, "hex");

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      throw new Error("Invalid Telegram signature");
    }

    const user = JSON.parse(params.get("user") || "{}");
    if (!user.id) throw new Error("Missing Telegram user");

    req.user = { id: String(user.id) };
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired Telegram data" });
  }
}

app.post("/api/ai/chat", requireUser, async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(503).json({ error: "AI service is not configured" });
  }

  const { message, chatId, createdAt } = req.body || {};

  if (typeof message !== "string" || !message.trim() || message.length > 4000) {
    return res.status(400).json({ error: "Message must be 1–4000 characters" });
  }

  // The client cannot extend a chat's lifetime by changing createdAt.
  if (!pool) {
    return res.status(503).json({ error: "Database is not configured" });
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ai_chats (
        id UUID PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        messages JSONB NOT NULL DEFAULT '[]'::jsonb
      )
    `);

    let id = chatId;
    let chat;

    if (id) {
      const result = await pool.query(
        `SELECT * FROM ai_chats
         WHERE id = $1 AND user_id = $2
         AND created_at > NOW() - INTERVAL '24 hours'`,
        [id, req.user.id]
      );
      chat = result.rows[0];
      if (!chat) return res.status(410).json({ error: "Chat expired. Create a new chat." });
    } else {
      id = crypto.randomUUID();
      const result = await pool.query(
        `INSERT INTO ai_chats (id, user_id)
         VALUES ($1, $2) RETURNING *`,
        [id, req.user.id]
      );
      chat = result.rows[0];
    }

    const history = Array.isArray(chat.messages) ? chat.messages : [];
    const contents = [
      {
        role: "user",
        parts: [{
          text: "Ты Planator — дружелюбный помощник по планированию. Отвечай по-русски, помогай составлять реалистичные планы. Не обещай, что действия выполнены за пользователя."
        }]
      },
      ...history,
      { role: "user", parts: [{ text: message.trim() }] }
    ];

    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": GEMINI_API_KEY
        },
        body: JSON.stringify({ contents })
      }
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(502).json({ error: "AI provider request failed" });
    }

    const answer = data.candidates?.[0]?.content?.parts
      ?.map(part => part.text || "").join("").trim();

    if (!answer) return res.status(502).json({ error: "Empty AI response" });

    const updated = [
      ...history,
      { role: "user", parts: [{ text: message.trim() }] },
      { role: "model", parts: [{ text: answer }] }
    ];

    await pool.query(
      `UPDATE ai_chats SET messages = $1::jsonb
       WHERE id = $2 AND user_id = $3`,
      [JSON.stringify(updated), id, req.user.id]
    );

    res.json({ chatId: id, answer, expiresAt: new Date(
      new Date(chat.created_at).getTime() + 24 * 60 * 60 * 1000
    ).toISOString() });
  } catch (error) {
    console.error("AI route failed:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/payments/create", requireUser, async (req, res) => {
  if (!YOOKASSA_SHOP_ID || !YOOKASSA_SECRET_KEY || !APP_URL) {
    return res.status(503).json({ error: "Payments are not configured" });
  }

  if (!pool) return res.status(503).json({ error: "Database is not configured" });

  const idempotenceKey = crypto.randomUUID();

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const paymentId = crypto.randomUUID();

    const response = await fetch("https://api.yookassa.ru/v3/payments", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotence-Key": idempotenceKey,
        Authorization: "Basic " + Buffer.from(
          `${YOOKASSA_SHOP_ID}:${YOOKASSA_SECRET_KEY}`
        ).toString("base64")
      },
      body: JSON.stringify({
        amount: { value: "299.00", currency: "RUB" },
        capture: true,
        confirmation: {
          type: "redirect",
          return_url: `${APP_URL}/?payment=return`
        },
        description: "Planator Plus — 30 дней доступа",
        metadata: {
          internal_payment_id: paymentId,
          telegram_user_id: req.user.id
        }
      })
    });

    const data = await response.json();

    if (!response.ok || !data.id || !data.confirmation?.confirmation_url) {
      return res.status(502).json({ error: "Could not create payment" });
    }

    await pool.query(
      `INSERT INTO payments (id, user_id, status) VALUES ($1, $2, 'pending')`,
      [data.id, req.user.id]
    );

    res.json({
      paymentId: data.id,
      confirmationUrl: data.confirmation.confirmation_url
    });
  } catch (error) {
    console.error("Payment creation failed:", error.message);
    res.status(500).json({ error: "Payment creation failed" });
  }
});

app.get("/api/subscription", requireUser, async (req, res) => {
  if (!pool) return res.status(503).json({ error: "Database is not configured" });

  try {
    const result = await pool.query(
      `SELECT expires_at FROM subscriptions
       WHERE user_id = $1 AND expires_at > NOW()
       ORDER BY expires_at DESC LIMIT 1`,
      [req.user.id]
    );

    res.json({
      plus: result.rows.length > 0,
      expiresAt: result.rows[0]?.expires_at || null
    });
  } catch (error) {
    if (error.code === "42P01") {
      return res.json({ plus: false, expiresAt: null });
    }
    res.status(500).json({ error: "Could not check subscription" });
  }
});

app.get("/", (_req, res) => {
  res.sendFile("index.html", { root: "public" });
});

app.listen(PORT, () => {
  console.log(`Planator API listening on port ${PORT}`);
});
