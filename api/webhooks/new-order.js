const crypto = require("crypto");
const https = require("https");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const VALID_ORDER_TYPES = [
  "custom-print",
  "miniature",
  "prototype",
  "bulk-order",
  "repair",
  "other",
];

const REQUIRED_FIELDS = [
  "name",
  "email",
  "phone",
  "orderType",
  "material",
  "description",
];

const OPTIONAL_FIELDS = [
  "quantity",
  "color",
  "deadline",
  "shippingAddress",
  "message",
];

const MAX_BODY_BYTES = 50_000; // 50 KB
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 10; // requests per window

const EMBED_COLOR = 0x7c3aed; // purple — brand-appropriate for 3-D printing

// ---------------------------------------------------------------------------
// Simple in-memory rate limiter (per-IP, resets on cold start)
// ---------------------------------------------------------------------------
const rateLimitMap = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { windowStart: now, count: 1 });
    return false;
  }

  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function timestamp() {
  return new Date().toISOString();
}

function sanitize(str) {
  if (typeof str !== "string") return String(str ?? "");
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function verifySignature(payload, signature, secret) {
  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(signature, "hex"),
    Buffer.from(expected, "hex")
  );
}

function postJSON(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = JSON.stringify(body);
    const req = https.request(
      {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
      },
      (res) => {
        let chunks = "";
        res.on("data", (c) => (chunks += c));
        res.on("end", () => resolve({ status: res.statusCode, body: chunks }));
      }
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Build Discord embed
// ---------------------------------------------------------------------------
function buildEmbed(data) {
  const fields = [
    { name: "Name", value: sanitize(data.name), inline: true },
    { name: "Email", value: sanitize(data.email), inline: true },
    { name: "Phone", value: sanitize(data.phone), inline: true },
    { name: "Order Type", value: sanitize(data.orderType), inline: true },
    { name: "Material", value: sanitize(data.material), inline: true },
  ];

  for (const key of OPTIONAL_FIELDS) {
    if (data[key] !== undefined && data[key] !== null && data[key] !== "") {
      const label = key.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase());
      fields.push({
        name: label,
        value: sanitize(data[key]),
        inline: key !== "shippingAddress" && key !== "message",
      });
    }
  }

  fields.push({
    name: "Description",
    value: sanitize(data.description),
    inline: false,
  });

  return {
    embeds: [
      {
        title: "New Order Request",
        color: EMBED_COLOR,
        fields,
        timestamp: new Date().toISOString(),
        footer: { text: "Poly People Printing Order Webhook" },
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------
module.exports = async function handler(req, res) {
  // -- Method check --------------------------------------------------------
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // -- Rate limit ----------------------------------------------------------
  const ip =
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    "unknown";

  if (isRateLimited(ip)) {
    console.warn(`[${timestamp()}] Rate limited: ${ip}`);
    return res.status(429).json({ error: "Too many requests. Try again later." });
  }

  // -- Body size guard (Vercel parses JSON automatically) ------------------
  const rawBody =
    typeof req.body === "string" ? req.body : JSON.stringify(req.body);

  if (Buffer.byteLength(rawBody, "utf8") > MAX_BODY_BYTES) {
    return res.status(413).json({ error: "Payload too large" });
  }

  // -- Signature validation ------------------------------------------------
  const secret = process.env.WEBHOOK_SECRET;
  if (secret) {
    const signature = req.headers["x-webhook-signature"];
    if (!signature) {
      return res.status(401).json({ error: "Missing webhook signature" });
    }
    try {
      if (!verifySignature(rawBody, signature, secret)) {
        return res.status(401).json({ error: "Invalid webhook signature" });
      }
    } catch {
      return res.status(401).json({ error: "Invalid webhook signature" });
    }
  } else {
    console.warn(
      `[${timestamp()}] WEBHOOK_SECRET is not set — skipping signature validation (dev mode)`
    );
  }

  // -- Parse & validate body -----------------------------------------------
  let data;
  try {
    data = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "Invalid JSON body" });
  }

  if (!data || typeof data !== "object") {
    return res.status(400).json({ error: "Request body must be a JSON object" });
  }

  const missing = REQUIRED_FIELDS.filter(
    (f) => data[f] === undefined || data[f] === null || data[f] === ""
  );
  if (missing.length > 0) {
    return res
      .status(400)
      .json({ error: `Missing required fields: ${missing.join(", ")}` });
  }

  if (!VALID_ORDER_TYPES.includes(data.orderType)) {
    return res.status(400).json({
      error: `Invalid orderType. Must be one of: ${VALID_ORDER_TYPES.join(", ")}`,
    });
  }

  // -- Build embed and forward to Discord ----------------------------------
  const discordUrl = process.env.DISCORD_WEBHOOK_URL_ORDER;
  if (!discordUrl) {
    console.error(`[${timestamp()}] DISCORD_WEBHOOK_URL_ORDER is not configured`);
    return res.status(503).json({ error: "Webhook destination not configured" });
  }

  try {
    const embed = buildEmbed(data);
    const result = await postJSON(discordUrl, embed);

    if (result.status < 200 || result.status >= 300) {
      console.error(
        `[${timestamp()}] Discord API error: ${result.status} — ${result.body}`
      );
      return res
        .status(502)
        .json({ error: "Failed to forward to notification service" });
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error(`[${timestamp()}] Discord request failed:`, err.message);
    return res
      .status(502)
      .json({ error: "Failed to forward to notification service" });
  }
};
