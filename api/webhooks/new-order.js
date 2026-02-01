const crypto = require("crypto");
const https = require("https");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const VALID_SERVICES = [
  "3d-printing",
  "dtf-transfers",
  "laser-services",
  "sublimation",
];

const VALID_TIMELINES = ["rush", "standard", "flexible", "ongoing"];

const REQUIRED_FIELDS = ["service", "firstName", "lastName", "email", "phone", "quantity", "timeline"];

const OPTIONAL_FIELDS = [
  "dimensions",
  "materials",
  "budget",
  "description",
  "referral",
  "contactMethod",
  "newsletter",
];

const MAX_BODY_BYTES = 50_000; // 50 KB
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 10; // requests per window

const EMBED_COLOR = 0x7c3aed; // purple

const SERVICE_LABELS = {
  "3d-printing": "3D Printing",
  "dtf-transfers": "DTF Transfers",
  "laser-services": "Laser Services",
  "sublimation": "Sublimation",
};

const TIMELINE_LABELS = {
  rush: "Rush (3-5 days)",
  standard: "Standard (1-2 weeks)",
  flexible: "Flexible (2+ weeks)",
  ongoing: "Ongoing/Multiple Orders",
};

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
    { name: "Name", value: sanitize(`${data.firstName} ${data.lastName}`), inline: true },
    { name: "Email", value: sanitize(data.email), inline: true },
    { name: "Phone", value: sanitize(data.phone), inline: true },
    { name: "Service", value: SERVICE_LABELS[data.service] || sanitize(data.service), inline: true },
    { name: "Quantity", value: sanitize(String(data.quantity)), inline: true },
    { name: "Timeline", value: TIMELINE_LABELS[data.timeline] || sanitize(data.timeline), inline: true },
  ];

  if (data.dimensions) {
    fields.push({ name: "Dimensions", value: sanitize(data.dimensions), inline: true });
  }
  if (data.materials) {
    fields.push({ name: "Material/Color", value: sanitize(data.materials), inline: true });
  }
  if (data.budget) {
    fields.push({ name: "Budget", value: sanitize(data.budget), inline: true });
  }
  if (data.contactMethod) {
    fields.push({ name: "Preferred Contact", value: sanitize(data.contactMethod), inline: true });
  }
  if (data.referral) {
    fields.push({ name: "Referral Source", value: sanitize(data.referral), inline: true });
  }
  if (data.newsletter) {
    fields.push({ name: "Newsletter", value: "Yes", inline: true });
  }
  if (data.description) {
    fields.push({ name: "Description", value: sanitize(data.description), inline: false });
  }

  return {
    embeds: [
      {
        title: "New Quote Request",
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

  if (!VALID_SERVICES.includes(data.service)) {
    return res.status(400).json({
      error: `Invalid service. Must be one of: ${VALID_SERVICES.join(", ")}`,
    });
  }

  if (!VALID_TIMELINES.includes(data.timeline)) {
    return res.status(400).json({
      error: `Invalid timeline. Must be one of: ${VALID_TIMELINES.join(", ")}`,
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
