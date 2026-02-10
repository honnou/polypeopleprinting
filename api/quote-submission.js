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

const MAX_BODY_BYTES = 50_000;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 10;

const EMBED_COLOR = 0x9333ea; // Purple

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
// In-memory rate limiter (per-IP, resets on cold start)
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
  return entry.count > RATE_LIMIT_MAX;
}

// ---------------------------------------------------------------------------
// Sanitization helpers
// ---------------------------------------------------------------------------
function sanitizeString(str) {
  if (!str) return "";
  return str
    .toString()
    .trim()
    .substring(0, 1000)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sanitizeEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const cleaned = (email || "").toString().trim().toLowerCase().substring(0, 254);
  return emailRegex.test(cleaned) ? cleaned : "";
}

function sanitizePhone(phone) {
  if (!phone) return "";
  return phone.toString().replace(/[^0-9+\-() ]/g, "").substring(0, 20);
}

// ---------------------------------------------------------------------------
// HTTP helper (uses built-in https module)
// ---------------------------------------------------------------------------
function postJSON(url, body, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = JSON.stringify(body);
    const reqHeaders = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data),
      ...headers,
    };
    const req = https.request(
      {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: reqHeaders,
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
// Email template
// ---------------------------------------------------------------------------
function generateQuoteConfirmationEmail(data) {
  return `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
    .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Quote Request Received!</h1>
    </div>
    <div class="content">
      <p>Hi ${data.firstName},</p>
      <p>Thanks for your interest in Poly People Printing! We've received your quote request for <strong>${data.service}</strong>.</p>

      <h3>What You Requested:</h3>
      <ul>
        <li><strong>Service:</strong> ${data.service}</li>
        <li><strong>Quantity:</strong> ${data.quantity}</li>
        <li><strong>Timeline:</strong> ${data.timeline}</li>
      </ul>

      <p>We'll review your request and send you a detailed quote within 24 hours (usually much faster!).</p>

      <p><strong>What happens next?</strong></p>
      <ol>
        <li>We'll analyze your project requirements</li>
        <li>Prepare a detailed quote with pricing options</li>
        <li>Email you the quote for review</li>
        <li>Answer any questions you have</li>
      </ol>

      <p>Questions in the meantime? Just reply to this email!</p>

      <p>Best,<br>The Poly People Printing Team</p>
    </div>
    <div class="footer">
      <p>Poly People Printing - Punderful Perfection<br>
      Auburn, WA | polypeopleprinting.com</p>
    </div>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Admin fallback email template
// ---------------------------------------------------------------------------
function generateAdminFallbackEmail(formType, data, labels) {
  const rows = Object.entries(data)
    .map(([key, val]) => `<tr><td style="padding:6px 12px;font-weight:bold;border:1px solid #ddd;">${key}</td><td style="padding:6px 12px;border:1px solid #ddd;">${val}</td></tr>`)
    .join("");

  const labelRows = labels
    ? Object.entries(labels)
        .map(([key, val]) => `<tr><td style="padding:6px 12px;font-weight:bold;border:1px solid #ddd;">${key}</td><td style="padding:6px 12px;border:1px solid #ddd;">${val}</td></tr>`)
        .join("")
    : "";

  return `<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
  <div style="background:#dc2626;color:white;padding:16px;border-radius:8px 8px 0 0;">
    <h2 style="margin:0;">Discord Unavailable — ${formType} Fallback</h2>
  </div>
  <div style="background:#fef2f2;padding:20px;border-radius:0 0 8px 8px;border:1px solid #fca5a5;">
    <p>Discord webhook delivery failed. This submission was <strong>not</strong> posted to Discord. Please process manually.</p>
    <table style="width:100%;border-collapse:collapse;margin-top:12px;">
      ${rows}
      ${labelRows}
    </table>
    <p style="margin-top:16px;color:#666;font-size:12px;">
      This is an automated fallback from Poly People Printing's form system.<br>
      Check Vercel function logs for additional details.
    </p>
  </div>
</body>
</html>`;
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
    return res.status(429).json({ error: "Too many requests. Try again later." });
  }

  // -- Body size guard -----------------------------------------------------
  const rawBody =
    typeof req.body === "string" ? req.body : JSON.stringify(req.body);

  if (Buffer.byteLength(rawBody, "utf8") > MAX_BODY_BYTES) {
    return res.status(413).json({ error: "Payload too large" });
  }

  // -- Parse body ----------------------------------------------------------
  let data;
  try {
    data = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "Invalid JSON body" });
  }

  if (!data || typeof data !== "object") {
    return res.status(400).json({ error: "Request body must be a JSON object" });
  }

  // -- Validate & sanitize -------------------------------------------------
  const sanitizedData = {
    service: sanitizeString(data.service),
    quantity: parseInt(data.quantity) || 0,
    timeline: sanitizeString(data.timeline),
    dimensions: sanitizeString(data.dimensions || ""),
    materials: sanitizeString(data.materials || ""),
    budget: sanitizeString(data.budget || ""),
    description: sanitizeString(data.description || ""),
    referral: sanitizeString(data.referral || ""),
    firstName: sanitizeString(data.firstName),
    lastName: sanitizeString(data.lastName),
    email: sanitizeEmail(data.email),
    phone: sanitizePhone(data.phone),
    contactMethod: sanitizeString(data.contactMethod || "email"),
    newsletter: Boolean(data.newsletter),
    timestamp: new Date().toISOString(),
  };

  // Check required fields
  const missing = REQUIRED_FIELDS.filter((f) => {
    const val = data[f];
    return val === undefined || val === null || val === "";
  });
  if (missing.length > 0) {
    return res
      .status(400)
      .json({ error: `Missing required fields: ${missing.join(", ")}` });
  }

  if (!sanitizedData.email) {
    return res.status(400).json({ error: "Invalid email address" });
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

  // Use friendly labels for display
  const serviceLabel = SERVICE_LABELS[data.service] || sanitizedData.service;
  const timelineLabel = TIMELINE_LABELS[data.timeline] || sanitizedData.timeline;

  // -- Send to Discord -----------------------------------------------------
  let discordOk = false;
  const discordUrl = process.env.DISCORD_WEBHOOK_QUOTES || process.env.DISCORD_WEBHOOK_URL_ORDER;
  if (discordUrl) {
    const fields = [
      { name: "Service", value: serviceLabel, inline: true },
      { name: "Quantity", value: sanitizedData.quantity.toString(), inline: true },
      { name: "Timeline", value: timelineLabel, inline: true },
      { name: "Customer", value: `${sanitizedData.firstName} ${sanitizedData.lastName}`, inline: false },
      { name: "Contact", value: `${sanitizedData.email}\n${sanitizedData.phone}`, inline: false },
    ];

    if (sanitizedData.dimensions) {
      fields.push({ name: "Dimensions", value: sanitizedData.dimensions, inline: true });
    }
    if (sanitizedData.materials) {
      fields.push({ name: "Material/Color", value: sanitizedData.materials, inline: true });
    }
    if (sanitizedData.budget) {
      fields.push({ name: "Budget", value: sanitizedData.budget, inline: true });
    }
    if (sanitizedData.contactMethod) {
      fields.push({ name: "Preferred Contact", value: sanitizedData.contactMethod, inline: true });
    }
    if (sanitizedData.referral) {
      fields.push({ name: "Referral Source", value: sanitizedData.referral, inline: true });
    }
    if (sanitizedData.newsletter) {
      fields.push({ name: "Newsletter", value: "Yes", inline: true });
    }
    if (sanitizedData.description) {
      fields.push({ name: "Details", value: sanitizedData.description, inline: false });
    }

    const discordPayload = {
      embeds: [
        {
          title: "New Quote Request",
          color: EMBED_COLOR,
          fields,
          timestamp: sanitizedData.timestamp,
          footer: { text: "Poly People Printing Quote System" },
        },
      ],
    };

    try {
      const discordResult = await postJSON(discordUrl, discordPayload);
      if (discordResult.status >= 200 && discordResult.status < 300) {
        discordOk = true;
      } else {
        console.error(
          `Discord webhook failed: ${discordResult.status} — ${discordResult.body}`
        );
      }
    } catch (err) {
      console.error("Discord webhook error:", err.message);
    }
  } else {
    console.error("No Discord webhook URL configured (DISCORD_WEBHOOK_QUOTES or DISCORD_WEBHOOK_URL_ORDER)");
  }

  // -- Send auto-reply email via SendGrid ----------------------------------
  let sendgridOk = false;
  const sendgridKey = process.env.SENDGRID_API_KEY;
  if (sendgridKey) {
    const emailPayload = {
      personalizations: [
        {
          to: [
            {
              email: sanitizedData.email,
              name: `${sanitizedData.firstName} ${sanitizedData.lastName}`,
            },
          ],
          subject: "Quote Request Received - Poly People Printing",
        },
      ],
      from: {
        email: "quotes@polypeopleprinting.com",
        name: "Poly People Printing",
      },
      content: [
        {
          type: "text/html",
          value: generateQuoteConfirmationEmail({
            firstName: sanitizedData.firstName,
            service: serviceLabel,
            quantity: sanitizedData.quantity,
            timeline: timelineLabel,
          }),
        },
      ],
    };

    try {
      const emailResult = await postJSON(
        "https://api.sendgrid.com/v3/mail/send",
        emailPayload,
        { Authorization: `Bearer ${sendgridKey}` }
      );
      if (emailResult.status < 400) {
        sendgridOk = true;
      } else {
        console.error(`SendGrid failed: ${emailResult.status} — ${emailResult.body}`);
      }
    } catch (err) {
      console.error("SendGrid error:", err.message);
    }
  }

  // -- Admin fallback: email when Discord is down --------------------------
  const adminEmail = process.env.ADMIN_EMAIL;
  if (!discordOk && adminEmail && sendgridKey) {
    const adminPayload = {
      personalizations: [
        {
          to: [{ email: adminEmail }],
          subject: `[FALLBACK] New Quote Request from ${sanitizedData.firstName} ${sanitizedData.lastName}`,
        },
      ],
      from: {
        email: "quotes@polypeopleprinting.com",
        name: "PPP System Alert",
      },
      content: [
        {
          type: "text/html",
          value: generateAdminFallbackEmail("Quote Request", sanitizedData, {
            service: serviceLabel,
            timeline: timelineLabel,
          }),
        },
      ],
    };

    try {
      await postJSON(
        "https://api.sendgrid.com/v3/mail/send",
        adminPayload,
        { Authorization: `Bearer ${sendgridKey}` }
      );
    } catch (err) {
      console.error("Admin fallback email error:", err.message);
    }
  }

  // -- Last resort: structured log for Vercel dashboard recovery -----------
  if (!discordOk && !sendgridOk) {
    console.error(
      JSON.stringify({
        _fallback: "SUBMISSION_RECOVERY",
        type: "quote",
        data: sanitizedData,
        serviceLabel,
        timelineLabel,
      })
    );
  }

  // -- Success response ----------------------------------------------------
  return res.status(200).json({
    success: true,
    message: "Quote request received! Check your email for confirmation.",
  });
};
