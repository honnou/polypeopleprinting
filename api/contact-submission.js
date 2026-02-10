const https = require("https");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const MAX_BODY_BYTES = 50_000;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 10;

const EMBED_COLOR = 0x3b82f6; // Blue

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

// ---------------------------------------------------------------------------
// HTTP helper
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
// FAQ detection
// ---------------------------------------------------------------------------
function detectFAQ(message) {
  const faqKeywords = [
    "hours", "open", "closed", "turnaround", "time", "how long",
    "shipping", "ship", "delivery", "pickup",
    "file format", "what format", "types of files",
    "minimum order", "how many", "quantity",
    "pricing", "how much", "cost", "price",
  ];
  const lowerMessage = message.toLowerCase();
  return faqKeywords.some((keyword) => lowerMessage.includes(keyword));
}

// ---------------------------------------------------------------------------
// Email template
// ---------------------------------------------------------------------------
function generateContactConfirmationEmail(data, isFAQ) {
  const faqNote = isFAQ
    ? `<p><strong>Quick Answer:</strong> Your question looks like it might be about our services. While we review your message, check out our <a href="https://polypeopleprinting.com/poly-contact.html">FAQ section</a> for immediate answers!</p>`
    : "";

  return `<!DOCTYPE html>
<html>
<body>
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <h2>Thanks for reaching out, ${data.name}!</h2>
    <p>We've received your message and will get back to you within 24 hours (usually much faster).</p>
    ${faqNote}
    <p>Your message:</p>
    <blockquote style="background: #f0f0f0; padding: 15px; border-left: 4px solid #667eea;">
      ${data.message}
    </blockquote>
    <p>Talk soon!<br>Poly People Printing Team</p>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Admin fallback email template
// ---------------------------------------------------------------------------
function generateAdminFallbackEmail(formType, data) {
  const rows = Object.entries(data)
    .map(([key, val]) => `<tr><td style="padding:6px 12px;font-weight:bold;border:1px solid #ddd;">${key}</td><td style="padding:6px 12px;border:1px solid #ddd;">${val}</td></tr>`)
    .join("");

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

  // -- Sanitize inputs -----------------------------------------------------
  const sanitizedData = {
    name: sanitizeString(data.name),
    email: sanitizeEmail(data.email),
    subject: sanitizeString(data.subject),
    message: sanitizeString(data.message),
    timestamp: new Date().toISOString(),
  };

  // -- Validate required fields --------------------------------------------
  if (!sanitizedData.email) {
    return res.status(400).json({ error: "Valid email address is required" });
  }
  if (!sanitizedData.message) {
    return res.status(400).json({ error: "Message is required" });
  }
  if (!sanitizedData.name) {
    return res.status(400).json({ error: "Name is required" });
  }

  // -- FAQ detection -------------------------------------------------------
  const isFAQ = detectFAQ(sanitizedData.message);

  // -- Send to Discord -----------------------------------------------------
  let discordOk = false;
  const discordUrl = process.env.DISCORD_WEBHOOK_CONTACT;
  if (discordUrl) {
    const discordPayload = {
      embeds: [
        {
          title: isFAQ
            ? "Contact Form (Possible FAQ)"
            : "Contact Form Submission",
          color: EMBED_COLOR,
          fields: [
            { name: "From", value: sanitizedData.name, inline: true },
            { name: "Email", value: sanitizedData.email, inline: true },
            {
              name: "Subject",
              value: sanitizedData.subject || "No subject",
              inline: false,
            },
            { name: "Message", value: sanitizedData.message, inline: false },
          ],
          timestamp: sanitizedData.timestamp,
          footer: { text: "Poly People Printing Contact Form" },
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
    console.error("DISCORD_WEBHOOK_CONTACT is not configured");
  }

  // -- Send auto-reply email via SendGrid ----------------------------------
  let sendgridOk = false;
  const sendgridKey = process.env.SENDGRID_API_KEY;
  if (sendgridKey) {
    const emailPayload = {
      personalizations: [
        {
          to: [{ email: sanitizedData.email, name: sanitizedData.name }],
          subject: "We received your message - Poly People Printing",
        },
      ],
      from: {
        email: "hello@polypeopleprinting.com",
        name: "Poly People Printing",
      },
      content: [
        {
          type: "text/html",
          value: generateContactConfirmationEmail(sanitizedData, isFAQ),
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
          subject: `[FALLBACK] Contact Form from ${sanitizedData.name}`,
        },
      ],
      from: {
        email: "hello@polypeopleprinting.com",
        name: "PPP System Alert",
      },
      content: [
        {
          type: "text/html",
          value: generateAdminFallbackEmail("Contact Form", sanitizedData),
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
        type: "contact",
        data: sanitizedData,
      })
    );
  }

  // -- Success response ----------------------------------------------------
  return res.status(200).json({
    success: true,
    message: "Message sent! We'll respond within 24 hours.",
  });
};
