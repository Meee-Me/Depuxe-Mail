import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const DOMAIN = "deluxemail.com";
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const users = () => getStore("users");
const sessions = () => getStore("sessions");
const mail = () => getStore("mail");

const validName = (n) => /^[a-z0-9._-]{3,30}$/.test(n);
const clean = (s, max) => String(s ?? "").slice(0, max);

function hashPassword(pw, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return { salt, hash };
}
function checkPassword(pw, { salt, hash }) {
  const test = crypto.scryptSync(pw, salt, 64);
  return crypto.timingSafeEqual(test, Buffer.from(hash, "hex"));
}

async function auth(req) {
  const h = req.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return null;
  const s = await sessions().get(token, { type: "json" });
  if (!s || s.expires < Date.now()) return null;
  return s.username;
}

async function deliver(username, folder, msg) {
  const id = crypto.randomUUID();
  // reverse timestamp so newest sorts first on list()
  const rev = String(9999999999999 - Date.now()).padStart(13, "0");
  const key = `${username}/${folder}/${rev}-${id}`;
  await mail().setJSON(key, { id, key, folder, date: Date.now(), read: folder === "sent", ...msg });
  return key;
}

async function sendExternal(from, to, subject, body) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return { ok: false, error: "Sending to outside addresses isn't configured yet (set RESEND_API_KEY)." };
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject, text: body }),
  });
  if (!r.ok) return { ok: false, error: "Outside delivery failed: " + (await r.text()).slice(0, 200) };
  return { ok: true };
}

export default async (req) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\//, "").replace(/\/$/, "");
  const method = req.method;

  try {
    // ---------- Sign up ----------
    if (route === "signup" && method === "POST") {
      const b = await req.json();
      const username = clean(b.username, 30).toLowerCase().trim();
      const password = clean(b.password, 200);
      const displayName = clean(b.displayName || username, 60).trim();
      if (!validName(username))
        return json({ error: "Name must be 3–30 characters: letters, numbers, dot, dash or underscore." }, 400);
      if (password.length < 8) return json({ error: "Password must be at least 8 characters." }, 400);
      if (await users().get(username)) return json({ error: "That name is already taken." }, 409);

      await users().setJSON(username, { username, displayName, ...hashPassword(password), created: Date.now() });
      await deliver(username, "inbox", {
        from: `Deluxe Mail <welcome@${DOMAIN}>`,
        to: `${username}@${DOMAIN}`,
        subject: "Welcome to Deluxe Mail ✦",
        body: `Hi ${displayName},\n\nYour deluxe address is ${username}@${DOMAIN}.\nShare it with anyone – messages land right here.\n\n— The Deluxe Mail team`,
      });
      return json({ ok: true, address: `${username}@${DOMAIN}` });
    }

    // ---------- Log in ----------
    if (route === "login" && method === "POST") {
      const b = await req.json();
      const username = clean(b.username, 60).toLowerCase().trim().replace(`@${DOMAIN}`, "");
      const u = await users().get(username, { type: "json" });
      if (!u || !checkPassword(clean(b.password, 200), u)) return json({ error: "Wrong name or password." }, 401);
      const token = crypto.randomBytes(32).toString("hex");
      await sessions().setJSON(token, { username, expires: Date.now() + 30 * 864e5 });
      return json({ token, address: `${username}@${DOMAIN}`, displayName: u.displayName });
    }

    // ---------- Inbound mail webhook (Postmark/Mailgun-style JSON) ----------
    if (route === "inbound" && method === "POST") {
      if (!process.env.INBOUND_SECRET || url.searchParams.get("key") !== process.env.INBOUND_SECRET)
        return json({ error: "Forbidden" }, 403);
      const b = await req.json();
      const toRaw = clean(b.OriginalRecipient || b.To || b.to || b.recipient, 300).toLowerCase();
      const m = toRaw.match(/([a-z0-9._-]+)@deluxemail\.com/);
      if (!m) return json({ error: "No deluxemail recipient" }, 200);
      if (!(await users().get(m[1]))) return json({ error: "Unknown user" }, 200);
      await deliver(m[1], "inbox", {
        from: clean(b.From || b.from || b.sender, 300),
        to: `${m[1]}@${DOMAIN}`,
        subject: clean(b.Subject || b.subject || "(no subject)", 300),
        body: clean(b.TextBody || b["body-plain"] || b.text || "", 50000),
      });
      return json({ ok: true });
    }

    // ---------- Everything below needs a login ----------
    const me = await auth(req);
    if (!me) return json({ error: "Please log in." }, 401);

    if (route === "list" && method === "GET") {
      const folder = url.searchParams.get("folder") === "sent" ? "sent" : "inbox";
      const { blobs } = await mail().list({ prefix: `${me}/${folder}/` });
      const items = await Promise.all(blobs.slice(0, 100).map((x) => mail().get(x.key, { type: "json" })));
      return json({ messages: items.filter(Boolean).map(({ body, ...rest }) => ({ ...rest, preview: body.slice(0, 90) })) });
    }

    if (route === "message" && method === "GET") {
      const key = url.searchParams.get("key") || "";
      if (!key.startsWith(`${me}/`)) return json({ error: "Not found" }, 404);
      const msg = await mail().get(key, { type: "json" });
      if (!msg) return json({ error: "Not found" }, 404);
      if (!msg.read) await mail().setJSON(key, { ...msg, read: true });
      return json(msg);
    }

    if (route === "delete" && method === "POST") {
      const { key } = await req.json();
      if (!String(key).startsWith(`${me}/`)) return json({ error: "Not found" }, 404);
      await mail().delete(key);
      return json({ ok: true });
    }

    if (route === "send" && method === "POST") {
      const b = await req.json();
      const to = clean(b.to, 200).toLowerCase().trim();
      const subject = clean(b.subject || "(no subject)", 300);
      const body = clean(b.body, 50000);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return json({ error: "Enter a valid recipient address." }, 400);
      const from = `${me}@${DOMAIN}`;
      const u = await users().get(me, { type: "json" });

      if (to.endsWith(`@${DOMAIN}`)) {
        const rcpt = to.split("@")[0];
        if (!(await users().get(rcpt))) return json({ error: "No Deluxe Mail account with that name." }, 404);
        await deliver(rcpt, "inbox", { from: `${u.displayName} <${from}>`, to, subject, body });
      } else {
        const r = await sendExternal(`${u.displayName} <${from}>`, to, subject, body);
        if (!r.ok) return json({ error: r.error }, 501);
      }
      await deliver(me, "sent", { from, to, subject, body });
      return json({ ok: true });
    }

    return json({ error: "Not found" }, 404);
  } catch (e) {
    return json({ error: "Server error: " + e.message }, 500);
  }
};
