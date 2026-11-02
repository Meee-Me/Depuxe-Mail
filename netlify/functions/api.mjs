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

// ---------- Gmail (read-only, per-user OAuth) ----------
const gStore = () => getStore("gmail");
const oauthStore = () => getStore("oauth");
const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const gConfigured = () =>
  !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.TOKEN_ENC_KEY);
const encKey = () => crypto.createHash("sha256").update(String(process.env.TOKEN_ENC_KEY)).digest();
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", encKey(), iv);
  const data = Buffer.concat([c.update(text, "utf8"), c.final()]);
  return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") };
}
function decrypt(o) {
  const d = crypto.createDecipheriv("aes-256-gcm", encKey(), Buffer.from(o.iv, "base64"));
  d.setAuthTag(Buffer.from(o.tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(o.data, "base64")), d.final()]).toString("utf8");
}
async function gAccessToken(username) {
  const rec = await gStore().get(username, { type: "json" });
  if (!rec) return null;
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      refresh_token: decrypt(rec.token),
      grant_type: "refresh_token",
    }),
  });
  if (!r.ok) return null;
  return (await r.json()).access_token;
}
async function gGet(at, path) {
  const r = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/" + path, {
    headers: { Authorization: "Bearer " + at },
  });
  if (!r.ok) throw new Error("Gmail error " + r.status);
  return r.json();
}
const hdr = (p, n) => ((p && p.headers) || []).find((h) => h.name.toLowerCase() === n)?.value || "";
const dec = (s) =>
  String(s || "").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const b64u = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
function gBody(payload) {
  let plain = "", html = "";
  (function walk(p) {
    if (!p) return;
    if (p.mimeType === "text/plain" && p.body?.data) plain += b64u(p.body.data);
    else if (p.mimeType === "text/html" && p.body?.data) html += b64u(p.body.data);
    (p.parts || []).forEach(walk);
  })(payload);
  if (plain) return plain;
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
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
      if (!u || u.google || !checkPassword(clean(b.password, 200), u)) return json({ error: "Wrong name or password." }, 401);
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

    // ---------- Sign in with Google (Gmail-only, no Deluxe account) ----------
    if (route === "google/start" && method === "POST") {
      if (!gConfigured()) return json({ error: "Google sign-in isn't set up on this site yet." }, 501);
      const st = crypto.randomBytes(24).toString("hex");
      const redirect = process.env.GOOGLE_REDIRECT_URI || `${url.origin}/api/gmail/callback`;
      await oauthStore().setJSON(st, { mode: "login", redirect, expires: Date.now() + 10 * 60 * 1000 });
      const q = new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        redirect_uri: redirect,
        response_type: "code",
        scope: GMAIL_SCOPE,
        access_type: "offline",
        prompt: "consent",
        state: st,
      });
      return json({ url: "https://accounts.google.com/o/oauth2/v2/auth?" + q });
    }

    // ---------- Gmail OAuth callback (browser redirect from Google, no login header) ----------
    if (route === "gmail/callback" && method === "GET") {
      const st = url.searchParams.get("state"), code = url.searchParams.get("code");
      const back = (r) => new Response(null, { status: 302, headers: { Location: "/?gmail=" + r } });
      if (!gConfigured() || !st || !code) return back("error");
      const rec = await oauthStore().get(st, { type: "json" });
      if (rec) await oauthStore().delete(st);
      if (!rec || rec.expires < Date.now()) return back("error");
      const tr = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: rec.redirect,
          grant_type: "authorization_code",
        }),
      });
      if (!tr.ok) return back("error");
      const tok = await tr.json();
      if (!tok.refresh_token) return back("error");
      const prof = await gGet(tok.access_token, "profile");
      if (rec.mode === "login") {
        // Gmail-only account. The ":" can never appear in a normal username, so nobody can pre-register this id.
        const gid = "google:" + crypto.createHash("sha256").update(String(prof.emailAddress).toLowerCase()).digest("hex").slice(0, 24);
        const existing = await users().get(gid, { type: "json" });
        if (!existing) await users().setJSON(gid, { username: gid, displayName: prof.emailAddress, google: true, email: prof.emailAddress, created: Date.now() });
        await gStore().setJSON(gid, { email: prof.emailAddress, token: encrypt(tok.refresh_token), connected: Date.now() });
        const sess = crypto.randomBytes(32).toString("hex");
        await sessions().setJSON(sess, { username: gid, expires: Date.now() + 30 * 864e5 });
        const frag = new URLSearchParams({ gtoken: sess, gaddr: prof.emailAddress, gname: prof.emailAddress });
        return new Response(null, { status: 302, headers: { Location: "/#" + frag } });
      }
      await gStore().setJSON(rec.username, { email: prof.emailAddress, token: encrypt(tok.refresh_token), connected: Date.now() });
      return back("connected");
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
      const u = await users().get(me, { type: "json" });
      if (u?.google) return json({ error: "Gmail-only accounts can read mail but not send. Create a Deluxe account to send." }, 403);
      const from = `${me}@${DOMAIN}`;

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

    // ---------- Gmail (logged-in users) ----------
    if (route === "gmail/status" && method === "GET") {
      const rec = await gStore().get(me, { type: "json" });
      return json({ configured: gConfigured(), connected: !!rec, email: rec?.email || null });
    }
    if (route === "gmail/start" && method === "POST") {
      if (!gConfigured()) return json({ error: "Gmail isn't set up on this site yet." }, 501);
      const st = crypto.randomBytes(24).toString("hex");
      const redirect = process.env.GOOGLE_REDIRECT_URI || `${url.origin}/api/gmail/callback`;
      await oauthStore().setJSON(st, { username: me, redirect, expires: Date.now() + 10 * 60 * 1000 });
      const q = new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        redirect_uri: redirect,
        response_type: "code",
        scope: GMAIL_SCOPE,
        access_type: "offline",
        prompt: "consent",
        state: st,
      });
      return json({ url: "https://accounts.google.com/o/oauth2/v2/auth?" + q });
    }
    if (route === "gmail/disconnect" && method === "POST") {
      const rec = await gStore().get(me, { type: "json" });
      if (rec) {
        try {
          await fetch("https://oauth2.googleapis.com/revoke?token=" + encodeURIComponent(decrypt(rec.token)), { method: "POST" });
        } catch (e) { /* best effort */ }
        await gStore().delete(me);
      }
      return json({ ok: true });
    }
    if (route === "gmail/list" && method === "GET") {
      const at = await gAccessToken(me);
      if (!at) return json({ error: "Gmail connection expired. Please reconnect Gmail." }, 409);
      const l = await gGet(at, "messages?maxResults=25&labelIds=INBOX");
      const msgs = await Promise.all(
        (l.messages || []).map((m) =>
          gGet(at, `messages/${m.id}?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject`)
        )
      );
      return json({
        messages: msgs.map((m) => ({
          id: m.id,
          from: hdr(m.payload, "from"),
          to: hdr(m.payload, "to"),
          subject: hdr(m.payload, "subject") || "(no subject)",
          preview: dec(m.snippet),
          date: Number(m.internalDate),
          read: !(m.labelIds || []).includes("UNREAD"),
        })),
      });
    }
    if (route === "gmail/message" && method === "GET") {
      const id = url.searchParams.get("id") || "";
      if (!/^[a-zA-Z0-9]+$/.test(id)) return json({ error: "Not found" }, 404);
      const at = await gAccessToken(me);
      if (!at) return json({ error: "Gmail connection expired. Please reconnect Gmail." }, 409);
      const m = await gGet(at, `messages/${id}?format=full`);
      return json({
        id: m.id,
        from: hdr(m.payload, "from"),
        to: hdr(m.payload, "to"),
        subject: hdr(m.payload, "subject") || "(no subject)",
        date: Number(m.internalDate),
        body: gBody(m.payload).slice(0, 50000) || dec(m.snippet),
      });
    }

    return json({ error: "Not found" }, 404);
  } catch (e) {
    return json({ error: "Server error: " + e.message }, 500);
  }
};
