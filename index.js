import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createBareServer } from "@nebula-services/bare-server-node";
import chalk from "chalk";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import mime from "mime";
import fetch from "node-fetch";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

console.log(chalk.yellow("🚀 Starting server..."));

const __dirname = process.cwd();
const server = http.createServer();
const app = express();
const bareServer = createBareServer("/ca/");
const PORT = process.env.PORT || 8080;
const cache = new Map();
const CACHE_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days

// ---------------- GOOGLE LOGIN SETUP ----------------
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const ALLOWLIST_URL = "https://raw.githubusercontent.com/lowland1/Superspace/refs/heads/main/allowlist.json";

// fetch latest allowlist
async function getAllowlist() {
  try {
    const res = await fetch(ALLOWLIST_URL);
    if (!res.ok) return [];
    const data = await res.json();
    return data.emails || [];
  } catch (err) {
    console.error("Error fetching allowlist:", err);
    return [];
  }
}

app.use(session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

app.use(passport.initialize());
app.use(passport.session());

// ---------------- GOOGLE STRATEGY ----------------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
  const allowlist = await getAllowlist();
  profile.authorized = allowlist.includes(profile.emails[0].value);
  done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ---------------- AUTH ROUTES ----------------
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    if (!req.user.authorized) {
      if (req.session) req.session.destroy(() => {});
      req.logout?.(() => {});
      return res.send(`
        <script>
          alert("You are not authorized.");
          window.location.href = "about:blank";
        </script>
      `);
    }

    req.session.authorized = true;
    res.redirect("/");
  }
);

// ---------------- AUTH MIDDLEWARE ----------------
async function ensureAuth(req, res, next) {
  if (req.path.startsWith("/auth")) return next();

  if (req.isAuthenticated() && req.session?.authorized) {
    return next();
  }

  if (req.session) req.session.destroy(() => {});
  req.logout?.(() => {});
  res.redirect("/auth/google");
}

app.use(ensureAuth);

// ---------------- ASSET ROUTES ----------------
app.get("/e/*", async (req, res, next) => {
  try {
    if (cache.has(req.path)) {
      const { data, contentType, timestamp } = cache.get(req.path);
      if (Date.now() - timestamp > CACHE_TTL) cache.delete(req.path);
      else {
        res.writeHead(200, { "Content-Type": contentType });
        return res.end(data);
      }
    }

    const baseUrls = {
      "/e/1/": "https://raw.githubusercontent.com/qrs/x/fixy/",
      "/e/2/": "https://raw.githubusercontent.com/3v1/V5-Assets/main/",
      "/e/3/": "https://raw.githubusercontent.com/3v1/V5-Retro/master/",
    };

    let reqTarget;
    for (const [prefix, baseUrl] of Object.entries(baseUrls)) {
      if (req.path.startsWith(prefix)) {
        reqTarget = baseUrl + req.path.slice(prefix.length);
        break;
      }
    }

    if (!reqTarget) return next();

    const asset = await fetch(reqTarget);
    if (!asset.ok) return next();

    const data = Buffer.from(await asset.arrayBuffer());
    const ext = path.extname(reqTarget);
    const no = [".unityweb"];
    const contentType = no.includes(ext) ? "application/octet-stream" : mime.getType(ext);

    cache.set(req.path, { data, contentType, timestamp: Date.now() });
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  } catch (error) {
    console.error("Error fetching asset:", error);
    res.setHeader("Content-Type", "text/html");
    res.status(500).send("Error fetching the asset");
  }
});

// ---------------- MIDDLEWARE ----------------
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "static")));
app.use("/ca", cors({ origin: true }));

// ---------------- STATIC ROUTES ----------------
const routes = [
  { path: "/b", file: "apps.html" },
  { path: "/a", file: "games.html" },
  { path: "/play.html", file: "games.html" },
  { path: "/c", file: "settings.html" },
  { path: "/d", file: "tabs.html" },
  { path: "/", file: "index.html" },
];

routes.forEach(route => {
  app.get(route.path, (_req, res) => res.sendFile(path.join(__dirname, "static", route.file)));
});

// ---------------- ERROR HANDLING ----------------
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, "static", "404.html")));
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, "static", "404.html"));
});

// ---------------- SERVER ----------------
server.on("request", (req, res) => {
  if (bareServer.shouldRoute(req)) bareServer.routeRequest(req, res);
  else app(req, res);
});

server.on("upgrade", (req, socket, head) => {
  if (bareServer.shouldRoute(req)) bareServer.routeUpgrade(req, socket, head);
  else socket.end();
});

server.listen({ port: PORT }, () => {
  console.log(chalk.green(`🌍 Server running on http://localhost:${PORT}`));
});
