/**
 * Mrigmareecha - Node.js HTTP Server
 * Entry point for the backend API server
 */

const http = require("http");

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "localhost";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Parse the request body as JSON.
 * @param {http.IncomingMessage} req
 * @returns {Promise<object>}
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

/**
 * Send a JSON response.
 * @param {http.ServerResponse} res
 * @param {number} statusCode
 * @param {object} data
 */
function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(body);
}

// ─── Router ───────────────────────────────────────────────────────────────────

/** Simple route registry: { "METHOD /path": handlerFn } */
const routes = {};

function register(method, path, handler) {
  routes[`${method.toUpperCase()} ${path}`] = handler;
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

register("GET", "/", async (_req, res) => {
  sendJSON(res, 200, {
    message: "Welcome to the Mrigmareecha API 🚀",
    version: "1.0.0",
    status: "healthy",
  });
});

register("GET", "/api/health", async (_req, res) => {
  sendJSON(res, 200, {
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

register("GET", "/api/hello", async (_req, res) => {
  sendJSON(res, 200, { message: "Hello from the Mrigmareecha backend!" });
});

// ─── Request Handler ──────────────────────────────────────────────────────────

async function requestHandler(req, res) {
  const { method, url } = req;

  // Handle CORS preflight
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    return res.end();
  }

  // Strip query string for routing
  const path = url.split("?")[0];
  const key = `${method} ${path}`;

  const handler = routes[key];

  if (!handler) {
    return sendJSON(res, 404, { error: "Route not found", path, method });
  }

  try {
    await handler(req, res);
  } catch (err) {
    console.error(`[ERROR] ${method} ${url}:`, err.message);
    sendJSON(res, 500, { error: "Internal server error", details: err.message });
  }
}

// ─── Server ───────────────────────────────────────────────────────────────────

const server = http.createServer(requestHandler);

server.listen(PORT, HOST, () => {
  console.log(`\n🚀  Mrigmareecha Backend running at http://${HOST}:${PORT}`);
  console.log(`   Health check → http://${HOST}:${PORT}/api/health`);
  console.log(`   Press Ctrl+C to stop.\n`);
});

server.on("error", (err) => {
  console.error("Server error:", err.message);
  process.exit(1);
});

module.exports = server;
