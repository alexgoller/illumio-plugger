#!/usr/bin/env node
/**
 * my-plugin — Plugger plugin for Illumio PCE.
 *
 * PCE connection details are injected as environment variables:
 *   PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
 */

const http = require("node:http");
const https = require("node:https");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PCE = {
  host: process.env.PCE_HOST,
  port: process.env.PCE_PORT || "8443",
  orgId: process.env.PCE_ORG_ID || "1",
  apiKey: process.env.PCE_API_KEY,
  apiSecret: process.env.PCE_API_SECRET,
};

const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL || "60", 10) * 1000;
const HTTP_PORT = parseInt(process.env.HTTP_PORT || "8080", 10);
const MY_SETTING = process.env.MY_PLUGIN_SETTING || "default-value";

// ---------------------------------------------------------------------------
// PCE API client
// ---------------------------------------------------------------------------

/**
 * Make an authenticated request to the Illumio PCE API.
 * @param {string} method - HTTP method (GET, POST, PUT, DELETE)
 * @param {string} path - API path (e.g., "/workloads")
 * @param {object} [body] - Request body (for POST/PUT)
 * @returns {Promise<{status: number, data: any}>}
 */
function pceRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const fullPath = `/api/v2/orgs/${PCE.orgId}${path}`;
    const auth = Buffer.from(`${PCE.apiKey}:${PCE.apiSecret}`).toString("base64");

    const options = {
      hostname: PCE.host,
      port: parseInt(PCE.port, 10),
      path: fullPath,
      method,
      headers: {
        Authorization: `Basic ${auth}`,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      rejectUnauthorized: process.env.PCE_TLS_SKIP_VERIFY !== "true",
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, data: data ? JSON.parse(data) : null });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });

    req.on("error", reject);
    req.setTimeout(30000, () => {
      req.destroy(new Error("Request timeout"));
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Convenience methods
const pce = {
  get: (path, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return pceRequest("GET", qs ? `${path}?${qs}` : path);
  },
  post: (path, body) => pceRequest("POST", path, body),
  put: (path, body) => pceRequest("PUT", path, body),
  delete: (path) => pceRequest("DELETE", path),
};

// ---------------------------------------------------------------------------
// YOUR PLUGIN LOGIC
// ---------------------------------------------------------------------------

/** State shared between the poller and HTTP handler. */
const state = {
  lastPoll: null,
  pollCount: 0,
  error: null,
  data: null,
};

/**
 * Main plugin logic — called periodically in daemon mode, once in cron mode.
 */
async function doWork() {
  console.log("[INFO] Doing work...");

  // Example: list workloads
  // const { status, data } = await pce.get("/workloads", { max_results: 100 });
  // if (status === 200) {
  //   console.log(`[INFO] Found ${data.length} workloads`);
  //   state.data = { workloads: data.length };
  // }

  // Example: list labels
  // const labels = await pce.get("/labels");
  // console.log(`[INFO] Found ${labels.data.length} labels`);

  // Example: get rulesets
  // const rulesets = await pce.get("/sec_policy/active/rule_sets");

  // TODO: Add your plugin logic here
  state.lastPoll = new Date().toISOString();
  state.pollCount++;
  console.log("[INFO] Work complete.");
}

/**
 * Process a PCE event — called in event mode.
 */
async function handleEvent(event) {
  console.log(`[INFO] Processing event: ${event.event_type}`);

  // Example: react to workload creation
  // if (event.event_type === "workload.create") {
  //   const href = event.resource.href;
  //   console.log(`[INFO] New workload: ${href}`);
  // }

  // TODO: Add your event handling logic here
  console.log("[INFO] Event processed.");
}

// ---------------------------------------------------------------------------
// HTTP server (health check + dashboard)
// ---------------------------------------------------------------------------

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>My Plugin</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{700:'#313244',800:'#1e1e2e',900:'#11111b'}}}}}
</script>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen">
<div class="max-w-4xl mx-auto px-4 py-8">
  <h1 class="text-2xl font-bold text-white mb-6">My Plugin</h1>

  <div class="grid grid-cols-2 gap-4 mb-8">
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-polls" class="text-3xl font-bold text-blue-400">—</div>
      <div class="text-sm text-gray-400 mt-1">Poll Cycles</div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <div id="stat-last" class="text-3xl font-bold text-green-400">—</div>
      <div class="text-sm text-gray-400 mt-1">Last Poll</div>
    </div>
  </div>

  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <h2 class="text-white font-semibold mb-3">State</h2>
    <pre id="state-json" class="text-sm text-gray-300 font-mono whitespace-pre-wrap">Loading...</pre>
  </div>
</div>
<script>
const BASE=(()=>{const m=window.location.pathname.match(/^\\/plugins\\/[^/]+\\/ui/);return m?m[0]:''})();
async function fetchData(){
  try{
    const resp=await fetch(BASE+'/api/state');
    const d=await resp.json();
    document.getElementById('stat-polls').textContent=d.pollCount||0;
    const ago=d.lastPoll?Math.round((Date.now()-new Date(d.lastPoll).getTime())/1000)+'s ago':'never';
    document.getElementById('stat-last').textContent=ago;
    document.getElementById('state-json').textContent=JSON.stringify(d,null,2);
  }catch(e){
    document.getElementById('state-json').textContent='Error: '+e;
  }
}
fetchData();
setInterval(fetchData,10000);
</script>
</body>
</html>`;

function startServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");

    if (req.method === "GET" && path === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "healthy" }));
    } else if (req.method === "GET" && path === "/api/state") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(state));
    } else if (req.method === "GET" && (path === "/" || path === "")) {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(DASHBOARD_HTML);
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    }
  });

  server.listen(HTTP_PORT, "0.0.0.0", () => {
    console.log(`[INFO] Dashboard listening on http://0.0.0.0:${HTTP_PORT}`);
  });

  return server;
}

// ---------------------------------------------------------------------------
// Runtime modes
// ---------------------------------------------------------------------------

async function runDaemon() {
  console.log(`[INFO] Running in daemon mode (interval=${POLL_INTERVAL / 1000}s)`);
  const server = startServer();

  const poll = async () => {
    try {
      await doWork();
    } catch (err) {
      console.error("[ERROR] Work cycle failed:", err.message);
      state.error = err.message;
    }
  };

  // First poll immediately
  await poll();
  const timer = setInterval(poll, POLL_INTERVAL);

  // Graceful shutdown
  const shutdown = () => {
    console.log("[INFO] Shutting down...");
    clearInterval(timer);
    server.close(() => {
      console.log("[INFO] Plugin stopped.");
      process.exit(0);
    });
    // Force exit after 10s
    setTimeout(() => process.exit(0), 10000);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

async function runCron() {
  console.log("[INFO] Running in cron mode");
  try {
    await doWork();
  } catch (err) {
    console.error("[ERROR] Cron run failed:", err.message);
    process.exit(1);
  }
  console.log("[INFO] Done.");
  process.exit(0);
}

async function runEvent() {
  const payload = process.env.PLUGGER_EVENT_PAYLOAD;
  if (!payload) {
    console.error("[ERROR] No event payload (PLUGGER_EVENT_PAYLOAD is empty)");
    process.exit(1);
  }
  try {
    const event = JSON.parse(payload);
    await handleEvent(event);
  } catch (err) {
    console.error("[ERROR] Event processing failed:", err.message);
    process.exit(1);
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("[INFO] Starting my-plugin...");
  console.log(`[INFO] PCE: ${PCE.host}:${PCE.port} (org ${PCE.orgId})`);
  console.log(`[INFO] MY_PLUGIN_SETTING=${MY_SETTING}`);

  const mode = process.env.PLUGIN_MODE || "daemon";
  switch (mode) {
    case "cron":
      await runCron();
      break;
    case "event":
      await runEvent();
      break;
    default:
      await runDaemon();
  }
}

main().catch((err) => {
  console.error("[FATAL]", err);
  process.exit(1);
});
