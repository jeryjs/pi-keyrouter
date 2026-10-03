#!/usr/bin/env node
// =============================================================================
// fake-openai-server.mjs — scriptable OpenAI-compatible endpoint for testing
// pi-keyrouter / cx-providers behavior offline.
// =============================================================================
//
// Implements `POST /v1/chat/completions` (SSE streaming, like pi always uses)
// and lets you *plan* exactly what each request should do: status code, error
// body shape, latency, dropped stream, etc. Every request is logged together
// with the `Authorization` header it arrived with, which is how you verify that
// keyrouter actually swapped keys between retries.
//
//   node fake-openai-server.mjs [--port 8787] [--host 127.0.0.1] [--quiet]
//   node fake-openai-server.mjs --selftest        # exercise own plan engine
//
// Then in cx-providers (~/.pi/cx/providers.json) add a provider like:
//   {
//     "id": "krtest",
//     "name": "KR Test",
//     "baseUrl": "http://127.0.0.1:8787/v1",
//     "api": "openai-completions",
//     "apiKey": "sk-a",            # pi sends this as Bearer unless overridden
//     "models": [{ "id": "fake-gpt", "name": "Fake GPT", "reasoning": false,
//                  "input": ["text"], "cost": { "input": 0, "output": 0,
//                  "cacheRead": 0, "cacheWrite": 0 },
//                  "contextWindow": 128000, "maxTokens": 1024 }]
//   }
// and in ~/.pi/keyrouter.json:
//   { "providers": [{ "name": "krtest",
//       "keys": [{ "name": "A", "value": "sk-a" }, { "name": "B", "value": "sk-b" }] }] }
//
// ---------------------------------------------------------------------------
// CONTROL API (all JSON)
// ---------------------------------------------------------------------------
// GET    /__admin/health      -> { ok: true, build, requests: N }
// GET    /__admin/state       -> { plan, cursor, log }
// POST   /__admin/reset       -> clears log + plan
// POST   /__admin/plan        -> install a plan (see below)
// GET    /__admin/log         -> request log only
//
// Plan shape (every field optional):
// {
//   "sequence": [ 429, 401, { "status": 500, "attempts": 2 }, "ok" ],
//   "byKey":    { "sk-a": { "status": 429 }, "sk-b": "ok" },
//   "default":  "ok",
//   "text":     "pong",
//   "repeatLast": true
// }
//   sequence   per-request steps, consumed in order by request number.
//   byKey      matched on the bearer token; OVERRIDES sequence. Use it to test
//              "key A is rate-limited, key B works".
//   default    step used once sequence is exhausted (or immediately if empty).
//   repeatLast when true, the last sequence step repeats forever instead of
//              falling back to default.
//   text       completion text for successful responses.
//
// A step is either a bare status number, "ok"/"error" shorthand, or an object:
//   { "status": 429, "attempts": 2, "delayMs": 1500,
//     "type": "rate_limit_error", "code": "rate_limit_exceeded",
//     "message": "Rate limit reached for gpt. Please slow down.",
//     "retryAfter": 1, "hang": false, "closeEarly": false,
//     "badJson": false, "text": "pong", "headers": { "x-test": "1" } }
//
// Presets cover what pi-keyrouter classifies differently:
//   429 rate_limit / 401 invalid_api_key / 403 bad auth / 402 insufficient_quota
//   (NON-rotatable AND non-retryable in pi) / 529 overloaded_error / 500 / 503
//   418 teapot (rotatable? no: unmatched -> ignored) / "hang" / "closeEarly"
//
// ---------------------------------------------------------------------------
// WHAT pi DOES WITH EACH OF THESE (verified against pi 1.0.0 sources)
// ---------------------------------------------------------------------------
// * Non-2xx: the openai SDK throws, so pi's `onResponse` hook never runs and
//   `after_provider_response` does NOT fire. keyrouter must therefore not rely
//   on it for failures — only for clearing cooldowns on success.
// * errorMessage seen by `message_end` contains the status number and the JSON
//   body, so keyrouter's regexes match on `"429"`, `rate.?limit`, `"40[13]"`.
// * pi retries only when `isRetryableAssistantError()` matches AND the text is
//   not quota/billing. "insufficient_quota"/"quota exceeded" => pi gives up.

import { createServer } from "node:http";

// Reported by /__admin/health so a runner can refuse a stale server build.
const SERVER_BUILD = "kr-fake-v2";

const PRESETS = {
	429: {
		status: 429,
		type: "rate_limit_error",
		code: "rate_limit_exceeded",
		message: "Rate limit reached for model fake-gpt. Please slow down.",
		retryAfter: 1,
	},
	401: {
		status: 401,
		type: "invalid_request_error",
		code: "invalid_api_key",
		message: "Incorrect API key provided: sk-a. You can find your API keys at https://platform.openai.com/account/api-keys.",
	},
	403: {
		status: 403,
		type: "access_denied",
		code: "access_denied",
		message: "Access denied for this key (403 forbidden).",
	},
	402: {
		status: 402,
		type: "insufficient_quota",
		code: "insufficient_quota",
		message: "You exceeded your current quota, quota exceeded, please check your plan and billing details.",
	},
	529: {
		status: 529,
		type: "overloaded_error",
		code: "overloaded",
		message: "Overloaded: the service is temporarily overloaded.",
		retryAfter: 1,
	},
	500: { status: 500, type: "server_error", code: "internal_error", message: "The server had an internal error (500)." },
	503: { status: 503, type: "server_error", code: "service_unavailable", message: "The server is currently unavailable (503 service_error)." },
	418: { status: 418, type: "teapot", code: "i_am_a_teapot", message: "I am a teapot." },
	200: { status: 200 },
};

const SHELL = {
	ok: { status: 200 },
	success: { status: 200 },
	error: { status: 429 },
	ratelimit: { status: 429 },
	"rate-limit": { status: 429 },
	unauthorized: { status: 401 },
	overloaded: { status: 529 },
	quota: { status: 402 },
	hang: { status: 200, hang: true },
	drop: { status: 200, closeEarly: true },
	badJson: { status: 200, badJson: true },
};

function normalizeStep(step) {
	if (step === null || step === undefined) return { ...PRESETS[200] };
	if (typeof step === "number") return { ...(PRESETS[step] ?? { status: step, message: `status ${step}` }) };
	if (typeof step === "string") {
		// Exact case first (camelCase shorthands like `badJson`), then lowercased.
		const preset =
			SHELL[step] ??
			SHELL[step.toLowerCase()] ??
			(/^\d{3}$/.test(step) ? PRESETS[step] ?? { status: Number(step) } : undefined);
		if (!preset) throw new Error(`unknown step shorthand "${step}"`);
		return { ...preset };
	}
	if (typeof step !== "object") throw new Error(`step must be number, string, or object`);
	const base = typeof step.status === "number" ? { ...(PRESETS[step.status] ?? {}), ...step } : { ...step };
	if (typeof base.status !== "number") base.status = 200;
	if (base.attempts === undefined) base.attempts = 1;
	return base;
}

function emptyPlan() {
	return {
		sequence: [],
		byKey: {},
		default: { status: 200 },
		text: "pong",
		repeatLast: false,
	};
}

function normalizePlan(input = {}) {
	if (typeof input === "number" || typeof input === "string") input = { sequence: [input] };
	if (Array.isArray(input)) input = { sequence: input };
	const plan = emptyPlan();
	plan.sequence = (Array.isArray(input.sequence) ? input.sequence : []).map(normalizeStep);
	plan.byKey = {};
	for (const [key, step] of Object.entries(input.byKey ?? {})) plan.byKey[key] = normalizeStep(step);
	plan.default = normalizeStep(input.default ?? { status: 200 });
	if (typeof input.text === "string") plan.text = input.text;
	plan.repeatLast = Boolean(input.repeatLast);
	return plan;
}

const state = {
	plan: normalizePlan({}),
	cursor: 0,
	requests: 0,
	log: [],
	installedAt: Date.now(),
};

/** Steps come from sequence (with attempts expansion), else byKey, else default. */
function stepFor(bearer) {
	const byKey = state.plan.byKey[bearer];
	const seq = state.plan.sequence;
	if (seq.length > 0) {
		const expanded = [];
		for (const step of seq) for (let i = 0; i < Math.max(1, step.attempts ?? 1); i++) expanded.push(step);
		if (state.cursor < expanded.length) {
			const step = expanded[state.cursor];
			state.cursor += 1;
			// byKey still wins on the status so you can pin a key's fate.
			return byKey ? { ...step, ...byKey } : step;
		}
		if (state.plan.repeatLast) {
			const last = expanded[expanded.length - 1];
			if (last) return byKey ? { ...last, ...byKey } : last;
		}
	}
	if (byKey) return byKey;
	return state.plan.default;
}

function bearerOf(req) {
	const header = req.headers["authorization"] ?? "";
	const match = /^Bearer\s+(.*)$/i.exec(header);
	return (match ? match[1] : header).trim();
}

function errorBody(step, model) {
	const message = step.message ?? `HTTP ${step.status}`;
	return {
		error: {
			message,
			type: step.type ?? "error",
			param: step.param ?? null,
			code: step.code ?? null,
			model,
		},
	};
}

function sendJson(res, status, value, extraHeaders = {}) {
	const body = JSON.stringify(value);
	res.writeHead(status, {
		"content-type": "application/json",
		"content-length": Buffer.byteLength(body),
		...extraHeaders,
	});
	res.end(body);
}

function chunk(id, model, delta, finishReason, usage) {
	const payload = {
		id,
		object: "chat.completion.chunk",
		created: Math.floor(Date.now() / 1000),
		model,
		choices: delta === undefined && finishReason === null ? [] : [{ index: 0, delta, finish_reason: finishReason }],
	};
	if (usage) payload.usage = usage;
	return `data: ${JSON.stringify(payload)}\n\n`;
}

async function streamCompletion(res, model, text) {
	const id = `chatcmpl-fake-${Date.now().toString(36)}`;
	res.writeHead(200, {
		"content-type": "text/event-stream",
		"cache-control": "no-cache",
		connection: "keep-alive",
		"x-accel-buffering": "no",
	});
	res.write(chunk(id, model, { role: "assistant", content: "" }, null));
	// Two deltas, so a mid-stream abort is observable.
	res.write(chunk(id, model, { content: text }, null));
	res.write(chunk(id, model, {}, "stop"));
	res.write(
		chunk(id, model, undefined, null, {
			prompt_tokens: 12,
			completion_tokens: Math.max(1, text.length),
			total_tokens: 12 + text.length,
		}),
	);
	res.write("data: [DONE]\n\n");
	res.end();
}

async function readBody(req) {
	const chunks = [];
	for await (const part of req) chunks.push(part);
	if (chunks.length === 0) return {};
	const raw = Buffer.concat(chunks).toString("utf8");
	try {
		return raw ? JSON.parse(raw) : {};
	} catch {
		return { __parseError: raw.slice(0, 400) };
	}
}

function record(entry) {
	state.requests += 1;
	state.log.push({ n: state.requests, at: new Date().toISOString(), ...entry });
	if (state.log.length > 500) state.log.shift();
	return entry.n;
}

const HOST_DEFAULT = "127.0.0.1";
const PORT_DEFAULT = 8787;

function parseArgs(argv) {
	const out = { port: PORT_DEFAULT, host: HOST_DEFAULT, quiet: false, selftest: false, plan: null };
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === "--port") out.port = Number(argv[++i]);
		else if (a === "--host") out.host = argv[++i];
		else if (a === "--quiet") out.quiet = true;
		else if (a === "--selftest") out.selftest = true;
		else if (a === "--plan") out.plan = JSON.parse(argv[++i]);
		else if (a === "--help" || a === "-h") out.help = true;
	}
	return out;
}

const server = createServer(async (req, res) => {
	const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
	const path = url.pathname;

	// ---------------- control ----------------
	if (path === "/__admin/health") return sendJson(res, 200, { ok: true, build: SERVER_BUILD, requests: state.requests });
	if (path === "/__admin/state") return sendJson(res, 200, { plan: state.plan, cursor: state.cursor, requests: state.requests, log: state.log });
	if (path === "/__admin/log") return sendJson(res, 200, { requests: state.requests, log: state.log });
	if (path === "/__admin/reset" && req.method === "POST") {
		state.plan = normalizePlan({});
		state.cursor = 0;
		state.log = [];
		state.requests = 0;
		return sendJson(res, 200, { ok: true });
	}
	if (path === "/__admin/plan" && req.method === "POST") {
		try {
			const body = await readBody(req);
			if (body.__parseError) return sendJson(res, 400, { error: { message: "invalid JSON plan" } });
			state.plan = normalizePlan(body);
			state.cursor = 0;
			return sendJson(res, 200, { ok: true, plan: state.plan });
		} catch (error) {
			return sendJson(res, 400, { error: { message: error instanceof Error ? error.message : String(error) } });
		}
	}
	if (path === "/v1/models") {
		return sendJson(res, 200, {
			object: "list",
			data: [{ id: "fake-gpt", object: "model", created: 0, owned_by: "krtest" }],
		});
	}

	// ---------------- inference ----------------
	if (path.endsWith("/chat/completions")) {
		const key = bearerOf(req);
		const body = await readBody(req);
		const model = typeof body.model === "string" ? body.model : "unknown";
		const wantsStream = body.stream === true;
		const step = stepFor(key);
		const n = record({
			path,
			key,
			model,
			stream: wantsStream,
			status: step.status,
			note: step.hang ? "hang" : step.closeEarly ? "closeEarly" : step.badJson ? "badJson" : undefined,
		});
		if (!opt.quiet) {
			console.log(`#${n} ${key ? `key=${redactKey(key)}` : "key=<none>"} model=${model} -> ${step.status}${step.hang ? " (hang)" : step.closeEarly ? " (drop stream)" : ""}`);
		}

		if (step.delayMs) await sleep(step.delayMs);

		if (step.status >= 300) {
			const headers = { ...(step.headers ?? {}) };
			if (step.retryAfter !== undefined) headers["retry-after"] = String(step.retryAfter);
			if (wantsStream) {
				// Some gateways only fail mid-stream. Keep it JSON for the SDK to see.
				return sendJson(res, step.status, errorBody(step, model), headers);
			}
			return sendJson(res, step.status, errorBody(step, model), headers);
		}

		if (step.hang) {
			// Never respond: exercises request timeout / abort paths.
			res.writeHead(200, { "content-type": "text/event-stream" });
			res.write(": keep-alive\n\n");
			return; // intentionally leave the request open
		}

		if (!wantsStream) {
			const text = step.text ?? state.plan.text;
			return sendJson(res, 200, {
				id: `chatcmpl-fake-${n}`,
				object: "chat.completion",
				created: Math.floor(Date.now() / 1000),
				model,
				choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
				usage: { prompt_tokens: 12, completion_tokens: text.length, total_tokens: 12 + text.length },
			});
		}

		if (step.closeEarly) {
			// Headers say 200, then the stream dies with no finish_reason:
			// pi reports "Stream ended without finish_reason" (NOT a rotatable error).
			const id = `chatcmpl-fake-${n}`;
			res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
			res.write(chunk(id, model, { role: "assistant", content: "" }, null));
			res.write(chunk(id, model, { content: "partial" }, null));
			res.destroy();
			return;
		}

		if (step.badJson) {
			res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
			res.write("data: {not json\n\n");
			res.end();
			return;
		}

		return streamCompletion(res, model, step.text ?? state.plan.text);
	}

	if (path === "/" ) return sendJson(res, 200, { ok: true, usage: "see file header" });
	return sendJson(res, 404, { error: { message: `no route ${path}` } });
});

function redactKey(key) {
	// Show enough to distinguish pool keys without dumping full secrets to stdout.
	return key.length <= 10 ? key : `${key.slice(0, 6)}…${key.slice(-3)}`;
}

function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

const opt = parseArgs(process.argv.slice(2));

if (opt.help) {
	console.log("usage: node fake-openai-server.mjs [--port 8787] [--host 127.0.0.1] [--quiet] [--plan JSON] [--selftest]");
	process.exit(0);
}

if (opt.selftest) {
	// Drive our own plan engine in-process so you can trust it before pi does.
	const tests = [
		{ plan: { sequence: [429, 401, "ok"] }, keys: ["sk-a", "sk-a", "sk-a", "sk-a"], want: [429, 401, 200, 200] },
		{ plan: { byKey: { "sk-a": 429 }, default: "ok" }, keys: ["sk-a", "sk-b"], want: [429, 200] },
		{ plan: { sequence: [{ status: 500, attempts: 2 }, "ok"], repeatLast: false, default: "ok" }, keys: ["k", "k", "k", "k"], want: [500, 500, 200, 200] },
		{ plan: { sequence: ["quota"], repeatLast: true }, keys: ["k", "k"], want: [402, 402] },
		{ plan: { sequence: ["overloaded"] }, keys: ["k"], want: [529] },
	];
	let failures = 0;
	for (const t of tests) {
		state.plan = normalizePlan(t.plan);
		state.cursor = 0;
		const got = t.keys.map((k) => stepFor(k).status);
		const pass = JSON.stringify(got) === JSON.stringify(t.want);
		if (!pass) failures += 1;
		console.log(`${pass ? "PASS" : "FAIL"}  plan=${JSON.stringify(t.plan)}  got=${got}  want=${t.want}`);
	}
	if (!failures) console.log("selftest: all plan cases pass");
	process.exit(failures ? 1 : 0);
}

server.listen(opt.port, opt.host, async () => {
	const addr = server.address();
	console.log(`fake-openai-server listening on http://${opt.host}:${addr.port}`);
	console.log(`  chat:  POST http://${opt.host}:${addr.port}/v1/chat/completions`);
	console.log(`  plan:  POST http://${opt.host}:${addr.port}/__admin/plan   (curl -d @plan.json)`);
	console.log(`  state: GET  http://${opt.host}:${addr.port}/__admin/state`);
	console.log(`  reset: POST http://${opt.host}:${addr.port}/__admin/reset`);
	if (opt.plan) {
		state.plan = normalizePlan(opt.plan);
		console.log(`  installed initial plan: ${JSON.stringify(opt.plan)}`);
	}
});

server.on("close", () => console.log("closed"));
process.on("SIGINT", () => {
	console.log("\nshutting down");
	server.close(() => process.exit(0));
	setTimeout(() => process.exit(0), 300).unref();
});

export { normalizePlan, PRESETS, server };
