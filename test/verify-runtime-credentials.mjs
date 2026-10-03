#!/usr/bin/env node
// =============================================================================
// verify-runtime-credentials.mjs — probe pi 1.0.0's credential store
// =============================================================================
//
// pi-keyrouter's OAuth pools depend on facts about pi's credential storage that
// are NOT part of the public extension API. This script is the evidence for
// each of them, run against a temp auth.json. It never touches ~/.pi.
//
//   1. `ModelRegistry.runtime.credentials` exists and exposes read/modify
//      (same facade trick already used for setRuntimeApiKey).
//   2. `modify(id, () => blob)` writes through pi's own store, so the file lock,
//      the readState revision and the in-process cache stay coherent — and
//      `read()` sees the change afterwards with no restart.
//   3. `modify` returning undefined is a documented no-op, not a write.
//   4. A stored `type:"oauth"` credential resolves to real auth; an injected
//      api_key on an OAuth-only provider resolves to NOTHING. That asymmetry is
//      precisely why OAuth pools must not use the runtime overlay.
//   5. A read-only store throws from modify, so keyrouter can degrade.
//
//   node test/verify-runtime-credentials.mjs
//
// Reference builds verified: pi 1.0.0.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
	ModelRegistry,
	ModelRuntime,
	readStoredCredential,
} from "@earendil-works/pi-coding-agent";
// Public subpath: this is the exact module pi itself loads to build its
// provider list (`model-runtime.js` imports it as `builtinProviderCatalog`).
import * as builtinCatalog from "@earendil-works/pi-ai/providers/all";

let failures = 0;
const log = (message) => console.log(message);
const check = (label, condition, detail) => {
	const pass = Boolean(condition);
	if (!pass) failures += 1;
	log(`${pass ? "PASS" : "FAIL"}  ${label}${detail === undefined || pass ? "" : `  (${detail})`}`);
};

// A provider id nothing else uses, so a collision cannot mask a result.
const PROVIDER = "krprobe";
const dir = mkdtempSync(join(tmpdir(), "kr-cred-probe-"));
const authPath = join(dir, "auth.json");
const A1 = {
	type: "oauth",
	refresh: "refresh-1",
	access: "access-1",
	expires: Date.now() + 3_600_000,
	probeExtraField: "must-survive-round-trip",
};
const A2 = { type: "oauth", refresh: "refresh-2", access: "access-2", expires: Date.now() + 7_200_000 };
const write = (data) => writeFileSync(authPath, JSON.stringify(data, null, 2) + "\n", "utf8");

try {
	// -----------------------------------------------------------------------
	// Baseline: what auth methods do the builtin providers actually declare?
	// This is the source of truth for keyrouter's skip logic.
	// -----------------------------------------------------------------------
	const builtins = builtinCatalog.builtinProviders();
	log(`builtin providers: ${builtins.length}`);
	const oauthOnly = builtins.filter((p) => p.auth?.oauth && !p.auth.apiKey).map((p) => p.id);
	const dualAuth = builtins.filter((p) => p.auth?.oauth && p.auth.apiKey).map((p) => p.id);
	const apiKeyOnly = builtins.filter((p) => p.auth?.apiKey && !p.auth.oauth).length;
	log(`  oauth-only : ${oauthOnly.join(", ") || "(none)"}`);
	log(`  api_key+oauth: ${dualAuth.join(", ") || "(none)"}`);
	log(`  api_key-only : ${apiKeyOnly} provider(s)`);

	check(
		"the catalog exposes at least one OAuth-only provider (the case keyrouter must not overlay)",
		oauthOnly.length > 0,
	);
	check(
		"the catalog exposes dual-auth providers (the case that freezes if overlaid)",
		dualAuth.length > 0,
	);

	// -----------------------------------------------------------------------
	// 1. Seed auth.json, create a runtime over it, find the store via the facade.
	// -----------------------------------------------------------------------
	write({ [PROVIDER]: A1 });
	log(`\nauth.json      ${authPath}`);

	const runtime = await ModelRuntime.create({
		authPath,
		allowModelNetwork: false,
		refreshOnCreate: false,
	});
	const registry = new ModelRegistry(runtime);
	const viaFacade = registry.runtime?.credentials;

	check(
		"ModelRegistry.runtime.credentials reachable (field name survives the build)",
		viaFacade !== undefined,
		`got ${typeof viaFacade}`,
	);
	check(
		"credentials exposes read + modify",
		typeof viaFacade?.read === "function" && typeof viaFacade?.modify === "function",
		`read=${typeof viaFacade?.read} modify=${typeof viaFacade?.modify}`,
	);
	check("credentials is the runtime's own store (identity, not a copy)", viaFacade === runtime.credentials);
	// modify() must be callable on RuntimeCredentials itself: it delegates to the
	// AuthStorage one hop down, so keyrouter never needs to reach `.store`.
	check("modify is on RuntimeCredentials (delegates to the store)", typeof runtime.credentials.modify === "function");

	// -----------------------------------------------------------------------
	// 2. read() returns the seeded OAuth blob untouched — opaque by contract.
	// -----------------------------------------------------------------------
	const readBack = await runtime.credentials.read(PROVIDER);
	check("read() returned the seeded credential", readBack?.type === "oauth");
	check("read() did not rewrite the blob", readBack?.access === "access-1");
	check(
		"read() preserved provider-specific extra fields (blob must stay opaque)",
		readBack?.probeExtraField === "must-survive-round-trip",
	);

	// -----------------------------------------------------------------------
	// 3. modify() writes through the store, visibly, without a restart.
	//    pi caches in readState and reloads only when the file revision changes,
	//    so a stale read here would be a real bug.
	// -----------------------------------------------------------------------
	const written = await runtime.credentials.modify(PROVIDER, async () => A2);
	check("modify() returned the new credential", written?.access === "access-2");
	const afterWrite = await runtime.credentials.read(PROVIDER);
	check(
		"a later read() sees modify()'s write (cache coherent, no restart)",
		afterWrite?.access === "access-2",
		`got ${afterWrite?.access}`,
	);
	check("modify() persisted to auth.json", JSON.parse(readFileSync(authPath, "utf8"))[PROVIDER]?.access === "access-2");

	// -----------------------------------------------------------------------
	// 4. `undefined` means "no change". keyrouter must never rely on it to write.
	// -----------------------------------------------------------------------
	const noChange = await runtime.credentials.modify(PROVIDER, async () => undefined);
	check("modify() returning undefined reports the current value", noChange?.access === "access-2");
	check(
		"modify() returning undefined did not mutate",
		(await runtime.credentials.read(PROVIDER))?.access === "access-2",
	);

	// -----------------------------------------------------------------------
	// 5. readStoredCredential is a plain synchronous file read (reads only).
	// -----------------------------------------------------------------------
	check("readStoredCredential sees the same data", readStoredCredential(PROVIDER, authPath)?.access === "access-2");

	// -----------------------------------------------------------------------
	// 6. Whole-file read-modify-write must not clobber a sibling provider. This
	//    is the case where an out-of-band writer would destroy a real login.
	// -----------------------------------------------------------------------
	write({ other: { type: "api_key", key: "sk-other" }, [PROVIDER]: A2 });
	await runtime.credentials.read(PROVIDER); // refresh cached state
	await runtime.credentials.modify(PROVIDER, async () => A1);
	const merged = JSON.parse(readFileSync(authPath, "utf8"));
	check(
		"modify() preserved an unrelated provider entry (no whole-file clobber)",
		merged.other?.key === "sk-other",
		JSON.stringify(Object.keys(merged)),
	);
	check("modify() still wrote its own entry", merged[PROVIDER]?.access === "access-1");

	// -----------------------------------------------------------------------
	// 7. THE CENTRAL ASYMMETRY. An OAuth-only provider resolves a stored OAuth
	//    credential; the same provider resolves NOTHING from an injected api_key.
	//    If this ever flips, OAuth pools could use the overlay — and until then,
	//    using it would silently break auth.
	// -----------------------------------------------------------------------
	const target = oauthOnly[0];
	const oauthBlob = {
		type: "oauth",
		refresh: "probe-refresh",
		access: "probe-access",
		expires: Date.now() + 3_600_000,
	};
	write({ [target]: oauthBlob });
	const rt2 = await ModelRuntime.create({ authPath, allowModelNetwork: false, refreshOnCreate: false });

	const oauthResolved = await rt2.getAuth(target);
	check(
		`stored OAuth credential resolves on OAuth-only provider "${target}"`,
		oauthResolved !== undefined && oauthResolved.auth !== undefined,
		`source=${oauthResolved?.source}`,
	);
	log(`  ${target} with stored oauth -> source=${oauthResolved?.source} authKeys=${Object.keys(oauthResolved?.auth ?? {}).join(",")}`);

	await rt2.setRuntimeApiKey(target, "sk-probe-should-not-resolve");
	const overlaid = await rt2.getAuth(target);
	const overlayWon = overlaid?.auth?.apiKey === "sk-probe-should-not-resolve";
	check(
		`an injected api_key does NOT become auth on OAuth-only "${target}"`,
		!overlayWon,
		`source=${overlaid?.source} authKeys=${Object.keys(overlaid?.auth ?? {}).join(",")} apiKey=${JSON.stringify(overlaid?.auth?.apiKey)}`,
	);
	await rt2.removeRuntimeApiKey(target);
	const restored = await rt2.getAuth(target);
	// NOTE: resolved auth for an OAuth credential legitimately carries an `apiKey`
	// field — pi calls the provider's `oauth.toAuth(credential)`, and e.g.
	// openai-codex converts its blob into a bearer string. So the mere presence of
	// `auth.apiKey` proves NOTHING about whether an overlay is installed. The only
	// trustworthy discriminator is `source` ("OAuth" vs "runtime"), which is also
	// what `getProviderAuthStatus()` reports. keyrouter must key off that.
	check(
		"removing the overlay restores the stored OAuth credential",
		restored?.source === "OAuth",
		`source=${restored?.source} apiKey=${JSON.stringify(restored?.auth?.apiKey)}`
	);
	check(
		"the restored OAuth auth does not carry the sentinel overlay value",
		restored?.auth?.apiKey !== "sk-probe-should-not-resolve",
		`apiKey=${JSON.stringify(restored?.auth?.apiKey)}`
	);
	log(`  after remove: source=${restored?.source} authKeys=${Object.keys(restored?.auth ?? {}).join(",")}`);

	// getProviderAuthStatus is the signal keyrouter's /status uses, so pin its
	// semantics. IMPORTANT: its vocabulary DIFFERS from getAuth().source —
	// status says "runtime"/"stored"/"environment", while getAuth() says
	// "runtime"/"OAuth"/"environment". Both report "runtime" for an overlay, so
	// "is an overlay installed?" can be asked either way, but a check written
	// against one enum must not be compared to the other.
	await rt2.setRuntimeApiKey(target, "sk-probe-sentinel-2");
	const statusWithOverlay = rt2.getProviderAuthStatus(target).source;
	const authWithOverlay = (await rt2.getAuth(target))?.source;
	await rt2.removeRuntimeApiKey(target);
	const statusWithout = rt2.getProviderAuthStatus(target).source;
	const authWithout = (await rt2.getAuth(target))?.source;
	check(
		"while an api_key overlay is installed on the OAuth-only provider, getAuth() resolves NOTHING",
		statusWithOverlay === "runtime" && authWithOverlay === undefined,
		`status=${statusWithOverlay} auth=${authWithOverlay}`
	);
	log(
		`  overlay on OAuth-only provider: status=${statusWithOverlay} but auth=${authWithOverlay} ` +
			`(THE central constraint: an overlay there yields no auth at all)`,
	);
	log(`  source vocabularies: status=${statusWithOverlay}|${statusWithout}  auth=${authWithOverlay}|${authWithout}`);

	// -----------------------------------------------------------------------
	// 8. Dual-auth provider: the overlay DOES win there, which is exactly why an
	//    OAuth pool must clear it — otherwise the OAuth credential is frozen out
	//    and pi never refreshes it.
	// -----------------------------------------------------------------------
	if (dualAuth.length > 0) {
		const dual = dualAuth[0];
		const rt3 = await ModelRuntime.create({ authPath, allowModelNetwork: false, refreshOnCreate: false });
		write({ [dual]: oauthBlob });
		await rt3.setRuntimeApiKey(dual, "sk-probe-overlay");
		const dualOverlaid = await rt3.getAuth(dual);
		check(
			`on dual-auth provider "${dual}" the overlay DOES win (so it must be cleared for OAuth pools)`,
			dualOverlaid?.auth?.apiKey === "sk-probe-overlay",
			`source=${dualOverlaid?.source}`,
		);
		await rt3.removeRuntimeApiKey(dual);
	}

	// -----------------------------------------------------------------------
	// 9. Read-only store: modify() throws, so keyrouter must catch and degrade
	//    to inert with one actionable warning instead of failing a turn.
	//    Not exported from the package root, hence the absolute-URL import.
	// -----------------------------------------------------------------------
	const authStorageUrl = pathToFileURL(
		join(process.env.PI_PKG_ROOT ?? "", "dist", "core", "auth-storage.js"),
	).href;
	const mod = await import(authStorageUrl).catch(() => undefined);
	if (mod?.ReadOnlyAuthStorage) {
		const ro = new mod.ReadOnlyAuthStorage(authPath);
		let threw = false;
		let message = "";
		try {
			await ro.modify(PROVIDER, async () => A1);
		} catch (error) {
			threw = true;
			message = error instanceof Error ? error.message : String(error);
		}
		check("read-only store throws from modify() (keyrouter must catch this)", threw);
		log(`  read-only modify() message: ${JSON.stringify(message)}`);
	} else {
		log("SKIP  ReadOnlyAuthStorage unavailable (set PI_PKG_ROOT to the pi package root)");
	}
} finally {
	rmSync(dir, { recursive: true, force: true });
}

log(
	failures === 0
		? "\nall credential-store probes pass"
		: `\n${failures} probe(s) failed`,
);
process.exit(failures === 0 ? 0 : 1);