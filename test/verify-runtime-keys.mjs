// Verify pi 1.0.0's runtime credential overlay semantics that pi-keyrouter
// depends on: injecting a key must win over auth.json/env, be readable through
// the ModelRegistry facade, and be fully reversible.
import { ModelRuntime } from "@earendil-works/pi-coding-agent";

const log = (m) => console.log(m);
const ok = (label, cond) => log(`${cond ? "PASS" : "FAIL"}  ${label}`);

const runtime = await ModelRuntime.create({ allowModelNetwork: false, refreshOnCreate: false });
const ids = runtime.getRegisteredProviderIds();
log(`registered provider ids: ${ids.join(", ")}`);

const providerId = process.argv[2] ?? "tokenharbor";
const provider = runtime.getProvider(providerId);
if (!provider) {
  log(`provider "${providerId}" not present in this build; try another id`);
  process.exit(2);
}
log(`provider ${providerId} auth methods: ${Object.keys(provider.auth ?? {}).join("/")}`);

const SENTINEL = "__KR_SENTINEL_0123456789__";

// 1. baseline
const before = await runtime.getAuth(providerId);
log(`baseline source=${before?.source} key=${String(before?.auth.apiKey).slice(0, 10)}`);

// 2. inject
await runtime.setRuntimeApiKey(providerId, SENTINEL);
const after = await runtime.getAuth(providerId);
ok("injected key wins over stored credential/env", after?.auth.apiKey === SENTINEL);
log(`after inject: source=${after?.source}`);

// 3. model-scoped resolution (what a request actually uses)
const model = provider.getModels()[0];
if (model) {
  const resolved = await runtime.getAuth(model);
  ok("model-scoped getAuth returns injected key", resolved?.auth.apiKey === SENTINEL);
}

// 4. availability + auth status flip
ok("hasConfiguredAuth true", runtime.hasConfiguredAuth(providerId) === true);

// 5. remove -> restore previous credential
await runtime.removeRuntimeApiKey(providerId);
const cleared = await runtime.getAuth(providerId);
ok("removeRuntimeApiKey restores previous credential", cleared?.auth.apiKey !== SENTINEL);
log(`after clear: source=${cleared?.source} key=${String(cleared?.auth.apiKey).slice(0, 10)}`);

// 6. the facade exposes the runtime under the field name we cast to
const { ModelRegistry } = await import("@earendil-works/pi-coding-agent");
const reg = new ModelRegistry(runtime);
const facaded = reg.runtime;
ok("ModelRegistry.runtime reachable (name survives build)",
  facaded !== undefined && typeof facaded.setRuntimeApiKey === "function" && typeof facaded.removeRuntimeApiKey === "function");
log(`facade methods present: setRuntimeApiKey=${typeof facaded.setRuntimeApiKey} removeRuntimeApiKey=${typeof facaded.removeRuntimeApiKey}`);
