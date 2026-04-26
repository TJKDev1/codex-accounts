import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { getModels } from "@mariozechner/pi-ai";
import { refreshOpenAICodexToken, type OAuthCredentials, type OAuthLoginCallbacks } from "@mariozechner/pi-ai/oauth";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const PROVIDER_PREFIX = "openai-codex-";
const STATE_FILE = "multi-codex-accounts.json";
const DEFAULT_MODEL = "gpt-5.1-codex-max";
const CALLBACK_HOST = process.env.PI_OAUTH_CALLBACK_HOST || "127.0.0.1";
const CALLBACK_PORT = 1455;
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/auth/callback`;
const SCOPE = "openid profile email offline_access";

type Account = {
	providerId: string;
	name: string;
	accountId?: string;
	source?: "codex-cli";
	createdAt: number;
	updatedAt: number;
};

type UsageWindow = {
	usedPercent: number;
	windowMinutes: number;
	resetsAt: number;
};

type UsageSnapshot = {
	providerId: string;
	collectedAt: number;
	limitId?: string;
	limitName?: string | null;
	planType?: string | null;
	credits?: { hasCredits?: boolean; unlimited?: boolean; balance?: string | number | null };
	primary?: UsageWindow;
	secondary?: UsageWindow;
	source: "codex-app-server" | "response-headers";
};

type State = {
	version: 1;
	defaultProviderId?: string;
	accounts: Record<string, Account>;
	usage?: Record<string, UsageSnapshot>;
};

type AuthCredential = { type: "api_key"; key: string } | ({ type: "oauth" } & OAuthCredentials);

type AuthData = Record<string, AuthCredential>;

function agentDir(): string {
	return process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent");
}

function statePath(): string {
	return join(agentDir(), STATE_FILE);
}

function authPath(): string {
	return join(agentDir(), "auth.json");
}

function codexCliAuthPath(): string {
	return join(process.env.CODEX_HOME || join(homedir(), ".codex"), "auth.json");
}

function emptyState(): State {
	return { version: 1, accounts: {}, usage: {} };
}

function loadJson<T>(path: string): T | undefined {
	try {
		if (!existsSync(path)) return undefined;
		return JSON.parse(readFileSync(path, "utf8")) as T;
	} catch {
		return undefined;
	}
}

function loadState(): State {
	const raw = loadJson<Partial<State>>(statePath());
	if (!raw || typeof raw !== "object") return emptyState();
	return {
		version: 1,
		defaultProviderId: typeof raw.defaultProviderId === "string" ? raw.defaultProviderId : undefined,
		accounts: raw.accounts && typeof raw.accounts === "object" ? (raw.accounts as Record<string, Account>) : {},
		usage: raw.usage && typeof raw.usage === "object" ? (raw.usage as Record<string, UsageSnapshot>) : {},
	};
}

async function saveState(state: State): Promise<void> {
	await mkdir(dirname(statePath()), { recursive: true });
	writeFileSync(statePath(), JSON.stringify(state, null, "\t") + "\n", "utf8");
}

function loadAuthData(): AuthData {
	return loadJson<AuthData>(authPath()) ?? {};
}

function jwtPayload(token: string | undefined): Record<string, unknown> | undefined {
	if (!token) return undefined;
	try {
		return JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
	} catch {
		return undefined;
	}
}

function accountIdFromToken(access: string | undefined): string | undefined {
	const payload = jwtPayload(access);
	const auth = payload?.["https://api.openai.com/auth"] as { chatgpt_account_id?: unknown } | undefined;
	return typeof auth?.chatgpt_account_id === "string" ? auth.chatgpt_account_id : undefined;
}

function expiresFromToken(access: string | undefined): number {
	const exp = jwtPayload(access)?.exp;
	return typeof exp === "number" ? exp * 1000 - 5 * 60 * 1000 : Date.now() + 55 * 60 * 1000;
}

function readCodexCliCredentials(): OAuthCredentials | undefined {
	const raw = loadJson<{
		tokens?: { access_token?: string; refresh_token?: string; account_id?: string };
	}>(codexCliAuthPath());
	const access = raw?.tokens?.access_token;
	const refresh = raw?.tokens?.refresh_token;
	if (!access || !refresh) return undefined;
	return {
		access,
		refresh,
		expires: expiresFromToken(access),
		accountId: raw?.tokens?.account_id ?? accountIdFromToken(access),
	};
}

function writeCodexCliCredentials(credentials: OAuthCredentials): void {
	const path = codexCliAuthPath();
	const raw = loadJson<Record<string, unknown>>(path);
	if (!raw || typeof raw !== "object") return;
	const tokens = (raw.tokens && typeof raw.tokens === "object" ? raw.tokens : {}) as Record<string, unknown>;
	tokens.access_token = credentials.access;
	tokens.refresh_token = credentials.refresh;
	tokens.account_id = (credentials.accountId as string | undefined) ?? accountIdFromToken(credentials.access) ?? tokens.account_id;
	raw.tokens = tokens;
	raw.last_refresh = new Date().toISOString();
	writeFileSync(path, JSON.stringify(raw, null, 2) + "\n", "utf8");
}

function slugify(input: string): string {
	const slug = input
		.trim()
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 48);
	return slug || "account";
}

function uniqueProviderId(name: string, state: State, auth: AuthData): string {
	const base = `${PROVIDER_PREFIX}${slugify(name)}`;
	let candidate = base;
	let i = 2;
	while (state.accounts[candidate] || auth[candidate]) {
		candidate = `${base}-${i++}`;
	}
	return candidate;
}

function inferName(providerId: string): string {
	return providerId.slice(PROVIDER_PREFIX.length).replace(/-/g, " ");
}

function reconcileAccounts(state: State, auth: AuthData): State {
	const now = Date.now();
	for (const [providerId, credential] of Object.entries(auth)) {
		if (!providerId.startsWith(PROVIDER_PREFIX) || credential.type !== "oauth") continue;
		const existing = state.accounts[providerId];
		state.accounts[providerId] = {
			providerId,
			name: existing?.name ?? inferName(providerId),
			accountId: existing?.accountId ?? accountIdFromToken(credential.access),
			createdAt: existing?.createdAt ?? now,
			updatedAt: existing?.updatedAt ?? now,
		};
	}

	for (const providerId of Object.keys(state.accounts)) {
		if (!auth[providerId]) delete state.accounts[providerId];
	}

	if (state.defaultProviderId && !state.accounts[state.defaultProviderId]) {
		state.defaultProviderId = undefined;
	}
	state.usage ??= {};
	return state;
}

function getAccounts(state = loadState(), auth = loadAuthData()): Account[] {
	return Object.values(reconcileAccounts(state, auth).accounts).sort((a, b) => a.name.localeCompare(b.name));
}

const codexModels = getModels("openai-codex").map((model) => ({
	id: model.id,
	name: model.name,
	api: model.api,
	reasoning: model.reasoning,
	input: model.input,
	cost: model.cost,
	contextWindow: model.contextWindow,
	maxTokens: model.maxTokens,
}));

function oauthName(account: Account): string {
	return `ChatGPT Codex (${account.name})`;
}

function registerAccountProvider(pi: ExtensionAPI, account: Account): void {
	pi.registerProvider(account.providerId, {
		baseUrl: "https://chatgpt.com/backend-api",
		api: "openai-codex-responses",
		models: codexModels,
		oauth: {
			name: oauthName(account),
			usesCallbackServer: true,
			login: async (callbacks: OAuthLoginCallbacks) => loginWithCallbacks(callbacks),
			refreshToken: async (credentials: OAuthCredentials) => {
				const refreshed = await refreshOpenAICodexToken(credentials.refresh);
				if (account.source === "codex-cli") writeCodexCliCredentials(refreshed);
				return refreshed;
			},
			getApiKey: (credentials: OAuthCredentials) => credentials.access,
		},
	});
}

function registerKnownProviders(pi: ExtensionAPI): void {
	for (const account of getAccounts()) registerAccountProvider(pi, account);
}

function providerLabel(account: Account, activeProvider?: string, defaultProvider?: string): string {
	const marks = [
		account.providerId === activeProvider ? "active" : undefined,
		account.providerId === defaultProvider ? "default" : undefined,
		account.source === "codex-cli" ? "codex-cli" : undefined,
	]
		.filter(Boolean)
		.join(", ");
	const suffix = marks ? ` [${marks}]` : "";
	return `${account.name} (${account.providerId})${suffix}`;
}

function findAccount(query: string | undefined, accounts: Account[]): Account | undefined {
	const q = query?.trim().toLowerCase();
	if (!q) return undefined;
	return accounts.find(
		(account) =>
			account.providerId.toLowerCase() === q ||
			account.providerId.toLowerCase() === `${PROVIDER_PREFIX}${q}` ||
			account.name.toLowerCase() === q ||
			slugify(account.name) === q,
	);
}

async function openUrl(pi: ExtensionAPI, url: string): Promise<void> {
	try {
		if (process.platform === "darwin") await pi.exec("open", [url], { timeout: 3000 });
		else if (process.platform === "win32") await pi.exec("cmd", ["/c", "start", "", url], { timeout: 3000 });
		else await pi.exec("xdg-open", [url], { timeout: 3000 });
	} catch {
		// User can open URL manually from widget.
	}
}

function parseAuthorizationInput(input: string): { code?: string; state?: string } {
	const value = input.trim();
	if (!value) return {};
	try {
		const url = new URL(value);
		return { code: url.searchParams.get("code") ?? undefined, state: url.searchParams.get("state") ?? undefined };
	} catch {
		// not URL
	}
	if (value.includes("#")) {
		const [code, state] = value.split("#", 2);
		return { code, state };
	}
	if (value.includes("code=")) {
		const params = new URLSearchParams(value);
		return { code: params.get("code") ?? undefined, state: params.get("state") ?? undefined };
	}
	return { code: value };
}

function pkce(): { verifier: string; challenge: string } {
	const verifier = randomBytes(32).toString("base64url");
	const challenge = createHash("sha256").update(verifier).digest("base64url");
	return { verifier, challenge };
}

function authorizationUrl(state: string, challenge: string): string {
	const url = new URL(AUTHORIZE_URL);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", CLIENT_ID);
	url.searchParams.set("redirect_uri", REDIRECT_URI);
	url.searchParams.set("scope", SCOPE);
	url.searchParams.set("code_challenge", challenge);
	url.searchParams.set("code_challenge_method", "S256");
	url.searchParams.set("state", state);
	url.searchParams.set("id_token_add_organizations", "true");
	url.searchParams.set("codex_cli_simplified_flow", "true");
	url.searchParams.set("originator", "pi-multi-codex");
	return url.toString();
}

async function exchangeCode(code: string, verifier: string): Promise<OAuthCredentials> {
	const response = await fetch(TOKEN_URL, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			client_id: CLIENT_ID,
			code,
			code_verifier: verifier,
			redirect_uri: REDIRECT_URI,
		}),
	});
	if (!response.ok) throw new Error(`Token exchange failed: ${response.status} ${await response.text()}`);
	const data = (await response.json()) as { access_token?: string; refresh_token?: string; expires_in?: number };
	if (!data.access_token || !data.refresh_token || typeof data.expires_in !== "number") {
		throw new Error("Token exchange failed: missing access_token, refresh_token, or expires_in");
	}
	const accountId = accountIdFromToken(data.access_token);
	if (!accountId) throw new Error("Failed to extract accountId from OpenAI token");
	return {
		access: data.access_token,
		refresh: data.refresh_token,
		expires: Date.now() + data.expires_in * 1000,
		accountId,
	};
}

function startCallbackServer(state: string): Promise<{ server?: Server; waitForCode: Promise<string | undefined> }> {
	let settle: (code: string | undefined) => void = () => {};
	const waitForCode = new Promise<string | undefined>((resolve) => {
		settle = resolve;
	});
	const server = createServer((req, res) => {
		const url = new URL(req.url || "", "http://localhost");
		if (url.pathname !== "/auth/callback") {
			res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
			res.end("<h1>OpenAI OAuth</h1><p>Callback route not found.</p>");
			return;
		}
		if (url.searchParams.get("state") !== state) {
			res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
			res.end("<h1>OpenAI OAuth</h1><p>State mismatch.</p>");
			settle(undefined);
			return;
		}
		const code = url.searchParams.get("code") ?? undefined;
		res.writeHead(code ? 200 : 400, { "Content-Type": "text/html; charset=utf-8" });
		res.end(code ? "<h1>OpenAI login complete</h1><p>You can close this window.</p>" : "<h1>OpenAI OAuth</h1><p>Missing code.</p>");
		settle(code);
	});
	return new Promise((resolve) => {
		server
			.listen(CALLBACK_PORT, CALLBACK_HOST, () => resolve({ server, waitForCode }))
			.on("error", () => resolve({ waitForCode: Promise.resolve(undefined) }));
	});
}

async function loginWithCallbacks(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
	const { verifier, challenge } = pkce();
	const state = randomBytes(16).toString("hex");
	const url = authorizationUrl(state, challenge);
	const callback = await startCallbackServer(state);
	callbacks.onAuth({ url, instructions: "Open browser, complete login, or paste redirect URL/code." });
	callbacks.onProgress?.("Waiting for OpenAI OAuth callback or manual code.");

	const manualController = new AbortController();
	(callbacks as OAuthLoginCallbacks & { __setManualSignal?: (signal: AbortSignal) => void }).__setManualSignal?.(
		manualController.signal,
	);
	const manual = (callbacks.onManualCodeInput?.() ?? callbacks.onPrompt({
		message: "Paste authorization code or redirect URL:",
		placeholder: REDIRECT_URI,
	}))
		.then((input) => ({ type: "manual" as const, input }))
		.catch((error) => {
			if (manualController.signal.aborted) return { type: "manual" as const, input: "" };
			throw error;
		});
	const server = callback.server
		? callback.waitForCode.then((code) => ({ type: "server" as const, code }))
		: new Promise<{ type: "server"; code: string | undefined }>(() => {});

	try {
		const first = await Promise.race([manual, server]);
		if (first.type === "server" && first.code) {
			manualController.abort();
			return exchangeCode(first.code, verifier);
		}
		const manualResult = first.type === "manual" ? first : await manual;
		const parsed = parseAuthorizationInput(manualResult.input);
		if (parsed.state && parsed.state !== state) throw new Error("State mismatch");
		if (!parsed.code) throw new Error("Missing authorization code");
		return exchangeCode(parsed.code, verifier);
	} finally {
		manualController.abort();
		callback.server?.close();
	}
}

function buildLoginCallbacks(pi: ExtensionAPI, ctx: any): OAuthLoginCallbacks {
	let manualSignal: AbortSignal | undefined;
	return {
		__setManualSignal: (signal: AbortSignal) => {
			manualSignal = signal;
		},
		onAuth: (info) => {
			if (ctx.hasUI) {
				ctx.ui.setWidget("multi-codex-oauth", ["OpenAI Codex OAuth", info.instructions ?? "Complete login.", info.url]);
				ctx.ui.notify("OpenAI login URL ready. Browser open attempted.", "info");
			}
			void openUrl(pi, info.url);
		},
		onPrompt: async (prompt) => {
			if (!ctx.hasUI) throw new Error(prompt.message);
			return (await ctx.ui.input(prompt.message, prompt.placeholder, { signal: manualSignal })) ?? "";
		},
		onManualCodeInput: async () => {
			if (!ctx.hasUI) return "";
			return (await ctx.ui.input("Paste authorization code or redirect URL:", REDIRECT_URI, {
				signal: manualSignal,
			})) ?? "";
		},
		onProgress: (message) => ctx.hasUI && ctx.ui.notify(message, "info"),
		signal: ctx.signal,
	} as OAuthLoginCallbacks;
}

async function importCodexCliAccount(
	pi: ExtensionAPI,
	state: State,
	authStorage: { getAll(): AuthData; set(provider: string, credential: AuthCredential): void },
	name = "codex-cli",
): Promise<Account> {
	const credentials = readCodexCliCredentials();
	if (!credentials) throw new Error(`No Codex CLI OAuth tokens found at ${codexCliAuthPath()}`);
	const accountId = (credentials.accountId as string | undefined) ?? accountIdFromToken(credentials.access);
	const existing = Object.values(state.accounts).find(
		(account) => account.source === "codex-cli" || (accountId && account.accountId === accountId),
	);
	const now = Date.now();
	const account: Account = existing ?? {
		providerId: uniqueProviderId(name, state, authStorage.getAll()),
		name,
		source: "codex-cli",
		createdAt: now,
		updatedAt: now,
	};
	account.accountId = accountId;
	account.source = "codex-cli";
	account.updatedAt = now;
	authStorage.set(account.providerId, { type: "oauth", ...credentials });
	state.accounts[account.providerId] = account;
	state.defaultProviderId ??= account.providerId;
	await saveState(state);
	registerAccountProvider(pi, account);
	return account;
}

async function chooseAccount(ctx: any, title: string, accounts: Account[]): Promise<Account | undefined> {
	if (!ctx.hasUI) return undefined;
	const choice = await ctx.ui.select(title, accounts.map((account) => providerLabel(account)));
	if (!choice) return undefined;
	return accounts.find((account) => providerLabel(account) === choice);
}

function accountSummary(accounts: Account[], activeProvider?: string, defaultProvider?: string): string[] {
	if (accounts.length === 0) return ["No multi Codex accounts. Run /codex-accounts add <name>."];
	return accounts.map((account) => {
		const id = account.accountId ? ` acct=${account.accountId}` : "";
		return `- ${providerLabel(account, activeProvider, defaultProvider)}${id}`;
	});
}

function asNumber(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "string" && value.trim() !== "") {
		const parsed = Number(value);
		if (Number.isFinite(parsed)) return parsed;
	}
	return undefined;
}

function header(headers: Record<string, string>, name: string): string | undefined {
	return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function parseHeaderUsage(providerId: string, headers: Record<string, string>): UsageSnapshot | undefined {
	const primaryUsed = asNumber(header(headers, "x-codex-primary-used-percent"));
	const secondaryUsed = asNumber(header(headers, "x-codex-secondary-used-percent"));
	if (primaryUsed === undefined && secondaryUsed === undefined) return undefined;
	const primaryWindow = asNumber(header(headers, "x-codex-primary-window-minutes")) ?? 300;
	const secondaryWindow = asNumber(header(headers, "x-codex-secondary-window-minutes")) ?? 10080;
	const primaryReset = asNumber(header(headers, "x-codex-primary-reset-at")) ?? asNumber(header(headers, "x-codex-primary-resets-at"));
	const secondaryReset = asNumber(header(headers, "x-codex-secondary-reset-at")) ?? asNumber(header(headers, "x-codex-secondary-resets-at"));
	const nowSeconds = Math.floor(Date.now() / 1000);
	return {
		providerId,
		collectedAt: Date.now(),
		limitId: header(headers, "x-codex-limit-id"),
		limitName: header(headers, "x-codex-limit-name") ?? null,
		planType: header(headers, "x-codex-plan-type") ?? null,
		credits: {
			hasCredits: header(headers, "x-codex-credits-has-credits") === "true",
			unlimited: header(headers, "x-codex-credits-unlimited") === "true",
			balance: header(headers, "x-codex-credits-balance") ?? null,
		},
		primary: primaryUsed === undefined ? undefined : {
			usedPercent: primaryUsed,
			windowMinutes: primaryWindow,
			resetsAt: primaryReset ?? nowSeconds + primaryWindow * 60,
		},
		secondary: secondaryUsed === undefined ? undefined : {
			usedPercent: secondaryUsed,
			windowMinutes: secondaryWindow,
			resetsAt: secondaryReset ?? nowSeconds + secondaryWindow * 60,
		},
		source: "response-headers",
	};
}

function appServerRateLimits(): Promise<any> {
	return new Promise((resolve, reject) => {
		const proc = spawn("codex", ["app-server"], { stdio: ["pipe", "pipe", "ignore"] });
		const rl = createInterface({ input: proc.stdout });
		const timeout = setTimeout(() => {
			proc.kill();
			reject(new Error("Timed out waiting for codex app-server rate limits"));
		}, 5000);
		proc.on("error", (error) => {
			clearTimeout(timeout);
			reject(error);
		});
		rl.on("line", (line) => {
			let msg: any;
			try { msg = JSON.parse(line); } catch { return; }
			if (msg.id === 1) {
				clearTimeout(timeout);
				proc.kill();
				if (msg.error) reject(new Error(msg.error.message ?? JSON.stringify(msg.error)));
				else resolve(msg.result?.rateLimits);
			}
		});
		proc.stdin.write(JSON.stringify({ method: "initialize", id: 0, params: { clientInfo: { name: "multi-codex-pi", title: "Multi Codex Pi", version: "0.1.0" } } }) + "\n");
		setTimeout(() => {
			proc.stdin.write(JSON.stringify({ method: "account/rateLimits/read", id: 1, params: {} }) + "\n");
		}, 500);
	});
}

function normalizeAppServerUsage(providerId: string, rateLimits: any): UsageSnapshot {
	const normalizeWindow = (win: any): UsageWindow | undefined => {
		const usedPercent = asNumber(win?.usedPercent);
		const windowMinutes = asNumber(win?.windowDurationMins) ?? asNumber(win?.windowMinutes);
		const resetsAt = asNumber(win?.resetsAt);
		if (usedPercent === undefined || windowMinutes === undefined || resetsAt === undefined) return undefined;
		return { usedPercent, windowMinutes, resetsAt };
	};
	return {
		providerId,
		collectedAt: Date.now(),
		limitId: rateLimits?.limitId,
		limitName: rateLimits?.limitName ?? null,
		planType: rateLimits?.planType ?? null,
		credits: rateLimits?.credits,
		primary: normalizeWindow(rateLimits?.primary),
		secondary: normalizeWindow(rateLimits?.secondary),
		source: "codex-app-server",
	};
}

function formatDuration(ms: number): string {
	const minutes = Math.max(0, Math.round(ms / 60000));
	const h = Math.floor(minutes / 60);
	const m = minutes % 60;
	return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function formatWindow(label: string, win?: UsageWindow): string {
	if (!win) return `${label}: no data`;
	const left = Math.max(0, 100 - win.usedPercent);
	const reset = new Date(win.resetsAt * 1000);
	return `${label}: ${win.usedPercent.toFixed(1)}% used / ${left.toFixed(1)}% left, resets ${formatDuration(reset.getTime() - Date.now())} (${reset.toLocaleString()})`;
}

function usageLines(snapshot: UsageSnapshot | undefined): string[] {
	if (!snapshot) return ["No usage data yet. Send one Codex request, or import Codex CLI and run usage again."];
	return [
		`Provider: ${snapshot.providerId}`,
		`Plan: ${snapshot.planType ?? "unknown"} | source: ${snapshot.source} | collected: ${new Date(snapshot.collectedAt).toLocaleString()}`,
		formatWindow("5h", snapshot.primary),
		formatWindow("Weekly", snapshot.secondary),
	];
}

async function refreshUsageForAccount(account: Account, cached?: UsageSnapshot): Promise<UsageSnapshot | undefined> {
	if (account.source !== "codex-cli") return cached;
	return normalizeAppServerUsage(account.providerId, await appServerRateLimits());
}

export default function (pi: ExtensionAPI) {
	registerKnownProviders(pi);

	pi.on("session_start", async (_event, ctx) => {
		const state = reconcileAccounts(loadState(), ctx.modelRegistry.authStorage.getAll() as AuthData);
		await saveState(state);
		for (const account of Object.values(state.accounts)) registerAccountProvider(pi, account);
		ctx.ui.setStatus("multi-codex", ctx.model.provider.startsWith(PROVIDER_PREFIX) ? ctx.model.provider : undefined);
	});

	pi.on("model_select", async (event, ctx) => {
		ctx.ui.setStatus("multi-codex", event.model.provider.startsWith(PROVIDER_PREFIX) ? event.model.provider : undefined);
	});

	pi.on("after_provider_response", async (event, ctx) => {
		if (!ctx.model.provider.startsWith(PROVIDER_PREFIX)) return;
		const snapshot = parseHeaderUsage(ctx.model.provider, event.headers);
		if (!snapshot) return;
		const state = loadState();
		state.usage ??= {};
		state.usage[ctx.model.provider] = snapshot;
		await saveState(state);
		ctx.ui.setStatus("codex-usage", `5h ${snapshot.primary?.usedPercent ?? "?"}% wk ${snapshot.secondary?.usedPercent ?? "?"}%`);
	});

	pi.registerCommand("codex-accounts", {
		description: "Manage multiple OpenAI Codex OAuth accounts",
		getArgumentCompletions(prefix: string) {
			const commands = ["add", "import-codex", "usage", "list", "switch", "default", "refresh", "remove", "rename"];
			return commands
				.filter((command) => command.startsWith(prefix.trim()))
				.map((command) => ({ value: command, label: command }));
		},
		handler: async (args, ctx) => {
			let [action, ...rest] = args.trim().split(/\s+/).filter(Boolean);
			if (!action && ctx.hasUI) {
				action = await ctx.ui.select("Codex account manager", [
					"add",
					"import-codex",
					"usage",
					"switch",
					"list",
					"default",
					"refresh",
					"rename",
					"remove",
				]);
				if (!action) return;
			}
			action ??= "list";

			const state = reconcileAccounts(loadState(), ctx.modelRegistry.authStorage.getAll() as AuthData);
			let accounts = Object.values(state.accounts).sort((a, b) => a.name.localeCompare(b.name));

			if (action === "list" || action === "ls") {
				ctx.ui.setWidget("multi-codex-accounts", accountSummary(accounts, ctx.model.provider, state.defaultProviderId));
				ctx.ui.notify(`${accounts.length} Codex account(s).`, "info");
				return;
			}

			if (action === "usage" || action === "status") {
				const account =
					findAccount(rest.join(" "), accounts) ??
					accounts.find((account) => account.providerId === ctx.model.provider) ??
					(state.defaultProviderId ? state.accounts[state.defaultProviderId] : undefined) ??
					(await chooseAccount(ctx, "Show Codex usage", accounts));
				if (!account) return;
				const cached = state.usage?.[account.providerId];
				const snapshot = await refreshUsageForAccount(account, cached);
				if (snapshot) {
					state.usage ??= {};
					state.usage[account.providerId] = snapshot;
					await saveState(state);
				}
				ctx.ui.setWidget("multi-codex-usage", usageLines(snapshot));
				ctx.ui.notify(`Usage for ${account.name}.`, "info");
				return;
			}

			if (action === "import-codex" || action === "import" || action === "codex") {
				const name = rest.join(" ").trim() || "codex-cli";
				const account = await importCodexCliAccount(pi, state, ctx.modelRegistry.authStorage, name);
				const model = ctx.modelRegistry.find(account.providerId, ctx.model.id) ?? ctx.modelRegistry.find(account.providerId, DEFAULT_MODEL);
				if (model) await pi.setModel(model);
				ctx.ui.notify(`Imported Codex CLI account as ${account.providerId}.`, "info");
				return;
			}

			if (action === "add" || action === "login") {
				const auth = ctx.modelRegistry.authStorage;
				let name = rest.join(" ").trim();
				if (!name) {
					if (!ctx.hasUI) throw new Error("Usage: /codex-accounts add <name>");
					name = (await ctx.ui.input("Account name:", "work"))?.trim() ?? "";
				}
				if (!name) return;

				const providerId = uniqueProviderId(name, state, auth.getAll() as AuthData);
				const now = Date.now();
				const account: Account = { providerId, name, createdAt: now, updatedAt: now };
				registerAccountProvider(pi, account);

				try {
					const credentials = await loginWithCallbacks(buildLoginCallbacks(pi, ctx));
					account.accountId = (credentials.accountId as string | undefined) ?? accountIdFromToken(credentials.access);
					account.updatedAt = Date.now();
					auth.set(providerId, { type: "oauth", ...credentials });
					state.accounts[providerId] = account;
					state.defaultProviderId ??= providerId;
					await saveState(state);
					registerAccountProvider(pi, account);

					const model = ctx.modelRegistry.find(providerId, ctx.model.id) ?? ctx.modelRegistry.find(providerId, DEFAULT_MODEL);
					if (model) await pi.setModel(model);
					ctx.ui.setWidget("multi-codex-oauth", undefined);
					ctx.ui.notify(`Added ${name} (${providerId}).`, "info");
				} catch (error) {
					pi.unregisterProvider(providerId);
					throw error;
				}
				return;
			}

			if (accounts.length === 0) {
				ctx.ui.notify("No multi Codex accounts. Run /codex-accounts add <name>.", "warning");
				return;
			}

			if (action === "switch" || action === "use") {
				const account = findAccount(rest.join(" "), accounts) ?? (await chooseAccount(ctx, "Switch Codex account", accounts));
				if (!account) return;
				const model = ctx.modelRegistry.find(account.providerId, ctx.model.id) ?? ctx.modelRegistry.find(account.providerId, DEFAULT_MODEL);
				if (!model) throw new Error(`No Codex model found for ${account.providerId}`);
				const ok = await pi.setModel(model);
				if (!ok) throw new Error(`No auth for ${account.providerId}. Run /codex-accounts refresh ${account.name}.`);
				ctx.ui.notify(`Switched to ${account.name}.`, "info");
				return;
			}

			if (action === "default") {
				const account = findAccount(rest.join(" "), accounts) ?? (await chooseAccount(ctx, "Default Codex account", accounts));
				if (!account) return;
				state.defaultProviderId = account.providerId;
				await saveState(state);
				ctx.ui.notify(`Default Codex account: ${account.name}.`, "info");
				return;
			}

			if (action === "refresh") {
				const account = findAccount(rest.join(" "), accounts) ?? (await chooseAccount(ctx, "Refresh Codex token", accounts));
				if (!account) return;
				const credential = ctx.modelRegistry.authStorage.get(account.providerId);
				if (!credential || credential.type !== "oauth") throw new Error(`No OAuth credential for ${account.providerId}`);
				const refreshed = await refreshOpenAICodexToken(credential.refresh);
				account.accountId = (refreshed.accountId as string | undefined) ?? accountIdFromToken(refreshed.access);
				account.updatedAt = Date.now();
				ctx.modelRegistry.authStorage.set(account.providerId, { type: "oauth", ...refreshed });
				state.accounts[account.providerId] = account;
				await saveState(state);
				ctx.ui.notify(`Refreshed ${account.name}.`, "info");
				return;
			}

			if (action === "rename") {
				const account = findAccount(rest.join(" "), accounts) ?? (await chooseAccount(ctx, "Rename Codex account", accounts));
				if (!account) return;
				if (!ctx.hasUI) throw new Error("Usage: /codex-accounts rename <account> then enter name in UI");
				const next = (await ctx.ui.input("New account name:", account.name))?.trim();
				if (!next) return;
				account.name = next;
				account.updatedAt = Date.now();
				state.accounts[account.providerId] = account;
				await saveState(state);
				registerAccountProvider(pi, account);
				ctx.ui.notify(`Renamed to ${next}.`, "info");
				return;
			}

			if (action === "remove" || action === "rm" || action === "delete") {
				const account = findAccount(rest.join(" "), accounts) ?? (await chooseAccount(ctx, "Remove Codex account", accounts));
				if (!account) return;
				const ok = !ctx.hasUI
					? true
					: await ctx.ui.confirm(
							"Remove Codex account?",
							`This deletes stored OAuth token for ${account.name} (${account.providerId}). Continue?`,
						);
				if (!ok) return;
				ctx.modelRegistry.authStorage.remove(account.providerId);
				delete state.accounts[account.providerId];
				if (state.defaultProviderId === account.providerId) state.defaultProviderId = undefined;
				await saveState(state);
				pi.unregisterProvider(account.providerId);
				ctx.ui.notify(`Removed ${account.name}.`, "info");
				return;
			}

			throw new Error(
				"Usage: /codex-accounts [add|import-codex|usage|list|switch|default|refresh|rename|remove] [account]",
			);
		},
	});
}
