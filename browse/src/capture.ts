/**
 * Network capture/replay — intercept fetch/xhr on a Playwright page, store the
 * JSON-shaped responses, and re-issue them with the session's cookies.
 *
 * Use case: paginated / scrapable APIs that are easier to consume as JSON
 * than by re-rendering the page. Especially useful when a site requires auth
 * that is hard to script (captcha, MFA, SSO) — the user logs in once in a
 * real browser, then capture+replay runs headlessly with the saved session
 * via `context.request.fetch()`.
 *
 * Pattern ported from mandarwagh9/agentbrowse v0.3.3 (npm) — same primitives
 * (`page.route` + isJsonish + `context.request.fetch`), local implementation
 * since the upstream is closed-source and 4 days old. The analytics-host
 * blocklist, header sanitization, and capture-id monotonic counter are
 * direct equivalents.
 *
 * Architecture:
 *   1. attach(page)  → installs a wildcard page.route() interceptor
 *   2. handler       → for each request, decides if it's an API response
 *                      (xhr/fetch with JSON content-type, or any *json* type).
 *                      Fulfills from server via route.fetch(), records body,
 *                      then passes the response back to the page.
 *   3. list() / get() → return captured entries (with token-bounded body).
 *   4. replay(ctx,id)→ re-issues the captured request via the context's
 *                      request API (carries page cookies). Query-string
 *                      overrides let you paginate/filter without re-navigating.
 */

import type { Page, Request, Route, BrowserContext } from 'playwright';

export interface CapturedRequest {
  id: number;
  method: string;
  url: string;
  resourceType: string;
  contentType: string;
  status: number;
  body: string;
  requestHeaders: Record<string, string>;
  timestamp: number;
}

export interface ReplayOptions {
  /** Override query params on the replayed URL (repeatable via the same key) */
  query?: Record<string, string>;
  /** Max characters of response body to return (default 8000) */
  maxChars?: number;
}

export interface AttachOptions {
  /** Filter to URLs containing this substring (case-insensitive) */
  filter?: string;
  /** Max entries to retain (default 200) — older entries shift out */
  maxEntries?: number;
}

// ─── Analytics host blocklist (mirrors agentbrowse) ──────────────
// These are hosts we explicitly do NOT want to capture — they would flood
// the store with telemetry noise and could leak tracking IDs. Source: the
// canonical analytics vendors whose JS tags fire on most modern sites.
const ANALYTICS_HOSTS = [
  'google-analytics.com',
  'googletagmanager.com',
  'analytics.google.com',
  'doubleclick.net',
  'googlesyndication.com',
  'segment.io',
  'segment.com',
  'mixpanel.com',
  'amplitude.com',
  'sentry.io',
  'ingest.sentry.io',
  'hotjar.com',
  'fullstory.com',
  'facebook.com/tr',
  'connect.facebook.net',
  'bat.bing.com',
  'clarity.ms',
  'datadoghq.com',
  'nr-data.net',
  'newrelic.com',
  'intercom.io',
  'heap.io',
  'heapanalytics.com',
  'snowplow',
  'optimizely.com',
  'branch.io',
  'appsflyer.com',
  'cdn.amplitude.com',
];

// Resource types that are NEVER API responses — assets, scripts, fonts, etc.
const ASSET_TYPES = new Set([
  'document', 'stylesheet', 'image', 'media', 'font', 'script',
  'texttrack', 'manifest', 'websocket',
]);

// Resource types that ARE always treated as API responses.
const DATA_TYPES = new Set(['xhr', 'fetch']);

// Headers that should be stripped on replay — they are connection-scoped
// (host, content-length) or carry credentials (cookie) that the context's
// request API will set itself.
const STRIP_HEADERS = new Set([
  'host', 'connection', 'content-length', 'accept-encoding',
  'cookie', 'transfer-encoding', 'keep-alive',
  'proxy-authorization', 'te', 'upgrade',
]);

// ─── Pure helpers (exported for testing) ─────────────────────────

export function isAnalyticsHost(url: string): boolean {
  try {
    const u = new URL(url);
    const host = (u.hostname + u.pathname).toLowerCase();
    return ANALYTICS_HOSTS.some(h => host.includes(h));
  } catch {
    return false;
  }
}

export function isJsonishContentType(contentType: string | undefined | null): boolean {
  if (!contentType) return false;
  const ct = contentType.split(';')[0].trim().toLowerCase();
  return ct.endsWith('/json') || ct.endsWith('+json') ||
         ct === 'application/graphql' || ct.includes('json');
}

export function isApiResponse(meta: {
  resourceType?: string;
  contentType?: string | null;
  url: string;
}): boolean {
  if (meta.url.startsWith('data:') || meta.url.startsWith('blob:')) return false;
  if (isAnalyticsHost(meta.url)) return false;
  const rt = meta.resourceType?.toLowerCase();
  if (rt) {
    if (ASSET_TYPES.has(rt)) return false;
    if (DATA_TYPES.has(rt)) return true;
  }
  return isJsonishContentType(meta.contentType);
}

export function sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (key.startsWith(':')) continue;          // HTTP/2 pseudo-headers
    if (STRIP_HEADERS.has(key)) continue;       // connection-scoped
    out[k] = v;
  }
  return out;
}

// ─── CaptureStore ────────────────────────────────────────────────

export class CaptureStore {
  private entries: CapturedRequest[] = [];
  private counter = 0;
  private routeHandler?: (route: Route, request: Request) => Promise<void>;
  private attachedPage?: Page;
  private filter?: string;
  private maxEntries: number;

  constructor(opts: AttachOptions = {}) {
    this.filter = opts.filter;
    this.maxEntries = opts.maxEntries ?? 200;
  }

  /**
   * Start intercepting requests on a page. Idempotent — calling twice
   * detaches the previous handler first so the page doesn't accumulate
   * double-handlers (which would call route.fulfill twice on the same req).
   */
  async attach(page: Page): Promise<void> {
    if (this.routeHandler) await this.detach();
    this.attachedPage = page;
    this.routeHandler = async (route: Route, request: Request) => {
      const url = request.url();
      const resourceType = request.resourceType();
      const contentType = request.headers()['content-type'] || null;

      if (!isApiResponse({ resourceType, contentType, url })) {
        await route.continue();
        return;
      }
      if (this.filter && !url.toLowerCase().includes(this.filter.toLowerCase())) {
        await route.continue();
        return;
      }

      try {
        // Fetch the real response, record it, then pass it through to the page.
        const response = await route.fetch();
        const body = await response.text().catch(() => '');
        const responseContentType = response.headers()['content-type'] || '';
        const id = ++this.counter;
        this.entries.push({
          id,
          method: request.method(),
          url,
          resourceType,
          contentType: responseContentType,
          status: response.status(),
          body,
          requestHeaders: sanitizeHeaders(request.headers()),
          timestamp: Date.now(),
        });
        if (this.entries.length > this.maxEntries) {
          this.entries.shift();
        }
        await route.fulfill({ response });
      } catch {
        // Network error or page closed — let the request fall through.
        try { await route.continue(); } catch { /* page gone */ }
      }
    };
    await page.route('**/*', this.routeHandler);
  }

  /** Stop intercepting. Safe to call multiple times. */
  async detach(): Promise<void> {
    if (this.attachedPage && this.routeHandler) {
      try {
        await this.attachedPage.unroute('**/*', this.routeHandler);
      } catch { /* page already closed */ }
    }
    this.attachedPage = undefined;
    this.routeHandler = undefined;
  }

  /** Return captured entries, optionally filtered by URL substring. */
  list(filter?: string): CapturedRequest[] {
    const entries = filter
      ? this.entries.filter(e => e.url.toLowerCase().includes(filter.toLowerCase()))
      : [...this.entries];
    return entries;
  }

  /** Return one captured entry by id, or undefined. */
  get(id: number): CapturedRequest | undefined {
    return this.entries.find(e => e.id === id);
  }

  /** Drop all captured entries. Does not detach. */
  clear(): void {
    this.entries = [];
    this.counter = 0;
  }

  /** Number of captured entries. */
  get size(): number {
    return this.entries.length;
  }

  /**
   * Re-issue a captured request via the context's request API (which carries
   * the page's cookies / auth state). Throws on unknown id. Returns the raw
   * response with body bounded by `maxChars` (default 8000).
   */
  async replay(
    context: BrowserContext,
    id: number,
    opts: ReplayOptions = {},
  ): Promise<{ status: number; contentType: string; text: string; url: string }> {
    const entry = this.get(id);
    if (!entry) throw new Error(`No captured request with id=${id}`);

    let url = entry.url;
    if (opts.query) {
      const u = new URL(url);
      for (const [k, v] of Object.entries(opts.query)) {
        u.searchParams.set(k, v);
      }
      url = u.toString();
    }
    const headers = sanitizeHeaders(entry.requestHeaders);
    const response = await context.request.fetch(url, {
      method: entry.method,
      headers,
    });
    const text = await response.text();
    const cap = opts.maxChars ?? 8000;
    return {
      status: response.status(),
      contentType: response.headers()['content-type'] || '',
      text: text.length > cap ? text.slice(0, cap) : text,
      url,
    };
  }
}
