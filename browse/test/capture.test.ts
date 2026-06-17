import { describe, it, expect, afterEach } from 'bun:test';
import { chromium } from 'playwright';
import * as fs from 'fs';
import {
  CaptureStore,
  isAnalyticsHost,
  isJsonishContentType,
  isApiResponse,
  sanitizeHeaders,
} from '../src/capture';
import { startTestServer } from './test-server';

// Playwright in this repo expects a specific browser revision at
// ~/Library/Caches/ms-playwright/chromium_headless_shell-1208/. If the
// installed revision is different (e.g. 1223), the integration tests can't
// run — skip them with a clear message rather than fail. The pure-helper
// tests above are the load-bearing business logic; integration tests
// exercise the Playwright glue, which is unchanged in scope.
function hasPlaywrightBrowser(): boolean {
  const candidates = [
    'chromium_headless_shell-1208',
    'chromium-1208',
  ];
  for (const c of candidates) {
    const p = `${process.env.HOME}/Library/Caches/ms-playwright/${c}`;
    if (fs.existsSync(p)) return true;
  }
  return false;
}
const BROWSER_OK = hasPlaywrightBrowser();

describe('capture helpers (pure)', () => {
  it('isAnalyticsHost catches GA / Segment / Mixpanel / Sentry', () => {
    expect(isAnalyticsHost('https://www.google-analytics.com/collect')).toBe(true);
    expect(isAnalyticsHost('https://api.segment.io/v1/track')).toBe(true);
    expect(isAnalyticsHost('https://api.mixpanel.com/track')).toBe(true);
    expect(isAnalyticsHost('https://ingest.sentry.io/api/123/envelope/')).toBe(true);
    expect(isAnalyticsHost('https://example.com/api/products')).toBe(false);
    expect(isAnalyticsHost('not-a-url')).toBe(false);
  });

  it('isJsonishContentType matches application/json, +json, graphql', () => {
    expect(isJsonishContentType('application/json')).toBe(true);
    expect(isJsonishContentType('application/json; charset=utf-8')).toBe(true);
    expect(isJsonishContentType('application/vnd.api+json')).toBe(true);
    expect(isJsonishContentType('application/graphql')).toBe(true);
    expect(isJsonishContentType('text/html')).toBe(false);
    expect(isJsonishContentType('image/png')).toBe(false);
    expect(isJsonishContentType(undefined)).toBe(false);
    expect(isJsonishContentType(null)).toBe(false);
    expect(isJsonishContentType('')).toBe(false);
  });

  it('isApiResponse returns true for xhr/fetch + JSON content-type', () => {
    // Explicit xhr/fetch resource type — always an API response
    expect(isApiResponse({ resourceType: 'xhr', contentType: 'text/plain', url: 'https://x.com' })).toBe(true);
    expect(isApiResponse({ resourceType: 'fetch', contentType: null, url: 'https://x.com' })).toBe(true);
    // JSON content-type even without explicit resourceType
    expect(isApiResponse({ resourceType: 'other', contentType: 'application/json', url: 'https://x.com' })).toBe(true);
    // Asset types always false
    expect(isApiResponse({ resourceType: 'image', contentType: 'application/json', url: 'https://x.com' })).toBe(false);
    expect(isApiResponse({ resourceType: 'script', contentType: 'application/json', url: 'https://x.com' })).toBe(false);
    // Non-JSON content-type without explicit resource type
    expect(isApiResponse({ resourceType: 'other', contentType: 'text/html', url: 'https://x.com' })).toBe(false);
    // data: / blob: URLs always false
    expect(isApiResponse({ resourceType: 'fetch', contentType: 'application/json', url: 'data:text/html,foo' })).toBe(false);
    // Analytics host is filtered out
    expect(isApiResponse({ resourceType: 'fetch', contentType: 'application/json', url: 'https://api.segment.io/v1/track' })).toBe(false);
  });

  it('sanitizeHeaders strips connection-scoped and credential headers', () => {
    const out = sanitizeHeaders({
      'Host': 'example.com',
      'Connection': 'keep-alive',
      'Content-Length': '42',
      'Accept-Encoding': 'gzip',
      'Cookie': 'session=secret',
      'Transfer-Encoding': 'chunked',
      ':authority': 'example.com',
      'X-Custom': 'keep-me',
      'Authorization': 'keep-me-too',
    });
    expect(out).toEqual({ 'X-Custom': 'keep-me', 'Authorization': 'keep-me-too' });
  });
});

describe('CaptureStore (Playwright integration)', () => {
  let browser: Awaited<ReturnType<typeof chromium.launch>> | null = null;

  afterEach(async () => {
    if (browser) {
      await browser.close();
      browser = null;
    }
  });

  it('captures JSON xhr and fetch from a real page, ignores image', async () => {
    if (!BROWSER_OK) {
      console.log('  [skip] Playwright browser revision 1208 not installed (need: npx playwright install chromium)');
      return;
    }
    const { url } = startTestServer();
    browser = await chromium.launch();
    const ctx = await browser.newContext();
    const page = await ctx.newPage();

    const store = new CaptureStore();
    await store.attach(page);

    await page.goto(`${url}/capture-page.html`);
    // Wait for the fixture to finish (it sets #out.textContent to JSON)
    await page.waitForFunction(
      () => {
        const el = document.getElementById('out');
        return el && el.textContent && !el.textContent.startsWith('pending');
      },
      { timeout: 5000 }
    );

    const entries = store.list();
    // We expect at least 2 API responses: the xhr and the fetch.
    // The /favicon.ico (image) MUST NOT be captured.
    const apiEntries = entries.filter(e =>
      e.url.includes('/echo') && (e.url.includes('kind=xhr') || e.url.includes('kind=fetch'))
    );
    expect(apiEntries.length).toBeGreaterThanOrEqual(2);

    for (const e of apiEntries) {
      expect(e.status).toBe(200);
      expect(e.body.length).toBeGreaterThan(0);
    }

    // No image request was captured
    const imageEntries = entries.filter(e => e.url.includes('favicon.ico'));
    expect(imageEntries.length).toBe(0);

    // Replay returns the same body via context.request.fetch
    const xhrEntry = entries.find(e => e.url.includes('kind=xhr'));
    expect(xhrEntry).toBeDefined();
    const replay = await store.replay(ctx, xhrEntry!.id, { maxChars: 4000 });
    expect(replay.status).toBe(200);
    expect(replay.text.length).toBeGreaterThan(0);
    expect(replay.url).toContain('/echo?kind=xhr');

    await store.detach();
  });

  it('list filter narrows by URL substring', async () => {
    if (!BROWSER_OK) {
      console.log('  [skip] Playwright browser revision 1208 not installed');
      return;
    }
    const { url } = startTestServer();
    browser = await chromium.launch();
    const ctx = await browser.newContext();
    const page = await ctx.newPage();

    const store = new CaptureStore();
    await store.attach(page);
    await page.goto(`${url}/capture-page.html`);
    await page.waitForFunction(
      () => {
        const el = document.getElementById('out');
        return el && el.textContent && !el.textContent.startsWith('pending');
      },
      { timeout: 5000 }
    );

    const filtered = store.list('kind=fetch');
    for (const e of filtered) {
      expect(e.url).toContain('kind=fetch');
    }
    expect(filtered.length).toBeGreaterThanOrEqual(1);

    await store.detach();
  });

  it('replay with query override re-issues with new params', async () => {
    if (!BROWSER_OK) {
      console.log('  [skip] Playwright browser revision 1208 not installed');
      return;
    }
    const { url } = startTestServer();
    browser = await chromium.launch();
    const ctx = await browser.newContext();
    const page = await ctx.newPage();

    const store = new CaptureStore();
    await store.attach(page);
    await page.goto(`${url}/capture-page.html`);
    await page.waitForFunction(
      () => {
        const el = document.getElementById('out');
        return el && el.textContent && !el.textContent.startsWith('pending');
      },
      { timeout: 5000 }
    );

    const xhrEntry = store.list('kind=xhr')[0];
    expect(xhrEntry).toBeDefined();

    const replay = await store.replay(ctx, xhrEntry.id, {
      query: { kind: 'replayed', extra: '1' },
    });
    expect(replay.url).toContain('kind=replayed');
    expect(replay.url).toContain('extra=1');

    await store.detach();
  });

  it('replay throws on unknown id', async () => {
    if (!BROWSER_OK) {
      console.log('  [skip] Playwright browser revision 1208 not installed');
      return;
    }
    browser = await chromium.launch();
    const ctx = await browser.newContext();
    const store = new CaptureStore();
    await expect(store.replay(ctx, 9999)).rejects.toThrow(/No captured request/);
  });
});
