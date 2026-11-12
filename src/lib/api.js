/**
 * CloudVuln API Client
 * - Reads JWT from localStorage (set by AuthContext on login/register)
 * - Auto-refreshes expired access tokens using the stored refresh token
 * - In-memory response caching with TTL
 * - XSS prevention: all params URL-encoded
 *
 * Token keys in localStorage:
 *   cloudvuln_access_token
 *   cloudvuln_refresh_token
 */

import { TOKEN_KEY, REFRESH_KEY } from '../context/AuthContext';

const BASE_URL = import.meta.env.VITE_API_URL || '/api';
const CACHE_TTL_MS = 30_000; // 30 seconds default


// ─── Simple in-memory cache ───────────────────────────────────────
const cache = new Map();

function getCacheKey(url, options = {}) {
  return `${options.method || 'GET'}::${url}`;
}

function getFromCache(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.data;
}

function setCache(key, data, ttl = CACHE_TTL_MS) {
  cache.set(key, { data, expiresAt: Date.now() + ttl });
}

export function invalidateCache(pattern) {
  for (const key of cache.keys()) {
    if (!pattern || key.includes(pattern)) {
      cache.delete(key);
    }
  }
}

// ─── Token retrieval from localStorage ───────────────────────────
function getAccessToken() {
  return localStorage.getItem(TOKEN_KEY) || null;
}

function getRefreshTokenValue() {
  return localStorage.getItem(REFRESH_KEY) || null;
}

// ─── Silent token refresh ─────────────────────────────────────────
async function tryRefreshToken() {
  const refreshToken = getRefreshTokenValue();
  if (!refreshToken) return null;

  try {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.access_token) {
      localStorage.setItem(TOKEN_KEY, data.access_token);
      if (data.refresh_token) localStorage.setItem(REFRESH_KEY, data.refresh_token);
      return data.access_token;
    }
  } catch {
    // Network error during refresh — return null
  }
  return null;
}

// ─── Core fetch wrapper ───────────────────────────────────────────
async function apiFetch(endpoint, options = {}, useCache = false, cacheTtl = CACHE_TTL_MS) {
  const url = `${BASE_URL}${endpoint}`;
  const cacheKey = getCacheKey(url, options);

  // Cache check (GET only)
  if (useCache && (!options.method || options.method === 'GET')) {
    const cached = getFromCache(cacheKey);
    if (cached) return cached;
  }

  const token = getAccessToken();

  const headers = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  let response = await fetch(url, {
    ...options,
    headers,
  });

  // If access token expired, attempt silent refresh and retry once
  if (response.status === 401) {
    const newToken = await tryRefreshToken();
    if (newToken) {
      const retryHeaders = {
        ...headers,
        Authorization: `Bearer ${newToken}`,
      };
      response = await fetch(url, {
        ...options,
        headers: retryHeaders,
      });
    } else {
      // Refresh failed — clear tokens so the app redirects to login
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(REFRESH_KEY);
      throw new Error('Session expired. Please sign in again.');
    }
  }

  // Parse response
  const contentType = response.headers.get('Content-Type') || '';
  let data;
  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const message =
      (typeof data === 'object' && (data.message || data.detail)) ||
      `Request failed with status ${response.status}`;
    throw new Error(message);
  }

  // Store in cache
  if (useCache && (!options.method || options.method === 'GET')) {
    setCache(cacheKey, data, cacheTtl);
  }

  return data;
}

// ─── Public API methods ───────────────────────────────────────────

export const api = {
  // Auth
  login: (email, password) =>
    apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  register: (email, password, full_name) =>
    apiFetch('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name }),
    }),

  me: () => apiFetch('/auth/me', {}, true, 60_000),

  logout: () => apiFetch('/auth/logout', { method: 'POST' }),

  refreshToken: (refreshToken) =>
    apiFetch('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    }),

  // Dashboard
  dashboardSummary: () =>
    apiFetch('/dashboard/summary', {}, true, 30_000),

  riskStatistics: () =>
    apiFetch('/dashboard/risk-statistics', {}, true, 30_000),

  recentScans: () =>
    apiFetch('/dashboard/recent-scans', {}, true, 15_000),

  activity: () =>
    apiFetch('/dashboard/activity', {}, true, 15_000),

  // Scans
  getScans: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') {
        qs.append(k, String(v));
      }
    });
    const queryString = qs.toString();
    return apiFetch(`/scans${queryString ? `?${queryString}` : ''}`, {}, false);
  },

  getScan: (scanRef) => apiFetch(`/scans/${encodeURIComponent(scanRef)}`, {}, true, 60_000),

  createScan: (data) => {
    invalidateCache('/scans');
    invalidateCache('/dashboard');
    return apiFetch('/scans', { method: 'POST', body: JSON.stringify(data) });
  },

  deleteScan: (scanRef) => {
    invalidateCache('/scans');
    invalidateCache('/dashboard');
    return apiFetch(`/scans/${encodeURIComponent(scanRef)}`, { method: 'DELETE' });
  },

  // Analysis
  analyzeTarget: (targetUrl) =>
    apiFetch('/analysis/target', {
      method: 'POST',
      body: JSON.stringify({ target_url: targetUrl }),
    }),

  analyzeDns: (domain, dkimSelector) =>
    apiFetch('/analysis/dns', {
      method: 'POST',
      body: JSON.stringify({ domain, dkim_selector: dkimSelector || undefined }),
    }),

  analyzeDependencies: (packageList, ecosystem = 'npm') =>
    apiFetch('/analysis/dependencies', {
      method: 'POST',
      body: JSON.stringify({ package_list: packageList, ecosystem }),
    }),

  analyzeCookies: (targetUrl) =>
    apiFetch('/analysis/cookies', {
      method: 'POST',
      body: JSON.stringify({ target_url: targetUrl }),
    }),

  runAllScans: (targetUrl, packageList, ecosystem = 'npm', dkimSelector) =>
    apiFetch('/analysis/run-all', {
      method: 'POST',
      body: JSON.stringify({
        target_url: targetUrl,
        package_list: packageList || undefined,
        ecosystem,
        dkim_selector: dkimSelector || undefined,
      }),
    }),

  searchCve: (query) =>
    apiFetch(`/cve/search?query=${encodeURIComponent(query)}`, {}, true, 120_000),

  whoisLookup: (domain) =>
    apiFetch(`/whois/lookup?domain=${encodeURIComponent(domain)}`, {}, true, 120_000),

  analyzeOwasp: (targetUrl) =>
    apiFetch('/analysis/owasp', {
      method: 'POST',
      body: JSON.stringify({ target_url: targetUrl }),
    }),

  // Reports
  getReports: () => apiFetch('/reports', {}, false),
  getReport: (scanRef) => apiFetch(`/reports/${encodeURIComponent(scanRef)}`, {}, false),
  getReportHtmlUrl: (scanRef) => `/api/reports/${encodeURIComponent(scanRef)}/html`,
  getReportDownloadUrl: (scanRef, format = 'html') =>
    `/api/reports/${encodeURIComponent(scanRef)}/download?format=${format}`,

  // Scan Comparison & Security Trends
  getComparisonOptions: () => apiFetch('/scans/comparison-options', {}, false),
  compareScans: (prevRef, latestRef) =>
    apiFetch(`/scans/compare/${encodeURIComponent(prevRef)}/${encodeURIComponent(latestRef)}`, {}, false),
  getScanTrend: (target) =>
    apiFetch(`/scans/trend${target ? `?target=${encodeURIComponent(target)}` : ''}`, {}, false),
  getComparisonDownloadUrl: (prevRef, latestRef, format = 'html') =>
    `/api/scans/compare/${encodeURIComponent(prevRef)}/${encodeURIComponent(latestRef)}/download?format=${format}`,

  health: () => apiFetch('/health', {}, false),
};

// ─── Date formatting utility ──────────────────────────────────────
export function formatScanDate(dateStr) {
  if (!dateStr) return '—';
  try {
    let clean = String(dateStr).trim();
    if (clean.includes(' UTC')) {
      clean = clean.replace(' UTC', 'Z').replace(' ', 'T');
    } else if (!clean.includes('Z') && !clean.includes('+') && !clean.includes('T')) {
      clean = clean.replace(' ', 'T') + 'Z';
    }
    const d = new Date(clean);
    if (isNaN(d.getTime())) return dateStr;

    const day = String(d.getUTCDate()).padStart(2, '0');
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[d.getUTCMonth()];
    const year = d.getUTCFullYear();

    let hours = d.getUTCHours();
    const minutes = String(d.getUTCMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12 || 12;
    const hourStr = String(hours).padStart(2, '0');

    return `${day} ${month} ${year}, ${hourStr}:${minutes} ${ampm} UTC`;
  } catch {
    return dateStr;
  }
}

// ─── Legacy helpers (kept for compatibility) ──────────────────────
export function setTokens(access, refresh) {
  if (access) localStorage.setItem(TOKEN_KEY, access);
  if (refresh) localStorage.setItem(REFRESH_KEY, refresh);
}
export function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
}
export function getToken() { return getAccessToken(); }
export function getRefreshToken() { return getRefreshTokenValue(); }

export default api;
