// In dev and preview, Vite proxies /api to the Express server. Set VITE_API_BASE to
// an absolute URL (e.g. https://api.example.com/api) when the API is hosted elsewhere.
export const API_BASE = String(import.meta.env?.VITE_API_BASE || '/api').replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(message, { status = 0, code = null, data = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.data = data;
  }
}

export async function apiFetch(path, { signal, method = 'GET', headers = {}, body } = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      signal,
      headers: {
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    if (err?.name === 'AbortError') throw err;
    throw new ApiError('Network error', { code: 'network_error' });
  }

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    throw new ApiError(data?.error || `HTTP ${response.status}`, {
      status: response.status,
      code: data?.reasonCode || data?.error || null,
      data,
    });
  }
  return data;
}

export const isAbortError = (err) => err?.name === 'AbortError';

export function describeApiError(err) {
  if (!err) return 'Unknown error';
  if (err.status === 429) return 'Too many requests. Try again in a minute.';
  if (err.code === 'network_error') return 'Cannot reach the API server.';
  const reason = String(err.code || '').toLowerCase();
  if (reason === 'invalid_model') return 'The configured AI model is invalid.';
  if (reason === 'timeout') return 'The AI provider timed out.';
  if (reason === 'throttled') return 'The AI provider is throttled.';
  if (reason === 'no_provider') return 'No AI provider is configured.';
  if (err.status >= 500) return 'The API server reported an error.';
  return 'Request failed.';
}
