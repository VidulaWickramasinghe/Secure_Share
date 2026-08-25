/** Browser authentication backed by an HttpOnly server-side session cookie. */

const NOTICE_STORAGE_KEY = "secure-share.auth-notice";
const LEGACY_TOKEN_STORAGE_KEY = "secure-share.auth-token";
const DEFAULT_CSRF_COOKIE_NAME = "secure_share_csrf";
export const AUTH_NOTICE_EVENT = "secure-share:auth-notice";

export class AuthenticationError extends Error {
  constructor(message, status = 401) {
    super(message);
    this.name = "AuthenticationError";
    this.status = status;
  }
}

function readSessionValue(key) {
  try {
    return window.sessionStorage.getItem(key);
  } catch (_error) {
    return null;
  }
}

function removeSessionValue(key) {
  try {
    window.sessionStorage.removeItem(key);
  } catch (_error) {
    // Notices are best-effort and never contain authentication credentials.
  }
}

// Remove credentials left by pre-cookie releases without ever reading them.
removeSessionValue(LEGACY_TOKEN_STORAGE_KEY);

async function responseError(response, fallbackMessage) {
  let message = fallbackMessage;
  try {
    const payload = await response.json();
    if (typeof payload?.error === "string" && payload.error.trim()) {
      message = payload.error;
    }
  } catch (_error) {
    // A malformed or empty error body must not hide the useful fallback.
  }
  return new AuthenticationError(message, response.status);
}

function sameOriginUrl(input) {
  const rawUrl = input instanceof Request ? input.url : input;
  const url = new URL(rawUrl, window.location.origin);
  if (url.origin !== window.location.origin) {
    throw new TypeError("Authenticated requests must use the Secure Share origin.");
  }
  return url;
}

function csrfCookieName() {
  return (
    document
      .querySelector('meta[name="secure-share-csrf-cookie"]')
      ?.getAttribute("content") || DEFAULT_CSRF_COOKIE_NAME
  );
}

function readCookie(name) {
  const encodedName = `${encodeURIComponent(name)}=`;
  for (const item of document.cookie.split(";")) {
    const candidate = item.trim();
    if (!candidate.startsWith(encodedName)) {
      continue;
    }
    const value = candidate.slice(encodedName.length);
    try {
      return decodeURIComponent(value);
    } catch (_error) {
      return null;
    }
  }
  return null;
}

export function getCsrfToken() {
  const token = readCookie(csrfCookieName());
  return typeof token === "string" && token.length > 0 ? token : null;
}

export function setAuthNotice(message) {
  if (typeof message === "string" && message.trim()) {
    try {
      window.sessionStorage.setItem(NOTICE_STORAGE_KEY, message.trim());
      return true;
    } catch (_error) {
      // A blocked storage API must never prevent logout or navigation.
    }
  }
  return false;
}

export function consumeAuthNotice() {
  const notice = readSessionValue(NOTICE_STORAGE_KEY);
  removeSessionValue(NOTICE_STORAGE_KEY);
  return notice;
}

export function handleUnauthorized(
  message = "Your session has expired. Please sign in again.",
) {
  setAuthNotice(message);
  window.dispatchEvent(
    new CustomEvent(AUTH_NOTICE_EVENT, { detail: { message } }),
  );

  const isLoginSurface =
    window.location.pathname === "/login" ||
    document.body?.dataset.page === "login";
  if (!isLoginSurface) {
    window.location.replace("/login");
  }
}

export async function refreshCsrfToken({ redirectOnUnauthorized = true } = {}) {
  const response = await window.fetch("/api/auth/csrf", {
    method: "GET",
    headers: { "X-Secure-Share-CSRF-Restore": "1" },
    cache: "no-store",
    credentials: "same-origin",
  });
  if (response.status === 401) {
    const error = await responseError(response, "Authentication is required.");
    if (redirectOnUnauthorized) {
      handleUnauthorized();
    }
    throw error;
  }
  if (!response.ok) {
    throw await responseError(response, "Unable to prepare a secure request.");
  }

  const token = getCsrfToken();
  if (!token) {
    throw new AuthenticationError(
      "The browser did not accept the CSRF protection cookie.",
      500,
    );
  }
  return token;
}

export async function ensureCsrfToken(options = {}) {
  return getCsrfToken() || refreshCsrfToken(options);
}

function requestMethod(input, options) {
  if (typeof options.method === "string") {
    return options.method.toUpperCase();
  }
  if (input instanceof Request) {
    return input.method.toUpperCase();
  }
  return "GET";
}

function isUnsafeMethod(method) {
  return !["GET", "HEAD", "OPTIONS"].includes(method);
}

/**
 * Send an authenticated same-origin request. The browser supplies the HttpOnly
 * session cookie; JavaScript supplies only the separate CSRF token when needed.
 */
export async function authorizedFetch(
  input,
  options = {},
  { redirectOnUnauthorized = true } = {},
) {
  const url = sameOriginUrl(input);
  const headers = new Headers(options.headers || {});
  if (isUnsafeMethod(requestMethod(input, options))) {
    headers.set(
      "X-CSRF-Token",
      await ensureCsrfToken({ redirectOnUnauthorized }),
    );
  }

  const response = await window.fetch(url, {
    ...options,
    headers,
    cache: options.cache || "no-store",
    credentials: "same-origin",
  });

  if (response.status === 401) {
    const error = await responseError(response, "Authentication is required.");
    if (redirectOnUnauthorized) {
      handleUnauthorized();
    }
    throw error;
  }
  return response;
}

/** Authenticate without ever exposing the session credential to JavaScript. */
export async function login(identifier, password) {
  const response = await window.fetch("/api/auth/browser-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier, password }),
    cache: "no-store",
    credentials: "same-origin",
  });

  if (!response.ok) {
    throw await responseError(
      response,
      response.status === 401
        ? "Invalid username/email or password."
        : "Unable to sign in right now.",
    );
  }

  let payload;
  try {
    payload = await response.json();
  } catch (_error) {
    throw new AuthenticationError(
      "The server returned an invalid authentication response.",
      500,
    );
  }
  if (!payload?.user || typeof payload.user !== "object" || !getCsrfToken()) {
    throw new AuthenticationError(
      "The server returned an invalid authentication response.",
      500,
    );
  }
  return payload;
}

export async function getCurrentUser({ redirectOnUnauthorized = true } = {}) {
  const response = await authorizedFetch(
    "/api/auth/me",
    {},
    { redirectOnUnauthorized },
  );
  if (!response.ok) {
    throw await responseError(response, "Unable to load your account.");
  }
  const payload = await response.json();
  if (!payload?.user || typeof payload.user !== "object") {
    throw new AuthenticationError(
      "The server returned an invalid account response.",
      500,
    );
  }
  return payload.user;
}

/** Revoke the active server-side session and let the server clear its cookies. */
export async function logout() {
  try {
    const response = await authorizedFetch(
      "/api/auth/logout",
      { method: "POST" },
      { redirectOnUnauthorized: false },
    );
    if (!response.ok) {
      throw await responseError(response, "Unable to sign out securely.");
    }
    return response.json();
  } catch (error) {
    // An expired/revoked session is already logged out, and the 401 response
    // clears stale cookies. Network failures are not treated as success.
    if (error?.status === 401) {
      return { message: "Logged out." };
    }
    throw error;
  }
}
