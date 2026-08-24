/**
 * Browser authentication for Secure Share.
 *
 * The API deliberately uses opaque bearer tokens. They are kept in
 * sessionStorage so they disappear when the tab is closed, and they are never
 * placed in URLs, page content, or logs.
 */

const TOKEN_STORAGE_KEY = "secure-share.auth-token";
const NOTICE_STORAGE_KEY = "secure-share.auth-notice";
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

function writeSessionValue(key, value) {
  try {
    window.sessionStorage.setItem(key, value);
  } catch (_error) {
    throw new AuthenticationError(
      "Authentication storage is unavailable in this browser.",
      500,
    );
  }
}

function removeSessionValue(key) {
  try {
    window.sessionStorage.removeItem(key);
  } catch (_error) {
    // There is nothing more the client can safely do if storage is blocked.
  }
}

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

export function getAuthToken() {
  const token = readSessionValue(TOKEN_STORAGE_KEY);
  return typeof token === "string" && token.length > 0 ? token : null;
}

function storeAuthToken(token) {
  if (typeof token !== "string" || !token.trim()) {
    throw new AuthenticationError(
      "The server returned an invalid authentication response.",
      500,
    );
  }
  writeSessionValue(TOKEN_STORAGE_KEY, token);
}

export function clearAuthentication() {
  removeSessionValue(TOKEN_STORAGE_KEY);
}

export function isAuthenticated() {
  return getAuthToken() !== null;
}

export function setAuthNotice(message) {
  if (typeof message === "string" && message.trim()) {
    try {
      window.sessionStorage.setItem(NOTICE_STORAGE_KEY, message.trim());
      return true;
    } catch (_error) {
      // Notices are best-effort. A blocked storage API must never prevent a
      // logout or expired-session redirect from completing.
    }
  }
  return false;
}

export function consumeAuthNotice() {
  const notice = readSessionValue(NOTICE_STORAGE_KEY);
  removeSessionValue(NOTICE_STORAGE_KEY);
  return notice;
}

/**
 * Clear a rejected session and move protected pages back to the login screen.
 */
export function handleUnauthorized(
  message = "Your session has expired. Please sign in again.",
) {
  clearAuthentication();
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

export function requireAuthentication() {
  if (isAuthenticated()) {
    return true;
  }
  handleUnauthorized("Please sign in to continue.");
  return false;
}

/**
 * Send a protected same-origin request with the current bearer token.
 * A backend 401 is authoritative: the local token is removed immediately.
 */
export async function authorizedFetch(input, options = {}) {
  const token = getAuthToken();
  if (!token) {
    handleUnauthorized("Please sign in to continue.");
    throw new AuthenticationError("Authentication is required.");
  }

  const url = sameOriginUrl(input);
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${token}`);

  const response = await window.fetch(url, {
    ...options,
    headers,
    cache: options.cache || "no-store",
    credentials: "same-origin",
  });

  if (response.status === 401) {
    handleUnauthorized();
    throw await responseError(response, "Authentication is required.");
  }
  return response;
}

/** Authenticate with either a username or email address. */
export async function login(identifier, password) {
  const response = await window.fetch("/api/auth/login", {
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
  storeAuthToken(payload?.token);
  return payload;
}

export async function getCurrentUser() {
  const response = await authorizedFetch("/api/auth/me");
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

/**
 * Ask the server to revoke the active session, then always remove the local
 * token. A missing/expired server session already satisfies logout.
 */
export async function logout() {
  const token = getAuthToken();
  if (!token) {
    clearAuthentication();
    return { message: "Logged out." };
  }

  let response;
  try {
    response = await window.fetch("/api/auth/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      credentials: "same-origin",
    });
  } finally {
    clearAuthentication();
  }

  if (response.status === 401) {
    return { message: "Logged out." };
  }
  if (!response.ok) {
    throw await responseError(response, "Unable to confirm logout with the server.");
  }
  return response.json();
}
