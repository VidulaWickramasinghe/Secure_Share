/** Thin, same-origin client for the Secure Share REST API. */

import {
  authorizedFetch,
  ensureCsrfToken,
  handleUnauthorized,
} from "./auth.js";

const STATUS_MESSAGES = {
  400: "Please check the request and try again.",
  401: "Please sign in to continue.",
  403: "You are not authorized to perform this action.",
  404: "The requested item could not be found.",
  409: "That action conflicts with the current state.",
  413: "The selected file is too large.",
  429: "Too many requests. Please wait and try again.",
  500: "Something went wrong on the server. Please try again.",
};

export class ApiError extends Error {
  constructor(message, status = 0, payload = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

function fallbackForStatus(status) {
  return STATUS_MESSAGES[status] || "The request could not be completed.";
}

async function parseResponseBody(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (_error) {
    return null;
  }
}

async function errorFromResponse(response) {
  const payload = await parseResponseBody(response);
  const apiMessage =
    typeof payload?.error === "string" && payload.error.trim()
      ? payload.error.trim()
      : null;
  return new ApiError(
    apiMessage || fallbackForStatus(response.status),
    response.status,
    payload,
  );
}

async function protectedJson(path, options = {}) {
  const response = await authorizedFetch(path, options);
  if (!response.ok) {
    throw await errorFromResponse(response);
  }
  return parseResponseBody(response);
}

async function publicJson(path, options = {}) {
  const response = await window.fetch(path, {
    ...options,
    cache: "no-store",
    // Public account-action endpoints never need ambient authentication.
    // Omitting cookies also prevents an unrelated signed-in account from
    // becoming part of a recovery or verification request.
    credentials: "omit",
  });
  if (!response.ok) {
    throw await errorFromResponse(response);
  }
  return parseResponseBody(response);
}

export function registerAccount({ username, email, password }) {
  return publicJson("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password }),
  });
}

export function requestEmailVerification() {
  return protectedJson("/api/auth/email-verification/request", {
    method: "POST",
  });
}

export function confirmEmailVerification(token) {
  return publicJson("/api/auth/email-verification/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
}

export function requestPasswordReset(email) {
  return publicJson("/api/auth/password-reset/request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
}

export function confirmPasswordReset(token, newPassword) {
  return publicJson("/api/auth/password-reset/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password: newPassword }),
  });
}

export async function listFiles() {
  const payload = await protectedJson("/api/files");
  return Array.isArray(payload?.files) ? payload.files : [];
}

export function getFilePermissions(fileId) {
  return protectedJson(
    `/api/files/${encodeURIComponent(fileId)}/permissions`,
  ).then((payload) =>
    Array.isArray(payload?.permissions) ? payload.permissions : [],
  );
}

export function grantFilePermission(fileId, userId) {
  return protectedJson(
    `/api/files/${encodeURIComponent(fileId)}/permissions`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: userId }),
    },
  );
}

export function revokeFilePermission(fileId, userId) {
  return protectedJson(
    `/api/files/${encodeURIComponent(fileId)}/permissions/${encodeURIComponent(userId)}`,
    { method: "DELETE" },
  );
}

export function deleteFile(fileId) {
  return protectedJson(`/api/files/${encodeURIComponent(fileId)}`, {
    method: "DELETE",
  });
}

/**
 * Upload through XMLHttpRequest so the dashboard can show byte progress.
 * The backend remains authoritative for authentication, size, and filename
 * validation. The browser sets the multipart boundary itself.
 */
export async function uploadFile(file, onProgress = null) {
  const csrfToken = await ensureCsrfToken();
  const formData = new FormData();
  formData.append("file", file);

  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", "/api/files", true);
    request.withCredentials = true;
    request.setRequestHeader("X-CSRF-Token", csrfToken);
    request.setRequestHeader("Accept", "application/json");

    request.upload.addEventListener("progress", (event) => {
      if (typeof onProgress !== "function") {
        return;
      }
      if (event.lengthComputable && event.total > 0) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      } else {
        onProgress(null);
      }
    });

    request.addEventListener("load", () => {
      let payload = null;
      if (request.responseText) {
        try {
          payload = JSON.parse(request.responseText);
        } catch (_error) {
          payload = null;
        }
      }

      if (request.status >= 200 && request.status < 300) {
        if (typeof onProgress === "function") {
          onProgress(100);
        }
        resolve(payload);
        return;
      }

      const message =
        typeof payload?.error === "string" && payload.error.trim()
          ? payload.error.trim()
          : fallbackForStatus(request.status);
      if (request.status === 401) {
        handleUnauthorized();
      }
      reject(new ApiError(message, request.status, payload));
    });

    request.addEventListener("error", () => {
      reject(
        new ApiError(
          "The upload could not reach the server. Check your connection and try again.",
        ),
      );
    });
    request.addEventListener("abort", () => {
      reject(new ApiError("The upload was cancelled."));
    });
    request.send(formData);
  });
}

/** Return authorized bytes; callers decide how to present the save dialog. */
export async function downloadFile(fileId) {
  const response = await authorizedFetch(
    `/api/files/${encodeURIComponent(fileId)}/download`,
  );
  if (!response.ok) {
    throw await errorFromResponse(response);
  }
  return response.blob();
}
