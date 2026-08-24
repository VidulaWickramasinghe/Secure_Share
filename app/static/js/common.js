/** Shared, dependency-free UI helpers. */

const TOAST_LIFETIME_MS = 6000;

export function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "Unknown size";
  }
  if (bytes === 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  const unitIndex = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  const amount = bytes / 1024 ** unitIndex;
  const digits = unitIndex === 0 || amount >= 10 ? 0 : 1;
  return `${amount.toFixed(digits)} ${units[unitIndex]}`;
}

export function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Unknown date";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function errorMessage(error, fallback = "The request could not be completed.") {
  if (typeof error?.message === "string" && error.message.trim()) {
    return error.message.trim();
  }
  return fallback;
}

export function setFormAlert(element, message = "", type = "error") {
  if (!element) {
    return;
  }
  const hasMessage = typeof message === "string" && message.trim().length > 0;
  element.textContent = hasMessage ? message.trim() : "";
  element.hidden = !hasMessage;
  element.classList.toggle("alert--error", hasMessage && type === "error");
  element.classList.toggle("alert--success", hasMessage && type === "success");
  element.classList.toggle("alert--info", hasMessage && type === "info");
  element.setAttribute("role", type === "error" ? "alert" : "status");
  element.setAttribute("aria-live", type === "error" ? "assertive" : "polite");
}

export function clearFormAlert(element) {
  setFormAlert(element);
}

export function setButtonBusy(button, busy, busyLabel = "Working…") {
  if (!button) {
    return;
  }
  if (busy) {
    if (!button.dataset.idleLabel) {
      button.dataset.idleLabel = button.textContent.trim();
    }
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.textContent = busyLabel;
    return;
  }

  button.disabled = false;
  button.removeAttribute("aria-busy");
  if (button.dataset.idleLabel) {
    button.textContent = button.dataset.idleLabel;
    delete button.dataset.idleLabel;
  }
}

export function createElement(tagName, className = "", text = null) {
  const element = document.createElement(tagName);
  if (className) {
    element.className = className;
  }
  if (text !== null && text !== undefined) {
    element.textContent = String(text);
  }
  return element;
}

export function showToast(message, type = "info") {
  const region = document.querySelector("#toast-region");
  if (!region || !message) {
    return;
  }

  const safeType = ["success", "error", "info"].includes(type) ? type : "info";
  const toast = createElement("div", `toast toast--${safeType}`);
  toast.setAttribute("role", safeType === "error" ? "alert" : "status");
  toast.setAttribute("aria-atomic", "true");

  const text = createElement("p", "toast__message", message);
  const close = createElement("button", "toast__close", "×");
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss notification");
  close.addEventListener("click", () => toast.remove());

  toast.append(text, close);
  region.append(toast);

  window.setTimeout(() => {
    if (toast.isConnected) {
      toast.remove();
    }
  }, TOAST_LIFETIME_MS);
}

export function safeDownloadName(value) {
  if (typeof value !== "string" || !value.trim()) {
    return "download";
  }
  const basename = value.trim().split(/[\\/]/).pop();
  return basename || "download";
}

export function saveBlob(blob, filename) {
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = safeDownloadName(filename);
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
}
