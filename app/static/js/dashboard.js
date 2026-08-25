import {
  getCurrentUser,
  logout,
  setAuthNotice,
} from "./auth.js";
import {
  deleteFile,
  downloadFile,
  getFilePermissions,
  grantFilePermission,
  listFiles,
  requestEmailVerification,
  revokeFilePermission,
  uploadFile,
} from "./api.js";
import {
  clearFormAlert,
  createElement,
  errorMessage,
  formatBytes,
  formatDate,
  saveBlob,
  setButtonBusy,
  setFormAlert,
  showToast,
} from "./common.js";

const elements = {};
const state = {
  currentUser: null,
  files: [],
  permissionsFile: null,
  deleteFile: null,
};

function collectElements() {
  const ids = [
    "dashboard-loading",
    "dashboard-content",
    "account-username",
    "account-username-detail",
    "account-email",
    "email-verification-status",
    "email-verification-banner",
    "resend-verification-button",
    "account-sharing-id",
    "logout-button",
    "upload-form",
    "file-input",
    "selected-file",
    "selected-file-size",
    "upload-submit",
    "upload-alert",
    "upload-progress-container",
    "upload-progress",
    "upload-status",
    "owned-files",
    "owned-empty",
    "shared-files",
    "shared-empty",
    "permissions-dialog",
    "permissions-file-name",
    "permissions-list",
    "permissions-empty",
    "permission-form",
    "permission-user-id",
    "permission-submit",
    "permission-alert",
    "permissions-close",
    "delete-dialog",
    "delete-file-name",
    "delete-confirm",
    "delete-cancel",
  ];

  for (const id of ids) {
    elements[id] = document.getElementById(id);
  }
  if (elements["selected-file-size"]) {
    elements["selected-file-size"].dataset.emptyLabel =
      elements["selected-file-size"].textContent.trim();
  }
}

function setDashboardLoading(isLoading) {
  if (elements["dashboard-loading"]) {
    elements["dashboard-loading"].hidden = !isLoading;
  }
  if (elements["dashboard-content"]) {
    elements["dashboard-content"].hidden = isLoading;
  }
}

function setListBusy(container, isBusy) {
  if (!container) {
    return;
  }
  if (isBusy) {
    container.setAttribute("aria-busy", "true");
  } else {
    container.removeAttribute("aria-busy");
  }
}

function renderListStatus(container, emptyState, message) {
  if (!container) {
    return;
  }
  container.replaceChildren(createElement("p", "loading-state", message));
  if (emptyState) {
    emptyState.hidden = true;
  }
}

function setFilesLoading() {
  setListBusy(elements["owned-files"], true);
  setListBusy(elements["shared-files"], true);
  renderListStatus(
    elements["owned-files"],
    elements["owned-empty"],
    "Loading your files…",
  );
  renderListStatus(
    elements["shared-files"],
    elements["shared-empty"],
    "Loading shared files…",
  );
}

function displayAccount(user) {
  if (elements["account-username"]) {
    elements["account-username"].textContent = user.username || "Account";
  }
  if (elements["account-username-detail"]) {
    elements["account-username-detail"].textContent =
      user.username || "Account";
  }
  if (elements["account-email"]) {
    elements["account-email"].textContent = user.email || "";
  }
  const isVerified = user.email_verified === true;
  if (elements["email-verification-status"]) {
    elements["email-verification-status"].hidden = isVerified;
  }
  if (elements["email-verification-banner"]) {
    elements["email-verification-banner"].hidden = isVerified;
  }
  if (elements["account-sharing-id"]) {
    elements["account-sharing-id"].textContent = String(user.id ?? "—");
  }
}

function createBadge(label, modifier) {
  const badge = createElement("span", `badge badge--${modifier}`, label);
  return badge;
}

function createDetail(label, value) {
  const detail = createElement("div", "file-card__detail");
  detail.append(
    createElement("dt", "file-card__detail-label", label),
    createElement("dd", "file-card__detail-value", value),
  );
  return detail;
}

function createActionButton(label, modifier, accessibleLabel, handler) {
  const button = createElement(
    "button",
    `button button--${modifier} button--small`,
    label,
  );
  button.type = "button";
  button.setAttribute("aria-label", accessibleLabel);
  button.addEventListener("click", () => handler(button));
  return button;
}

function permissionCount(file) {
  const count = Number(file.authorized_user_count);
  return Number.isSafeInteger(count) && count >= 0 ? count : 0;
}

function fileName(file) {
  return typeof file.original_filename === "string" && file.original_filename
    ? file.original_filename
    : "Unnamed file";
}

function createFileCard(file, accessType) {
  const name = fileName(file);
  const card = createElement("article", "file-card");
  const icon = createElement("div", "file-card__icon", "🔒");
  icon.setAttribute("aria-hidden", "true");

  const body = createElement("div", "file-card__body");
  const heading = createElement("div", "file-card__heading");
  const title = createElement("h3", "file-card__name", name);
  const badges = createElement("div", "file-card__badges");

  if (accessType === "owner") {
    badges.append(createBadge("Owner", "owner"), createBadge("Private", "private"));
  } else {
    badges.append(createBadge("Shared with you", "shared"));
  }
  heading.append(title, badges);

  const details = createElement("dl", "file-card__details");
  details.append(
    createDetail("Size", formatBytes(file.file_size)),
    createDetail("Uploaded", formatDate(file.created_at)),
  );

  if (accessType === "owner") {
    const count = permissionCount(file);
    details.append(
      createDetail("Owner", "You"),
      createDetail(
        "Access",
        `${count} authorized user${count === 1 ? "" : "s"}`,
      ),
    );
  } else {
    const ownerName =
      typeof file.owner?.username === "string" && file.owner.username
        ? file.owner.username
        : "Unknown owner";
    details.append(createDetail("Owner", ownerName));
  }

  const actions = createElement("div", "file-card__actions");
  actions.append(
    createActionButton(
      "Download",
      "primary",
      `Download ${name}`,
      (button) => void handleDownload(file, button),
    ),
  );

  // These controls are presentation affordances only. The API repeats the
  // ownership check for every permission and delete request.
  if (accessType === "owner") {
    actions.append(
      createActionButton(
        "Manage Access",
        "secondary",
        `Manage access to ${name}`,
        () => void openPermissionsDialog(file),
      ),
      createActionButton(
        "Delete",
        "danger",
        `Delete ${name}`,
        () => openDeleteDialog(file),
      ),
    );
  }

  body.append(heading, details, actions);
  card.append(icon, body);
  return card;
}

function renderFiles(files) {
  const ownedFiles = files.filter((file) => file?.access_type === "owner");
  const sharedFiles = files.filter((file) => file?.access_type === "shared");

  if (elements["owned-files"]) {
    elements["owned-files"].replaceChildren(
      ...ownedFiles.map((file) => createFileCard(file, "owner")),
    );
    setListBusy(elements["owned-files"], false);
  }
  if (elements["owned-empty"]) {
    elements["owned-empty"].hidden = ownedFiles.length !== 0;
  }

  if (elements["shared-files"]) {
    elements["shared-files"].replaceChildren(
      ...sharedFiles.map((file) => createFileCard(file, "shared")),
    );
    setListBusy(elements["shared-files"], false);
  }
  if (elements["shared-empty"]) {
    elements["shared-empty"].hidden = sharedFiles.length !== 0;
  }
}

async function refreshFiles({ loading = true, quiet = false } = {}) {
  if (loading) {
    setFilesLoading();
  }

  try {
    state.files = await listFiles();
    renderFiles(state.files);
    return true;
  } catch (error) {
    setListBusy(elements["owned-files"], false);
    setListBusy(elements["shared-files"], false);
    renderListStatus(
      elements["owned-files"],
      elements["owned-empty"],
      "Your files could not be loaded.",
    );
    renderListStatus(
      elements["shared-files"],
      elements["shared-empty"],
      "Shared files could not be loaded.",
    );
    if (!quiet && error?.status !== 401) {
      showToast(errorMessage(error, "Unable to load your files."), "error");
    }
    return false;
  }
}

function downloadFailureMessage(error) {
  if (error?.status === 403) {
    return "You are no longer authorized to download this file.";
  }
  if (error?.status === 404) {
    return "This file could not be found or is no longer available.";
  }
  return errorMessage(error, "The file could not be downloaded.");
}

async function handleDownload(file, button) {
  setButtonBusy(button, true, "Downloading…");
  try {
    const blob = await downloadFile(file.id);
    saveBlob(blob, fileName(file));
    showToast(`${fileName(file)} downloaded.`, "success");
  } catch (error) {
    if (error?.status !== 401) {
      showToast(downloadFailureMessage(error), "error");
    }
    if (error?.status === 403 || error?.status === 404) {
      void refreshFiles({ loading: false, quiet: true });
    }
  } finally {
    setButtonBusy(button, false);
  }
}

function selectedUpload() {
  return elements["file-input"]?.files?.[0] || null;
}

function maximumUploadBytes() {
  const configured = Number(
    elements["upload-form"]?.dataset.maxUploadBytes,
  );
  return Number.isSafeInteger(configured) && configured > 0
    ? configured
    : null;
}

function updateSelectedUpload() {
  const file = selectedUpload();
  if (elements["selected-file"]) {
    elements["selected-file"].textContent = file
      ? file.name
      : "No file selected";
  }
  if (elements["selected-file-size"]) {
    elements["selected-file-size"].textContent = file
      ? formatBytes(file.size)
      : elements["selected-file-size"].dataset.emptyLabel || "";
  }
  if (elements["upload-submit"]) {
    elements["upload-submit"].disabled = !file;
  }
}

function updateUploadProgress(percent) {
  const progress = elements["upload-progress"];
  if (!progress) {
    return;
  }

  if (percent === null) {
    progress.removeAttribute("value");
    if (elements["upload-status"]) {
      elements["upload-status"].textContent = "Uploading file…";
    }
    return;
  }

  progress.max = 100;
  progress.value = percent;
  const message = percent < 100 ? `Uploading… ${percent}%` : "Finishing upload…";
  if (elements["upload-status"]) {
    elements["upload-status"].textContent = message;
  }
}

async function handleUpload(event) {
  event.preventDefault();
  clearFormAlert(elements["upload-alert"]);

  const file = selectedUpload();
  if (!file) {
    setFormAlert(elements["upload-alert"], "Choose a file to upload.");
    elements["file-input"]?.focus();
    return;
  }

  const maximum = maximumUploadBytes();
  if (maximum !== null && file.size > maximum) {
    const message = `The selected file is too large. The maximum size is ${formatBytes(maximum)}.`;
    setFormAlert(elements["upload-alert"], message);
    showToast(message, "error");
    elements["file-input"]?.focus();
    return;
  }

  setButtonBusy(elements["upload-submit"], true, "Uploading…");
  if (elements["file-input"]) {
    elements["file-input"].disabled = true;
  }
  if (elements["upload-progress-container"]) {
    elements["upload-progress-container"].hidden = false;
  }
  updateUploadProgress(0);

  try {
    await uploadFile(file, updateUploadProgress);
    showToast(`${file.name} uploaded securely.`, "success");
    elements["upload-form"]?.reset();
    updateSelectedUpload();
    setFormAlert(
      elements["upload-alert"],
      "Upload complete. The file is private until you grant access.",
      "success",
    );
    await refreshFiles({ loading: false });
  } catch (error) {
    if (error?.status !== 401) {
      const message = errorMessage(error, "The file could not be uploaded.");
      setFormAlert(
        elements["upload-alert"],
        message,
      );
      showToast(message, "error");
    }
  } finally {
    if (elements["file-input"]) {
      elements["file-input"].disabled = false;
    }
    setButtonBusy(elements["upload-submit"], false);
    updateSelectedUpload();
    if (elements["upload-progress-container"]) {
      elements["upload-progress-container"].hidden = true;
    }
  }
}

function openDialog(dialog) {
  if (!dialog || dialog.open) {
    return;
  }
  if (typeof dialog.showModal === "function") {
    dialog.showModal();
  } else {
    dialog.setAttribute("open", "");
  }
}

function closeDialog(dialog) {
  if (!dialog?.open) {
    return;
  }
  if (typeof dialog.close === "function") {
    dialog.close();
  } else {
    dialog.removeAttribute("open");
  }
}

function permissionUser(permission) {
  const username =
    typeof permission.user?.username === "string" && permission.user.username
      ? permission.user.username
      : "Authorized user";
  return { username, id: permission.user_id };
}

function renderPermissions(permissions) {
  const list = elements["permissions-list"];
  if (!list) {
    return;
  }

  list.replaceChildren();
  setListBusy(list, false);
  if (elements["permissions-empty"]) {
    elements["permissions-empty"].hidden = permissions.length !== 0;
  }

  for (const permission of permissions) {
    const user = permissionUser(permission);
    const row = createElement("div", "permission-row");
    const identity = createElement("div", "permission-row__identity");
    identity.append(
      createElement("p", "permission-row__name", user.username),
      createElement(
        "p",
        "permission-row__meta",
        `Sharing ID ${user.id} · Granted ${formatDate(permission.created_at)}`,
      ),
    );

    const actions = createElement("div", "permission-row__actions");
    const revokeButton = createActionButton(
      "Revoke",
      "danger",
      `Revoke ${user.username}'s access`,
      (button) => void handleRevokePermission(permission, button),
    );
    actions.append(revokeButton);
    row.append(identity, actions);
    list.append(row);
  }
}

async function loadPermissions(fileId) {
  const list = elements["permissions-list"];
  if (list) {
    setListBusy(list, true);
    list.replaceChildren(
      createElement("p", "loading-state", "Loading authorized users…"),
    );
  }
  if (elements["permissions-empty"]) {
    elements["permissions-empty"].hidden = true;
  }

  try {
    const permissions = await getFilePermissions(fileId);
    if (state.permissionsFile?.id === fileId) {
      renderPermissions(permissions);
    }
    return true;
  } catch (error) {
    if (state.permissionsFile?.id === fileId) {
      if (list) {
        setListBusy(list, false);
        list.replaceChildren();
      }
      if (error?.status !== 401) {
        setFormAlert(
          elements["permission-alert"],
          error?.status === 403
            ? "Only the file owner can manage access to this file."
            : errorMessage(error, "Unable to load authorized users."),
        );
      }
    }
    return false;
  }
}

async function openPermissionsDialog(file) {
  state.permissionsFile = file;
  if (elements["permissions-file-name"]) {
    elements["permissions-file-name"].textContent = fileName(file);
  }
  if (elements["permission-user-id"]) {
    elements["permission-user-id"].value = "";
  }
  clearFormAlert(elements["permission-alert"]);
  openDialog(elements["permissions-dialog"]);
  await loadPermissions(file.id);
  elements["permission-user-id"]?.focus();
}

async function handleGrantPermission(event) {
  event.preventDefault();
  clearFormAlert(elements["permission-alert"]);

  const file = state.permissionsFile;
  if (!file) {
    return;
  }

  const rawUserId = elements["permission-user-id"]?.value.trim() || "";
  const userId = Number(rawUserId);
  if (!/^[1-9]\d*$/.test(rawUserId) || !Number.isSafeInteger(userId)) {
    setFormAlert(
      elements["permission-alert"],
      "Enter a valid positive sharing ID.",
    );
    elements["permission-user-id"]?.focus();
    return;
  }

  setButtonBusy(elements["permission-submit"], true, "Granting…");
  try {
    await grantFilePermission(file.id, userId);
    if (elements["permission-user-id"]) {
      elements["permission-user-id"].value = "";
    }
    showToast("Access granted successfully.", "success");
    await Promise.all([
      loadPermissions(file.id),
      refreshFiles({ loading: false, quiet: true }),
    ]);
  } catch (error) {
    if (error?.status !== 401) {
      setFormAlert(
        elements["permission-alert"],
        error?.status === 403
          ? "Only the file owner can grant access to this file."
          : errorMessage(error, "Access could not be granted."),
      );
    }
  } finally {
    setButtonBusy(elements["permission-submit"], false);
  }
}

async function handleRevokePermission(permission, button) {
  const file = state.permissionsFile;
  if (!file) {
    return;
  }

  const user = permissionUser(permission);
  setButtonBusy(button, true, "Revoking…");
  clearFormAlert(elements["permission-alert"]);
  try {
    await revokeFilePermission(file.id, user.id);
    showToast(`${user.username}'s access was revoked.`, "success");
    await Promise.all([
      loadPermissions(file.id),
      refreshFiles({ loading: false, quiet: true }),
    ]);
  } catch (error) {
    if (error?.status !== 401) {
      setFormAlert(
        elements["permission-alert"],
        error?.status === 403
          ? "Only the file owner can revoke access to this file."
          : errorMessage(error, "Access could not be revoked."),
      );
      setButtonBusy(button, false);
    }
  }
}

function openDeleteDialog(file) {
  state.deleteFile = file;
  if (elements["delete-file-name"]) {
    elements["delete-file-name"].textContent = fileName(file);
  }
  openDialog(elements["delete-dialog"]);
}

async function handleDelete(event) {
  event.preventDefault();
  const file = state.deleteFile;
  if (!file) {
    return;
  }

  setButtonBusy(elements["delete-confirm"], true, "Deleting…");
  try {
    await deleteFile(file.id);
    closeDialog(elements["delete-dialog"]);
    showToast(`${fileName(file)} was permanently deleted.`, "success");
    await refreshFiles({ loading: false });
  } catch (error) {
    if (error?.status !== 401) {
      showToast(
        error?.status === 403
          ? "Only the file owner can delete this file."
          : errorMessage(error, "The file could not be deleted."),
        "error",
      );
    }
  } finally {
    setButtonBusy(elements["delete-confirm"], false);
  }
}

async function handleLogout() {
  setButtonBusy(elements["logout-button"], true, "Signing out…");
  try {
    await logout();
    setAuthNotice("You have signed out successfully.");
  } catch (error) {
    showToast(
      errorMessage(
        error,
        "Secure logout could not reach the server. Please try again.",
      ),
      "error",
    );
    setButtonBusy(elements["logout-button"], false);
    return;
  }
  window.location.replace("/login");
}

async function handleResendVerification() {
  const button = elements["resend-verification-button"];
  setButtonBusy(button, true, "Sending…");
  try {
    const payload = await requestEmailVerification();
    showToast(
      payload?.message || "A new verification email has been requested.",
      "success",
    );
  } catch (error) {
    if (error?.status !== 401) {
      showToast(
        errorMessage(error, "Unable to request a verification email."),
        "error",
      );
    }
  } finally {
    setButtonBusy(button, false);
  }
}

function bindEvents() {
  elements["logout-button"]?.addEventListener("click", () => void handleLogout());
  elements["resend-verification-button"]?.addEventListener(
    "click",
    () => void handleResendVerification(),
  );
  elements["file-input"]?.addEventListener("change", () => {
    clearFormAlert(elements["upload-alert"]);
    updateSelectedUpload();
  });
  elements["upload-form"]?.addEventListener("submit", handleUpload);
  elements["permission-form"]?.addEventListener(
    "submit",
    handleGrantPermission,
  );
  elements["permissions-close"]?.addEventListener("click", () => {
    closeDialog(elements["permissions-dialog"]);
  });
  elements["permissions-dialog"]?.addEventListener("close", () => {
    state.permissionsFile = null;
    clearFormAlert(elements["permission-alert"]);
  });
  elements["delete-confirm"]?.addEventListener("click", handleDelete);
  elements["delete-cancel"]?.addEventListener("click", () => {
    closeDialog(elements["delete-dialog"]);
  });
  elements["delete-dialog"]?.addEventListener("close", () => {
    state.deleteFile = null;
  });
}

async function initializeDashboard() {
  collectElements();
  if (!elements["dashboard-content"]) {
    return;
  }
  bindEvents();
  updateSelectedUpload();
  setDashboardLoading(true);

  try {
    const [user, files] = await Promise.all([getCurrentUser(), listFiles()]);
    state.currentUser = user;
    state.files = files;
    displayAccount(user);
    renderFiles(files);
  } catch (error) {
    if (error?.status !== 401) {
      showToast(
        errorMessage(error, "The dashboard could not be loaded."),
        "error",
      );
      renderListStatus(
        elements["owned-files"],
        elements["owned-empty"],
        "Your files could not be loaded.",
      );
      renderListStatus(
        elements["shared-files"],
        elements["shared-empty"],
        "Shared files could not be loaded.",
      );
    }
  } finally {
    setDashboardLoading(false);
  }
}

initializeDashboard();
