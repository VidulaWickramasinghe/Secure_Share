import { confirmPasswordReset } from "./api.js";
import {
  clearFormAlert,
  errorMessage,
  setButtonBusy,
  setFormAlert,
} from "./common.js";

const MINIMUM_PASSWORD_LENGTH = 15;
const MAXIMUM_PASSWORD_LENGTH = 1024;

function consumeFragmentToken() {
  const parameters = new URLSearchParams(window.location.hash.slice(1));
  const token = parameters.get("token");
  // Fragments are not sent to Flask, but remove the secret immediately so it
  // is not left visible or copied from the address bar.
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  return typeof token === "string" && token.length > 0 ? token : null;
}

function initializePasswordReset() {
  const form = document.querySelector("#reset-password-form");
  if (!form) {
    return;
  }

  const token = consumeFragmentToken();
  const passwordInput = form.querySelector("#new-password");
  const confirmationInput = form.querySelector("#confirm-new-password");
  const submitButton = form.querySelector("#reset-submit");
  const formAlert = document.querySelector("#form-alert");

  if (!token) {
    setFormAlert(
      formAlert,
      "This reset link is incomplete. Request a new password-reset email.",
    );
    for (const control of form.elements) {
      control.disabled = true;
    }
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearFormAlert(formAlert);
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }

    const password = passwordInput.value;
    if (password.length < MINIMUM_PASSWORD_LENGTH) {
      setFormAlert(formAlert, "Password must be at least 15 characters.");
      passwordInput.focus();
      return;
    }
    if (password.length > MAXIMUM_PASSWORD_LENGTH) {
      setFormAlert(formAlert, "Password is too long.");
      passwordInput.focus();
      return;
    }
    if (password !== confirmationInput.value) {
      setFormAlert(formAlert, "Passwords do not match.");
      confirmationInput.focus();
      return;
    }

    setButtonBusy(submitButton, true, "Resetting…");
    let completed = false;
    try {
      const payload = await confirmPasswordReset(token, password);
      form.reset();
      completed = true;
      form.hidden = true;
      setFormAlert(
        formAlert,
        payload?.message ||
          "Password reset successfully. Sign in with your new password.",
        "success",
      );
      const signIn = document.createElement("a");
      signIn.href = "/login";
      signIn.className = "button button--primary button--block button--link action-result-link";
      signIn.textContent = "Continue to sign in";
      form.after(signIn);
      signIn.focus();
    } catch (error) {
      setFormAlert(
        formAlert,
        errorMessage(error, "The reset link is invalid or has expired."),
      );
    } finally {
      if (!completed) {
        setButtonBusy(submitButton, false);
      }
    }
  });
}

initializePasswordReset();
