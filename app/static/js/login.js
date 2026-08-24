import {
  AUTH_NOTICE_EVENT,
  consumeAuthNotice,
  getCurrentUser,
  isAuthenticated,
  login,
} from "./auth.js";
import {
  clearFormAlert,
  errorMessage,
  setButtonBusy,
  setFormAlert,
} from "./common.js";

async function initializeLogin() {
  const form = document.querySelector("#login-form");
  if (!form) {
    return;
  }

  const identifierInput = form.querySelector("#identifier");
  const passwordInput = form.querySelector("#password");
  const submitButton = form.querySelector("#login-submit");
  const formAlert = document.querySelector("#form-alert");

  const initialNotice = consumeAuthNotice();
  if (initialNotice) {
    setFormAlert(formAlert, initialNotice, "info");
  }

  window.addEventListener(AUTH_NOTICE_EVENT, (event) => {
    consumeAuthNotice();
    setFormAlert(
      formAlert,
      event.detail?.message || "Please sign in again.",
      "info",
    );
  });

  // A stored token is only a claim. Verify it with the API before redirecting.
  if (isAuthenticated()) {
    setButtonBusy(submitButton, true, "Checking session…");
    try {
      await getCurrentUser();
      window.location.replace("/dashboard");
      return;
    } catch (error) {
      if (isAuthenticated()) {
        setFormAlert(
          formAlert,
          errorMessage(error, "Unable to verify your session."),
        );
      }
    } finally {
      setButtonBusy(submitButton, false);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearFormAlert(formAlert);

    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }

    const identifier = identifierInput.value.trim();
    if (!identifier) {
      setFormAlert(formAlert, "Enter your username or email address.");
      identifierInput.focus();
      return;
    }
    if (!passwordInput.value) {
      setFormAlert(formAlert, "Enter your password.");
      passwordInput.focus();
      return;
    }

    setButtonBusy(submitButton, true, "Signing in…");
    try {
      await login(identifier, passwordInput.value);
      window.location.replace("/dashboard");
    } catch (error) {
      setFormAlert(
        formAlert,
        errorMessage(error, "Unable to sign in. Please try again."),
      );
      passwordInput.focus();
      passwordInput.select();
    } finally {
      setButtonBusy(submitButton, false);
    }
  });
}

initializeLogin();
