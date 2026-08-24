import {
  getCurrentUser,
  isAuthenticated,
  setAuthNotice,
} from "./auth.js";
import { registerAccount } from "./api.js";
import {
  clearFormAlert,
  errorMessage,
  setButtonBusy,
  setFormAlert,
} from "./common.js";

const USERNAME_PATTERN = /^[a-z0-9_.-]{3,80}$/i;
const MINIMUM_PASSWORD_LENGTH = 8;
const MAXIMUM_PASSWORD_LENGTH = 1024;

async function initializeRegistration() {
  const form = document.querySelector("#register-form");
  if (!form) {
    return;
  }

  const usernameInput = form.querySelector("#username");
  const emailInput = form.querySelector("#email");
  const passwordInput = form.querySelector("#register-password");
  const confirmationInput = form.querySelector("#confirm-password");
  const submitButton = form.querySelector("#register-submit");
  const formAlert = document.querySelector("#form-alert");

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

    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!USERNAME_PATTERN.test(username)) {
      setFormAlert(
        formAlert,
        "Username must be 3–80 characters using letters, numbers, dots, underscores, or hyphens.",
      );
      usernameInput.focus();
      return;
    }
    if (!email || !emailInput.validity.valid) {
      setFormAlert(formAlert, "Enter a valid email address.");
      emailInput.focus();
      return;
    }
    if (password.length < MINIMUM_PASSWORD_LENGTH) {
      setFormAlert(formAlert, "Password must be at least 8 characters.");
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

    setButtonBusy(submitButton, true, "Creating account…");
    try {
      await registerAccount({ username, email, password });
      setAuthNotice("Account created successfully. Sign in to continue.");
      window.location.replace("/login");
    } catch (error) {
      setFormAlert(
        formAlert,
        errorMessage(error, "Unable to create your account."),
      );
    } finally {
      setButtonBusy(submitButton, false);
    }
  });
}

initializeRegistration();
