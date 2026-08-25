import { requestPasswordReset } from "./api.js";
import {
  clearFormAlert,
  errorMessage,
  setButtonBusy,
  setFormAlert,
} from "./common.js";

function initializePasswordRecovery() {
  const form = document.querySelector("#forgot-password-form");
  if (!form) {
    return;
  }

  const emailInput = form.querySelector("#recovery-email");
  const submitButton = form.querySelector("#recovery-submit");
  const formAlert = document.querySelector("#form-alert");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearFormAlert(formAlert);
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }

    setButtonBusy(submitButton, true, "Sending…");
    try {
      const payload = await requestPasswordReset(emailInput.value.trim());
      form.reset();
      setFormAlert(
        formAlert,
        payload?.message ||
          "If an account matches that email, password-reset instructions have been sent.",
        "success",
      );
    } catch (error) {
      setFormAlert(
        formAlert,
        errorMessage(error, "Unable to request a reset right now."),
      );
    } finally {
      setButtonBusy(submitButton, false);
    }
  });
}

initializePasswordRecovery();
