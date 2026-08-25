import { confirmEmailVerification } from "./api.js";
import { errorMessage, setFormAlert } from "./common.js";

function consumeFragmentToken() {
  const parameters = new URLSearchParams(window.location.hash.slice(1));
  const token = parameters.get("token");
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  return typeof token === "string" && token.length > 0 ? token : null;
}

async function initializeEmailVerification() {
  const alert = document.querySelector("#form-alert");
  const title = document.querySelector("#verify-title");
  const description = document.querySelector("#verify-description");
  const continueLink = document.querySelector("#verify-continue");
  const dashboardLink = document.querySelector("#verify-dashboard");
  if (!alert || !title) {
    return;
  }

  const token = consumeFragmentToken();
  if (!token) {
    title.textContent = "Verification link incomplete";
    description.textContent = "Sign in to request a fresh verification email.";
    setFormAlert(alert, "This verification link is incomplete or no longer available.");
    continueLink.hidden = false;
    return;
  }

  try {
    await confirmEmailVerification(token);
    title.textContent = "Email verified";
    description.textContent = "Your address can now receive owner-authorized shares.";
    setFormAlert(alert, "Your email address was verified successfully.", "success");
    continueLink.hidden = false;
    dashboardLink.hidden = false;
    continueLink.focus();
  } catch (error) {
    title.textContent = "Link could not be verified";
    description.textContent = "The link may have expired or already been used.";
    setFormAlert(
      alert,
      errorMessage(error, "The verification link is invalid or has expired."),
    );
    continueLink.hidden = false;
  }
}

initializeEmailVerification();
