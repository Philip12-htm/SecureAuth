// strength.js — live, server-validated password strength feedback.
// Deliberately calls the backend (/api/password-strength) rather than
// re-implementing scoring in JS, so the client can never see different
// rules than the ones actually enforced on submit.

(() => {
  const passwordInput = document.getElementById("password");
  const usernameInput = document.getElementById("username");
  const confirmInput = document.getElementById("confirm_password");
  if (!passwordInput) return;

  const bar = document.getElementById("strength-bar");
  const label = document.getElementById("strength-label");
  const entropyEl = document.getElementById("strength-entropy");
  const feedbackList = document.getElementById("strength-feedback");
  const matchHint = document.getElementById("match-hint");

  const shieldFill = document.getElementById("shield-fill");
  const shieldCaption = document.getElementById("shield-caption");
  const stop1 = document.getElementById("shieldStop1");
  const stop2 = document.getElementById("shieldStop2");

  const COLORS = {
    0: ["#ff5c6c", "#ff5c6c"],
    1: ["#ff5c6c", "#f5a623"],
    2: ["#f5a623", "#f5d423"],
    3: ["#34d399", "#2dd4bf"],
    4: ["#2dd4bf", "#5b8def"],
  };

  let debounceTimer = null;

  function renderResult(result) {
    const pct = result.percent ?? 0;
    bar.style.width = pct + "%";
    bar.dataset.score = result.score;
    bar.style.background = COLORS[result.score]?.[0] || "var(--danger)";

    label.textContent = "Strength: " + result.label;
    entropyEl.textContent = result.entropy_bits ? `${result.entropy_bits} bits entropy` : "";

    feedbackList.innerHTML = "";
    (result.feedback || []).forEach((msg) => {
      const li = document.createElement("li");
      li.textContent = msg;
      feedbackList.appendChild(li);
    });

    // Shield gauge: signature element of the page
    if (shieldFill) {
      const opacity = passwordInput.value.length ? 0.25 + (result.score / 4) * 0.75 : 0;
      shieldFill.style.opacity = opacity;
      const [c1, c2] = COLORS[result.score] || COLORS[0];
      if (stop1) stop1.setAttribute("stop-color", c1);
      if (stop2) stop2.setAttribute("stop-color", c2);
    }
    if (shieldCaption) {
      shieldCaption.textContent = passwordInput.value.length
        ? `${result.label} — ${result.feedback?.[0] || "Looks good."}`
        : "Start typing a password to see its live security rating.";
    }
  }

  async function checkStrength() {
    const password = passwordInput.value;
    const username = usernameInput ? usernameInput.value : "";
    try {
      const res = await fetch("/api/password-strength", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password, username }),
      });
      const data = await res.json();
      renderResult(data);
    } catch (e) {
      console.error("Strength check failed", e);
    }
  }

  passwordInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkStrength, 180);
    checkMatch();
  });
  if (usernameInput) usernameInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkStrength, 180);
  });

  function checkMatch() {
    if (!confirmInput || !matchHint) return;
    if (!confirmInput.value) {
      matchHint.textContent = "";
      matchHint.className = "field-hint";
      return;
    }
    const match = confirmInput.value === passwordInput.value;
    matchHint.textContent = match ? "Passwords match." : "Passwords do not match yet.";
    matchHint.className = "field-hint " + (match ? "ok" : "bad");
  }
  if (confirmInput) confirmInput.addEventListener("input", checkMatch);
})();
