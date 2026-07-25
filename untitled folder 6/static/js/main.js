// main.js — shared interactions across all pages

document.addEventListener("DOMContentLoaded", () => {
  // Reveal/hide password fields
  document.querySelectorAll(".reveal-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = document.getElementById(btn.dataset.target);
      if (!target) return;
      const showing = target.type === "text";
      target.type = showing ? "password" : "text";
      btn.style.color = showing ? "" : "var(--accent)";
    });
  });

  // CAPTCHA refresh (AJAX, no full page reload)
  const refreshBtn = document.getElementById("captcha-refresh");
  const captchaImg = document.getElementById("captcha-img");
  if (refreshBtn && captchaImg) {
    refreshBtn.addEventListener("click", async () => {
      refreshBtn.classList.add("spin");
      try {
        const res = await fetch("/captcha/refresh", { cache: "no-store" });
        const data = await res.json();
        captchaImg.src = data.image;
        const input = document.getElementById("captcha");
        if (input) input.value = "";
      } catch (e) {
        console.error("Could not refresh CAPTCHA", e);
      } finally {
        setTimeout(() => refreshBtn.classList.remove("spin"), 400);
      }
    });
  }

  // Auto-dismiss flash messages after a while
  document.querySelectorAll(".flash").forEach((el, i) => {
    setTimeout(() => {
      el.style.transition = "opacity 0.4s ease, transform 0.4s ease";
      el.style.opacity = "0";
      el.style.transform = "translateY(-6px)";
    }, 6000 + i * 200);
  });
});
