/**
 * static/js/auth.js
 * Handles client-side authentication enhancements:
 * - Live password strength meter & complexity checklist
 * - Secure show/hide password toggling
 * Strictly adheres to Content Security Policy (no inline handlers).
 * XSS defense: Zero innerHTML usage (uses textContent and DOM properties).
 */

document.addEventListener("DOMContentLoaded", () => {
  // Password Visibility Toggle
  const toggleBtn = document.getElementById("toggle-password");
  const passwordInput = document.getElementById("password");

  if (toggleBtn && passwordInput) {
    toggleBtn.addEventListener("click", () => {
      const isPassword = passwordInput.getAttribute("type") === "password";
      passwordInput.setAttribute("type", isPassword ? "text" : "password");
      toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
      
      const eyeIcon = toggleBtn.querySelector(".eye-icon");
      if (eyeIcon) {
        eyeIcon.textContent = isPassword ? "🔒" : "👁️";
      }
    });
  }

  // Register Page Password Strength & Checklist
  const registerForm = document.getElementById("register-form");
  if (registerForm && passwordInput) {
    const strengthBar = document.getElementById("strength-bar");
    const strengthText = document.getElementById("strength-text");

    const checkLength = document.getElementById("check-length");
    const checkUpper = document.getElementById("check-upper");
    const checkLower = document.getElementById("check-lower");
    const checkDigit = document.getElementById("check-digit");
    const checkSymbol = document.getElementById("check-symbol");

    const updateChecklist = () => {
      const val = passwordInput.value;

      const hasLength = val.length >= 10 && val.length <= 128;
      const hasUpper = /[A-Z]/.test(val);
      const hasLower = /[a-z]/.test(val);
      const hasDigit = /[0-9]/.test(val);
      const hasSymbol = /[!@#$%^&*(),.?":{}|<>\-_\+=\[\]\\\/~`']/.test(val);

      const updateItem = (elem, passed) => {
        if (!elem) return;
        if (passed) {
          elem.classList.add("valid");
          const icon = elem.querySelector(".check-icon");
          if (icon) icon.textContent = "✓";
        } else {
          elem.classList.remove("valid");
          const icon = elem.querySelector(".check-icon");
          if (icon) icon.textContent = "○";
        }
      };

      updateItem(checkLength, hasLength);
      updateItem(checkUpper, hasUpper);
      updateItem(checkLower, hasLower);
      updateItem(checkDigit, hasDigit);
      updateItem(checkSymbol, hasSymbol);

      // Calculate score (0 to 5)
      const passedCount = [hasLength, hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;

      if (strengthBar && strengthText) {
        let percentage = (passedCount / 5) * 100;
        let color = "#ef4444"; // Red
        let label = "Very Weak";

        if (passedCount === 0) {
          percentage = 0;
          label = "None";
        } else if (passedCount === 1) {
          color = "#ef4444";
          label = "Very Weak";
        } else if (passedCount === 2) {
          color = "#f97316";
          label = "Weak";
        } else if (passedCount === 3) {
          color = "#eab308";
          label = "Moderate";
        } else if (passedCount === 4) {
          color = "#10b981";
          label = "Strong";
        } else if (passedCount === 5) {
          color = "#38bdf8";
          label = "Excellent (All criteria met)";
        }

        strengthBar.style.width = `${percentage}%`;
        strengthBar.style.backgroundColor = color;
        strengthText.textContent = `Password strength: ${label}`;
      }
    };

    passwordInput.addEventListener("input", updateChecklist);
    updateChecklist();
  }
});
