/**
 * static/js/idle.js
 * Enforces client-side session idle timeout:
 * - 15-minute countdown displayed in the navigation bar
 * - Displays a prominent warning banner at 60 seconds remaining
 * - Submits automatic logout when time reaches 0
 * - Resets on user activity (mouse/keyboard) and pings POST /api/ping to keep server session active
 * Strictly follows Content Security Policy and uses safe DOM manipulation.
 */

document.addEventListener("DOMContentLoaded", () => {
  const TOTAL_IDLE_SECONDS = 15 * 60; // 15 minutes
  let secondsRemaining = TOTAL_IDLE_SECONDS;
  let lastPingTime = Date.now();

  const timerDisplay = document.getElementById("idle-timer-display");
  const warningBanner = document.getElementById("idle-warning-banner");
  const warningSecondsSpan = document.getElementById("warning-seconds");

  // Retrieve CSRF token from meta tag
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";

  const formatTime = (totalSeconds) => {
    const mins = Math.floor(totalSeconds / 60);
    const secs = totalSeconds % 60;
    return `${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  const updateDisplay = () => {
    if (timerDisplay) {
      timerDisplay.textContent = formatTime(secondsRemaining);
    }

    if (warningBanner && warningSecondsSpan) {
      if (secondsRemaining <= 60 && secondsRemaining > 0) {
        warningBanner.classList.remove("hidden");
        warningSecondsSpan.textContent = secondsRemaining.toString();
      } else {
        warningBanner.classList.add("hidden");
      }
    }
  };

  const performAutoLogout = () => {
    // SECURITY: Auto-Logout on Inactivity - Clears session on the server
    const logoutForm = document.querySelector(".logout-form");
    if (logoutForm) {
      logoutForm.submit();
    } else {
      // Fallback redirect
      window.location.href = "/login";
    }
  };

  // Interval timer tick every 1 second
  const timerInterval = setInterval(() => {
    secondsRemaining -= 1;
    updateDisplay();

    if (secondsRemaining <= 0) {
      clearInterval(timerInterval);
      performAutoLogout();
    }
  }, 1000);

  // Ping backend to refresh server session sliding expiration
  const pingServer = () => {
    const now = Date.now();
    // Throttle server pings to at most once every 30 seconds
    if (now - lastPingTime < 30 * 1000) {
      return;
    }
    lastPingTime = now;

    fetch("/api/ping", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
    }).catch(() => {
      // Network issues handled gracefully without crashing UI
    });
  };

  // Reset timer on user interaction
  const resetTimer = () => {
    secondsRemaining = TOTAL_IDLE_SECONDS;
    updateDisplay();
    pingServer();
  };

  // Attach event listeners for user activity
  const activityEvents = ["mousemove", "keydown", "click", "scroll", "touchstart"];
  activityEvents.forEach((evt) => {
    window.addEventListener(evt, resetTimer, { passive: true });
  });

  updateDisplay();
});
