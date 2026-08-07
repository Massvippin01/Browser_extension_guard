/**
 * overlay.js - Handles interactions within the injected security overlay.
 * Runs in the context of the page because it is injected by the content script.
 */

(function() {
  const backBtn = document.getElementById('verity-btn-back');
  const proceedBtn = document.getElementById('verity-btn-proceed');
  const overlay = document.getElementById('verity-security-overlay');

  if (backBtn) {
    backBtn.addEventListener('click', () => {
      // Attempt to go back
      if (window.history.length > 1) {
        window.history.back();
      } else {
        // Fallback if there is no history
        try {
          window.close();
        } catch(e) {
          // If close() is blocked, navigate to a safe page like about:blank
          window.location.href = 'about:blank';
        }
      }
    });
  }

  if (proceedBtn) {
    proceedBtn.addEventListener('click', () => {
      console.log('[Verity] User chose "Proceed anyway"');
      // Hide the overlay for Stage 1
      if (overlay) {
        overlay.style.display = 'none';
      }
    });
  }
})();
