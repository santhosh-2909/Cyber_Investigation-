/* ============================================================
   CYBER DETECTIVE — Application JavaScript
   ============================================================ */

(function() {
  'use strict';

  // ============================================================
  // CASE TIMER
  // ============================================================
  const timerEl = document.getElementById('case-timer');
  if (timerEl && !timerEl.hasAttribute('data-remaining-ms')) {
    let seconds = parseInt(timerEl.dataset.seconds || '0', 10);
    const startTime = Date.now() - (seconds * 1000);

    function updateTimer() {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
      const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
      const s = String(elapsed % 60).padStart(2, '0');
      timerEl.textContent = h + ':' + m + ':' + s;
    }

    updateTimer();
    setInterval(updateTimer, 1000);
  }

  // ============================================================
  // TOAST NOTIFICATIONS
  // ============================================================
  window.showToast = function(message, type) {
    type = type || 'success';
    let container = document.querySelector('.toast-container');
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const icons = {
      success: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
      error: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
      warning: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>'
    };

    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.innerHTML = (icons[type] || '') + '<span>' + message + '</span>';
    container.appendChild(toast);

    setTimeout(function() {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(function() { toast.remove(); }, 300);
    }, 4000);
  };

  // ============================================================
  // SCROLL ANIMATIONS
  // ============================================================
  const observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('animate-slide-up');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('[data-animate]').forEach(function(el) {
    observer.observe(el);
  });

  // ============================================================
  // SMOOTH SCROLL
  // ============================================================
  document.querySelectorAll('a[href^="#"]').forEach(function(link) {
    link.addEventListener('click', function(e) {
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // ============================================================
  // KEYBOARD SHORTCUTS
  // ============================================================
  document.addEventListener('keydown', function(e) {
    // Escape closes modals
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-backdrop.active').forEach(function(m) {
        m.classList.remove('active');
      });
    }
  });

  // ============================================================
  // AUTO-SAVE INDICATOR
  // ============================================================
  document.querySelectorAll('textarea, input[type="text"]').forEach(function(el) {
    let timeout;
    el.addEventListener('input', function() {
      clearTimeout(timeout);
      timeout = setTimeout(function() {
        // Simulate autosave
        const indicator = document.getElementById('autosave-indicator');
        if (indicator) {
          indicator.textContent = 'Saved just now';
          indicator.style.color = 'var(--success)';
          setTimeout(function() {
            indicator.textContent = 'Autosaved';
            indicator.style.color = '';
          }, 2000);
        }
      }, 1000);
    });
  });

})();
