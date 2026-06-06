/* ═══════════════════════════════════════════════════════════════
   VulnScan5G — Landing Page Scripts
   Navbar scroll effect, mobile menu, scroll animations
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── Navbar scroll effect ──────────────────────────────────
  const navbar = document.getElementById('navbar');

  function handleNavScroll() {
    if (window.scrollY > 20) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }
  }

  window.addEventListener('scroll', handleNavScroll, { passive: true });
  handleNavScroll();

  // ── Mobile nav toggle ─────────────────────────────────────
  const navToggle = document.getElementById('navToggle');
  const navLinks = document.getElementById('navLinks');

  if (navToggle && navLinks) {
    navToggle.addEventListener('click', () => {
      navLinks.classList.toggle('open');
    });

    // Close mobile menu when a link is clicked
    navLinks.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('open');
      });
    });
  }

  // ── Smooth scroll for anchor links ────────────────────────
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener('click', function (e) {
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        e.preventDefault();
        const offset = 80; // navbar height
        const top = target.getBoundingClientRect().top + window.scrollY - offset;
        window.scrollTo({ top, behavior: 'smooth' });
      }
    });
  });

  // ── Scroll-triggered reveal animations ────────────────────
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -40px 0px',
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);

  document.querySelectorAll('.animate-on-scroll').forEach((el) => {
    observer.observe(el);
  });

  // ── Animated stat counters ────────────────────────────────
  function animateCounter(el) {
    const text = el.textContent.trim();
    const hasPlus = text.includes('+');
    const hasPercent = text.includes('%');
    const numericPart = parseInt(text.replace(/[^0-9]/g, ''), 10);

    if (isNaN(numericPart) || numericPart === 0) return;

    const duration = 1200;
    const startTime = performance.now();

    function tick(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(numericPart * eased);

      let display = current.toString();
      if (hasPlus) display += '+';
      if (hasPercent) display += '%';
      el.textContent = display;

      if (progress < 1) {
        requestAnimationFrame(tick);
      }
    }

    requestAnimationFrame(tick);
  }

  const statObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          animateCounter(entry.target);
          statObserver.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.5 }
  );

  document.querySelectorAll('.stat-value').forEach((el) => {
    statObserver.observe(el);
  });
})();
