(function () {
  if (typeof document === 'undefined' || typeof document.getElementById !== 'function') return;

  const button = document.getElementById('back-to-top');
  if (!button) return;

  const scrollThreshold = 480;
  const reducedMotion = typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-reduced-motion: reduce)')
    : { matches: false };

  let scheduled = false;
  let previousHidden;

  function updateVisibility() {
    scheduled = false;
    const hidden = window.scrollY < scrollThreshold;
    if (hidden !== previousHidden) {
      button.hidden = hidden;
      previousHidden = hidden;
    }
  }

  function scheduleVisibility() {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(updateVisibility);
  }

  window.addEventListener('scroll', scheduleVisibility, { passive: true });
  window.addEventListener('resize', scheduleVisibility, { passive: true });
  button.addEventListener('click', function () {
    window.scrollTo({
      top: 0,
      behavior: reducedMotion.matches ? 'auto' : 'smooth',
    });
  });

  scheduleVisibility();
})();
