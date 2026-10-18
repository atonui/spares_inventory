(function () {
  if (typeof document === 'undefined' || typeof document.getElementById !== 'function') return;

  const button = document.getElementById('back-to-top');
  if (!button) return;

  const scrollThreshold = 480;
  const reducedMotion = typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-reduced-motion: reduce)')
    : { matches: false };

  function updateVisibility() {
    button.hidden = window.scrollY < scrollThreshold;
  }

  window.addEventListener('scroll', updateVisibility, { passive: true });
  window.addEventListener('resize', updateVisibility, { passive: true });
  button.addEventListener('click', function () {
    window.scrollTo({
      top: 0,
      behavior: reducedMotion.matches ? 'auto' : 'smooth',
    });
  });

  updateVisibility();
})();
