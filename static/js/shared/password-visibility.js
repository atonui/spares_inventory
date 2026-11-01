if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
  document.addEventListener('click', (event) => {
    const button = event.target?.closest?.('[data-password-visibility]');
    if (!button) return;

    const input = document.getElementById(button.getAttribute('aria-controls'));
    if (!input || !['password', 'text'].includes(input.type)) return;

    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(visible));
    button.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
    button.classList.toggle('is-visible', visible);
  });
}
