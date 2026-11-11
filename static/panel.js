document.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-copy]');
  if (!button) return;
  const input = document.getElementById(button.dataset.copy);
  try {
    await navigator.clipboard.writeText(input.value);
    document.getElementById('copy-status').textContent = 'Ссылка скопирована';
  } catch {
    input.focus(); input.select();
    document.getElementById('copy-status').textContent = 'Выделенная ссылка готова для копирования';
  }
});
document.addEventListener('submit', (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
