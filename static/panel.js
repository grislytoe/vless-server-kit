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
document.addEventListener('submit', async (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) { event.preventDefault(); return; }
  const form = event.target;
  if (!form.matches('.add, [data-confirm]')) return;
  event.preventDefault();
  const status = document.getElementById('operation-status');
  if (form.dataset.pending) return;
  form.dataset.pending = 'true';
  const id = crypto.randomUUID();
  const data = new FormData(form);
  data.set('operation_id', id);
  document.querySelectorAll('button').forEach(button => { button.disabled = true; });
  status.textContent = 'Применяем изменения. Соединение может кратко прерваться…';
  // Send exactly once: restarting Xray can destroy this HTTP response after
  // the mutation succeeds. Poll a session-owned operation ID instead of retrying.
  fetch(form.action, {method: 'POST', body: data, credentials: 'same-origin'}).catch(() => {});
  for (let attempt = 0; attempt < 90; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    try {
      const response = await fetch(status.dataset.panel + 'operation/' + id, {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) continue;
      const result = await response.json();
      if (result.status === 'pending') continue;
      const target = new URL(status.dataset.panel, location.origin);
      target.searchParams.set('operation', id);
      location.replace(target.href);
      return;
    } catch { /* Wait for the management connection to recover. */ }
  }
  status.textContent = 'Не удалось подтвердить результат. Обновите список ключей перед повтором, чтобы избежать дубликатов.';
});
