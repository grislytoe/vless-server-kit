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

function trafficSize(value) {
  let size = Number(value);
  const units = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ'];
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
  return `${size.toFixed(unit ? 2 : 0)} ${units[unit]}`;
}

async function refreshStatistics() {
  const panel = document.getElementById('operation-status');
  if (!panel) return;
  try {
    if (document.hidden) return;
    const response = await fetch(panel.dataset.panel + 'statistics', {cache: 'no-store', credentials: 'same-origin'});
    if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error();
    const stats = await response.json();
    document.querySelectorAll('[data-stats-key]').forEach(element => {
      const value = stats[element.dataset.statsKey];
      element.querySelector('[data-stat="online"]').textContent = element.dataset.enabled === '0' ? 'Ключ отключён' :
        value?.online === true ? 'Есть соединения' : value?.online === false ? 'Нет соединений' : 'Данные недоступны';
      for (const key of ['upload', 'download', 'total']) {
        element.querySelector(`[data-stat="${key}"]`).textContent = value ? trafficSize(key === 'total' ? value.upload + value.download : value[key]) : '—';
      }
      element.querySelector('[data-stat="last"]').textContent = value?.last_activity ?
        new Date(value.last_activity * 1000).toLocaleString() : 'Данных пока нет';
    });
  } catch {
    document.querySelectorAll('[data-stat="online"]').forEach(element => { element.textContent = 'Данные недоступны'; });
  } finally {
    setTimeout(refreshStatistics, 5000);
  }
}
refreshStatistics();
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
      // Refresh only list/count; keep the document, focus and page URL intact.
      const target = new URL(status.dataset.panel, location.origin);
      target.searchParams.set('operation', id);
      const updated = await fetch(target.href, {cache: 'no-store', credentials: 'same-origin'});
      if (!updated.ok) continue;
      const documentUpdate = new DOMParser().parseFromString(await updated.text(), 'text/html');
      const keys = documentUpdate.querySelector('.keys');
      const count = documentUpdate.getElementById('client-count');
      if (!keys || !count) continue;
      document.querySelector('.keys').replaceWith(keys);
      document.getElementById('client-count').replaceWith(count);
      status.textContent = result.message;
      if (result.status === 'success' && form.matches('.add')) form.reset();
      delete form.dataset.pending;
      document.querySelectorAll('button').forEach(button => { button.disabled = false; });
      return;
    } catch { /* Wait for the management connection to recover. */ }
  }
  status.textContent = 'Не удалось подтвердить результат. Обновите список ключей перед повтором, чтобы избежать дубликатов.';
});
