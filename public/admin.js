'use strict';
document.addEventListener('click', async (e) => {
  const copy = e.target.closest('.copy');
  if (copy) {
    e.preventDefault();
    try { await navigator.clipboard.writeText(copy.dataset.url); }
    catch {
      const t = document.createElement('textarea'); t.value = copy.dataset.url; document.body.appendChild(t);
      t.select(); document.execCommand('copy'); t.remove();
    }
    const old = copy.textContent; copy.textContent = 'הועתק ✓'; setTimeout(() => (copy.textContent = old), 1500);
  }
  const ref = e.target.closest('#refreshAll');
  if (ref) {
    ref.disabled = true; ref.textContent = 'מרענן…';
    await fetch('/admin/api/sync-all', { method: 'POST', headers: { 'x-csrf-token': ref.dataset.csrf } }).catch(() => {});
    location.reload();
  }
});
// Auto-refresh the dashboard every 60s unless the admin is typing
if (location.pathname === '/admin') {
  setInterval(() => {
    const a = document.activeElement;
    if (!a || !['INPUT', 'TEXTAREA', 'SELECT'].includes(a.tagName)) location.reload();
  }, 60000);
}
