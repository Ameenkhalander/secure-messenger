const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || '';

export class ApiError extends Error {
  constructor(message, status, code) { super(message); this.status = status; this.code = code; }
}

export async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401) { window.location.href = '/login'; throw new ApiError('Signed out', 401, 'auth_required'); }
  if (!res.ok) throw new ApiError((data && data.error) || res.statusText, res.status, data && data.code);
  return data;
}
