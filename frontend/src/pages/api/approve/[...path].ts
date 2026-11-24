import type { APIRoute } from 'astro';

/*
 * Server-side passthrough to the issuer service's approval routes (OpenSpec add-scope-requests), so the browser
 * never talks to the issuer directly. This page decides nothing: the issuer checks the approver session on
 * every decision. The session lives in an HTTP-only, SameSite=Strict cookie scoped to these routes.
 */
export const SESSION_COOKIE = 'approver_session';
const ISSUER = () => process.env.ISSUER_URL ?? 'http://localhost:8083';
const REQUEST_ID = /^sr_[A-Za-z0-9_-]{6,40}$/;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

export const ALL: APIRoute = async({ params, request, cookies }) => {
  const [action, rid] = (params.path ?? '').split('/');
  if (!REQUEST_ID.test(rid ?? '')) return json({ error: 'NOT_FOUND', detail: 'no such request' }, 404);
  const session = cookies.get(SESSION_COOKIE)?.value;
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (session) headers['x-approver-session'] = session;

  let upstream: Response;
  if (action === 'view' && request.method === 'GET') {
    upstream = await fetch(`${ISSUER()}/requests/${rid}/view`, { headers });
  } else if (action === 'decision' && request.method === 'POST') {
    upstream = await fetch(`${ISSUER()}/requests/${rid}/decision`, {
      method: 'POST',
      headers,
      body: await request.text(),
    });
  } else {
    return json({ error: 'NOT_FOUND', detail: 'unknown approval route' }, 404);
  }
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
};
