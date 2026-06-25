const CACHE = 'doorsense-v1';
const SHELL = ['/', '/manifest.json', '/icon.svg', '/icon-192.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const { url, method } = e.request;
  // Never cache SSE stream, ingest endpoints, or non-GET requests
  if (method !== 'GET' ||
      url.includes('/events') ||
      url.includes('/ingest/') ||
      url.includes('/set_') ||
      url.includes('/devices') ||
      url.includes('/delete_device')) return;

  e.respondWith(
    fetch(e.request)
      .then(r => {
        const clone = r.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
        return r;
      })
      .catch(() => caches.match(e.request))
  );
});
