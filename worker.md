// ============================================================
// Cloudflare Worker - 多后端反代 + IP一致性哈希 + 故障转移
//
// 部署步骤:
// 1. Cloudflare Dashboard → Workers & Pages → Create Worker
// 2. 粘贴此代码 → Deploy
// 3. Settings → Triggers → Custom Domains 绑定你的域名
//    例如: proxy.yourdomain.com
//
// 后端 Wasmer App 的 DOMAIN 环境变量填: proxy.yourdomain.com
// ============================================================

// ------ 配置区（只需改这里）------

const BACKENDS = [
  { host: 'node01.app', healthy: true, lastCheck: 0 },
  { host: 'node02.app', healthy: true, lastCheck: 0 },

  // 按需增减，格式相同
  // { host: 'app-ddd.wasmer.app', healthy: true, lastCheck: 0 },
];

// 健康检查配置
const HEALTH_CHECK_INTERVAL = 30000;  // 30秒检查一次
const HEALTH_CHECK_TIMEOUT = 5000;    // 超时5秒判定不健康
const HEALTH_CHECK_PATH = '/api/health'; // 健康检查路径（对应Python代码中的路由）

// ------ 以下不需要改 ------

// ============================================================
// IP 一致性哈希
// 同一个客户端 IP 始终分配到同一个后端
// 出口 IP 不跳动，不触发目标网站风控
// ============================================================

async function hashIP(ip) {
  const encoder = new TextEncoder();
  const data = encoder.encode(ip + '_salt_2024');
  const buffer = await crypto.subtle.digest('SHA-256', data);
  const arr = new Uint8Array(buffer);
  return (arr[0] << 24 | arr[1] << 16 | arr[2] << 8 | arr[3]) >>> 0;
}

async function getBackendByIP(clientIP) {
  const healthy = BACKENDS.filter(b => b.healthy);

  if (healthy.length === 0) {
    // 全挂了，从所有节点里选一个碰碰运气
    const hash = await hashIP(clientIP);
    return BACKENDS[hash % BACKENDS.length];
  }

  const hash = await hashIP(clientIP);
  return healthy[hash % healthy.length];
}

// ============================================================
// 健康检查
// ============================================================

async function checkHealth(backend) {
  const now = Date.now();

  // 未到检查间隔，跳过
  if (now - backend.lastCheck < HEALTH_CHECK_INTERVAL) {
    return backend.healthy;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), HEALTH_CHECK_TIMEOUT);

    const resp = await fetch(
      `https://${backend.host}${HEALTH_CHECK_PATH}`,
      {
        method: 'GET',
        headers: { 'User-Agent': 'HealthCheck/1.0' },
        signal: controller.signal,
      }
    );

    clearTimeout(timeoutId);
    backend.healthy = resp.ok;
  } catch {
    backend.healthy = false;
  }

  backend.lastCheck = now;
  return backend.healthy;
}

// ============================================================
// 请求头清理
// 白名单模式：只保留必要头部
// 自动排除所有 CF 特征头（CF-Ray, CF-Connecting-IP 等）
// ============================================================

function buildWSHeaders(request, backendHost) {
  const headers = new Headers();

  const whitelist = [
    'upgrade',
    'connection',
    'sec-websocket-key',
    'sec-websocket-version',
    'sec-websocket-extensions',
    'sec-websocket-protocol',
  ];

  for (const key of whitelist) {
    const val = request.headers.get(key);
    if (val) headers.set(key, val);
  }

  headers.set('Host', backendHost);
  headers.set('Origin', `https://${backendHost}`);
  headers.set('User-Agent',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

  return headers;
}

function buildHTTPHeaders(request, backendHost) {
  const headers = new Headers();

  const whitelist = [
    'accept',
    'accept-language',
    'accept-encoding',
    'content-type',
    'content-length',
    'cache-control',
    'pragma',
    'if-none-match',
    'if-modified-since',
  ];

  for (const key of whitelist) {
    const val = request.headers.get(key);
    if (val) headers.set(key, val);
  }

  headers.set('Host', backendHost);
  headers.set('User-Agent',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

  return headers;
}

function cleanResponseHeaders(resp) {
  const clean = new Response(resp.body, { status: resp.status });

  const whitelist = [
    'content-type',
    'content-length',
    'content-encoding',
    'transfer-encoding',
    'cache-control',
    'etag',
    'last-modified',
    'access-control-allow-origin',
    'access-control-allow-methods',
    'access-control-allow-headers',
  ];

  for (const key of whitelist) {
    const val = resp.headers.get(key);
    if (val) clean.headers.set(key, val);
  }

  // 伪装服务器标识
  clean.headers.set('Server', 'nginx');

  return clean;
}

// ============================================================
// 故障转移
// 当前后端失败时尝试其他健康后端
// ============================================================

async function tryFallback(request, url, failedHost) {
  const others = BACKENDS.filter(b => b.healthy && b.host !== failedHost);

  for (const fallback of others) {
    try {
      const targetUrl = `https://${fallback.host}${url.pathname}${url.search}`;
      const headers = buildHTTPHeaders(request, fallback.host);

      const resp = await fetch(targetUrl, {
        method: request.method,
        headers: headers,
        body: request.method !== 'GET' ? request.body : undefined,
      });

      if (resp.ok) {
        return cleanResponseHeaders(resp);
      }
    } catch {
      fallback.healthy = false;
    }
  }

  return new Response(
    JSON.stringify({ error: 'All backends unavailable' }),
    {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

// ============================================================
// WebSocket 处理
// ============================================================

async function handleWebSocket(request, url, backend) {
  const targetUrl = `https://${backend.host}${url.pathname}${url.search}`;
  const headers = buildWSHeaders(request, backend.host);

  try {
    const resp = await fetch(targetUrl, {
      method: request.method,
      headers: headers,
      body: request.body,
    });
    return resp;
  } catch (err) {
    backend.healthy = false;

    // WebSocket 故障转移
    const others = BACKENDS.filter(b => b.healthy && b.host !== backend.host);
    for (const fallback of others) {
      try {
        const fbUrl = `https://${fallback.host}${url.pathname}${url.search}`;
        const fbHeaders = buildWSHeaders(request, fallback.host);
        const resp = await fetch(fbUrl, {
          method: request.method,
          headers: fbHeaders,
          body: request.body,
        });
        return resp;
      } catch {
        fallback.healthy = false;
      }
    }

    return new Response('Bad Gateway', { status: 502 });
  }
}

// ============================================================
// HTTP 处理
// ============================================================

async function handleHTTP(request, url, backend) {
  const targetUrl = `https://${backend.host}${url.pathname}${url.search}`;
  const headers = buildHTTPHeaders(request, backend.host);

  try {
    const resp = await fetch(targetUrl, {
      method: request.method,
      headers: headers,
      body: request.method !== 'GET' ? request.body : undefined,
      redirect: 'follow',
    });

    return cleanResponseHeaders(resp);
  } catch (err) {
    backend.healthy = false;
    return await tryFallback(request, url, backend.host);
  }
}

// ============================================================
// 主入口
// ============================================================

async function handleRequest(request) {
  const url = new URL(request.url);

  // 获取客户端真实 IP（CF 自动提供）
  const clientIP = request.headers.get('CF-Connecting-IP') ||
                   request.headers.get('X-Real-IP') ||
                   '0.0.0.0';

  // 根据客户端 IP 选择固定后端（不轮询，不跳动）
  const backend = await getBackendByIP(clientIP);

  // 后台异步健康检查（不阻塞当前请求）
  checkHealth(backend).catch(() => {});

  // 判断是否是 WebSocket 升级请求
  const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();

  if (upgrade === 'websocket') {
    return handleWebSocket(request, url, backend);
  }

  return handleHTTP(request, url, backend);
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request);
  },
};
