#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import hmac
import time
import json
from aiohttp import web
from urllib.parse import quote

# =============================================================================
# 配置 - 通过环境变量设置
# =============================================================================

UUID = os.environ.get('UUID', '233dcb7e-7044-4a22-ab64-287338a11d53')
DOMAIN = os.environ.get('DOMAIN', '')
NAME = os.environ.get('NAME', '')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

# 路径派生：基于UUID自动生成，也可通过环境变量覆盖
def _derive(purpose):
    return hmac.new(UUID.encode(), purpose.encode(), hashlib.sha256).hexdigest()[:10]

WS_PATH = os.environ.get('WSPATH') or _derive('ws')
SUB_PATH = os.environ.get('SUB_PATH') or _derive('sub')

# 内部常量
UUID_NO_DASH = UUID.replace('-', '')
UUID_BYTES = bytes.fromhex(UUID_NO_DASH)
TROJAN_HASH = hashlib.sha224(UUID.encode()).hexdigest()
BUFFER_SIZE = 16384
MAX_CONCURRENT = 50
CONNECT_TIMEOUT = 10

# =============================================================================
# 日志
# =============================================================================

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
for _m in ['aiohttp.access', 'aiohttp.server', 'aiohttp.client',
           'aiohttp.internal', 'aiohttp.websocket']:
    logging.getLogger(_m).setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# =============================================================================
# 安全过滤
# =============================================================================

BLOCKED_DOMAINS = {
    'speedtest.cn', 
    'speedof.me', 'testmy.net', 'bandwidth.place', 'librespeed.org',
    'speedcheck.org', 'speed.io'
}

PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

def is_blocked(host, port=0):
    if host:
        h = host.lower()
        if any(h == d or h.endswith('.' + d) for d in BLOCKED_DOMAINS):
            return True
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in net for net in PRIVATE_NETWORKS):
            return True
    except ValueError:
        pass
    if port in (25, 465, 587):
        return True
    return False

# =============================================================================
# DNS 缓存
# =============================================================================

class DNSCache:
    def __init__(self, ttl=300):
        self._cache = {}
        self._ttl = ttl

    async def resolve(self, host):
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        now = time.time()
        cached = self._cache.get(host)
        if cached and now < cached[1]:
            return cached[0]

        ip = await self._query(host)
        if ip:
            self._cache[host] = (ip, now + self._ttl)
            if len(self._cache) > 500:
                self._evict(now)
        return ip or host

    async def _query(self, host):
        endpoints = [
            ('https://dns.google/resolve', {}),
            ('https://cloudflare-dns.com/dns-query', {'Accept': 'application/dns-json'}),
        ]
        for url, headers in endpoints:
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(
                        f'{url}?name={host}&type=A',
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=3)
                    ) as r:
                        if r.status == 200:
                            data = await r.json()
                            if data.get('Status') == 0:
                                for a in data.get('Answer', []):
                                    if a.get('type') == 1:
                                        return a['data']
            except Exception:
                continue
        return None

    def _evict(self, now):
        expired = [k for k, (_, t) in self._cache.items() if t <= now]
        for k in expired:
            del self._cache[k]

dns_cache = DNSCache()

# =============================================================================
# 缓冲区读取器
# =============================================================================

class BufferReader:
    __slots__ = ('data', 'pos')

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    @property
    def remaining(self):
        return len(self.data) - self.pos

    def byte(self):
        if self.pos >= len(self.data):
            raise ValueError("underflow")
        v = self.data[self.pos]
        self.pos += 1
        return v

    def read(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("underflow")
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def uint16(self):
        return struct.unpack('!H', self.read(2))[0]

    def ipv4(self):
        return '.'.join(str(b) for b in self.read(4))

    def ipv6(self):
        return str(ipaddress.IPv6Address(self.read(16)))

    def domain(self):
        length = self.byte()
        return self.read(length).decode('ascii')

    def skip_crlf(self):
        if (self.pos + 2 <= len(self.data) and
                self.data[self.pos:self.pos + 2] == b'\r\n'):
            self.pos += 2

    def rest(self):
        v = self.data[self.pos:]
        self.pos = len(self.data)
        return v

# =============================================================================
# 协议解析
# =============================================================================

def parse_address(buf, atyp):
    """通用地址解析"""
    if atyp == 1:   return buf.ipv4()
    elif atyp == 2: return buf.domain()
    elif atyp == 3: return buf.domain()
    elif atyp == 4: return buf.ipv6()
    raise ValueError(f"unknown atyp: {atyp}")


def parse_vless(data):
    try:
        buf = BufferReader(data)
        if buf.byte() != 0:
            return None
        if buf.read(16) != UUID_BYTES:
            return None
        addon_len = buf.byte()
        if addon_len:
            buf.read(addon_len)
        cmd = buf.byte()
        if cmd != 1:
            return None
        port = buf.uint16()
        atyp = buf.byte()
        host = parse_address(buf, atyp)
        return host, port, b'\x00\x00', buf.rest()
    except (ValueError, UnicodeDecodeError):
        return None


def parse_trojan(data):
    try:
        if len(data) < 58:
            return None
        buf = BufferReader(data)
        received = buf.read(56).decode('ascii')
        if received != TROJAN_HASH:
            return None
        buf.skip_crlf()
        if buf.byte() != 1:
            return None
        atyp = buf.byte()
        if atyp == 1:   host = buf.ipv4()
        elif atyp == 3: host = buf.domain()
        elif atyp == 4: host = buf.ipv6()
        else: return None
        port = buf.uint16()
        buf.skip_crlf()
        return host, port, None, buf.rest()
    except (ValueError, UnicodeDecodeError):
        return None


def parse_shadowsocks(data):
    try:
        if not data or data[0] not in (1, 3, 4):
            return None
        buf = BufferReader(data)
        atyp = buf.byte()
        if atyp == 1:   host = buf.ipv4()
        elif atyp == 3: host = buf.domain()
        elif atyp == 4: host = buf.ipv6()
        else: return None
        port = buf.uint16()
        return host, port, None, buf.rest()
    except (ValueError, UnicodeDecodeError):
        return None


def detect_protocol(data):
    if len(data) > 17 and data[0] == 0:
        r = parse_vless(data)
        if r:
            return 'vless', r

    if len(data) >= 58:
        r = parse_trojan(data)
        if r:
            return 'trojan', r

    if len(data) > 3 and data[0] in (1, 3, 4):
        r = parse_shadowsocks(data)
        if r:
            return 'ss', r

    return None, None

# =============================================================================
# 双向转发
# =============================================================================

_semaphore = asyncio.Semaphore(MAX_CONCURRENT)

async def relay(ws, host, port, initial=None):
    reader = writer = None
    try:
        resolved = await dns_cache.resolve(host)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved, port),
            timeout=CONNECT_TIMEOUT
        )

        if initial:
            writer.write(initial)
            await writer.drain()

        async def ws_to_tcp():
            try:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data)
                        await writer.drain()
                    elif msg.type in (aiohttp.WSMsgType.ERROR,
                                      aiohttp.WSMsgType.CLOSE,
                                      aiohttp.WSMsgType.CLOSING):
                        break
            except (ConnectionError, OSError):
                pass

        async def tcp_to_ws():
            try:
                while True:
                    chunk = await reader.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    await ws.send_bytes(chunk)
            except (ConnectionError, OSError):
                pass

        t1 = asyncio.create_task(ws_to_tcp())
        t2 = asyncio.create_task(tcp_to_ws())
        _, pending = await asyncio.wait(
            [t1, t2], return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    except asyncio.TimeoutError:
        logger.debug(f"Timeout → {host}:{port}")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.debug(f"Relay error: {e}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

# =============================================================================
# WebSocket 处理
# =============================================================================

async def ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    acquired = False

    try:
        if _semaphore.locked():
            return ws

        await _semaphore.acquire()
        acquired = True

        msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if msg.type != aiohttp.WSMsgType.BINARY:
            return ws

        proto, result = detect_protocol(msg.data)
        if not result:
            return ws

        host, port, response, payload = result

        if is_blocked(host, port):
            logger.debug(f"Blocked: {host}:{port}")
            return ws

        logger.debug(f"[{proto}] → {host}:{port}")

        if response:
            await ws.send_bytes(response)

        await relay(ws, host, port, payload or None)

    except asyncio.TimeoutError:
        pass
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.debug(f"WS error: {e}")
    finally:
        if acquired:
            _semaphore.release()
        if not ws.closed:
            await ws.close()

    return ws

# =============================================================================
# 网络信息（ISP + IP 检测）
# =============================================================================

_net_info = {'domain': '', 'port': 443, 'tls': 'tls', 'isp': ''}
_net_ready = False

async def init_net_info():
    global _net_ready
    if _net_ready:
        return

    # 获取 ISP
    for url, cc, isp in [
        ('https://api.ip.sb/geoip', 'country_code', 'isp'),
        ('http://ip-api.com/json', 'countryCode', 'org'),
    ]:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url,
                    headers={'User-Agent': 'Mozilla/5.0'},
                    timeout=aiohttp.ClientTimeout(total=3)
                ) as r:
                    if r.status == 200:
                        d = await r.json()
                        _net_info['isp'] = f"{d.get(cc,'')}-{d.get(isp,'')}".replace(' ','_')
                        break
        except Exception:
            continue

    if not _net_info['isp']:
        _net_info['isp'] = 'Unknown'

    # 域名/IP
    if DOMAIN:
        _net_info['domain'] = DOMAIN
        _net_info['tls'] = 'tls'
        _net_info['port'] = 443
    else:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get('https://api-ipv4.ip.sb/ip',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as r:
                    if r.status == 200:
                        _net_info['domain'] = (await r.text()).strip()
                        _net_info['tls'] = 'none'
                        _net_info['port'] = PORT
        except Exception:
            _net_info['domain'] = 'your-domain.com'

    _net_ready = True

# =============================================================================
# 伪装首页
# =============================================================================

FAKE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>TaskFlow - Project Management</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#f0f2f5;color:#1a1a2e;line-height:1.6}
.nav{background:#1a1a2e;color:#fff;padding:1rem 2rem;display:flex;
justify-content:space-between;align-items:center}
.nav h1{font-size:1.4rem}
.nav a{color:#8888aa;text-decoration:none;margin-left:1.5rem;font-size:.9rem}
.wrap{max-width:1100px;margin:2rem auto;padding:0 1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.2rem}
.card{background:#fff;border-radius:10px;padding:1.4rem;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card h3{margin-bottom:.4rem;font-size:1rem}
.card p{color:#666;font-size:.88rem}
.num{font-size:1.8rem;font-weight:700;color:#4361ee}
.bar{background:#e9ecef;border-radius:8px;height:6px;margin-top:.8rem}
.bar>div{background:#4361ee;height:100%;border-radius:8px}
.tag{display:inline-block;padding:.15rem .6rem;border-radius:12px;font-size:.75rem}
.g{background:#d4edda;color:#155724}
.b{background:#cce5ff;color:#004085}
.y{background:#fff3cd;color:#856404}
footer{text-align:center;padding:2rem;color:#aaa;font-size:.8rem}
</style>
</head>
<body>
<div class="nav"><h1>TaskFlow</h1><nav>
<a href="#">Dashboard</a><a href="#">Projects</a><a href="#">Team</a>
</nav></div>
<div class="wrap">
<h2 style="margin-bottom:1.2rem">Dashboard</h2>
<div class="grid">
<div class="card"><h3>Active Projects</h3><div class="num">12</div>
<p>3 due this week</p><div class="bar"><div style="width:75%"></div></div></div>
<div class="card"><h3>Tasks Done</h3><div class="num">847</div>
<p>+23 this week</p><div class="bar"><div style="width:62%"></div></div></div>
<div class="card"><h3>Team</h3><div class="num">16</div>
<p>4 online</p><div class="bar"><div style="width:90%"></div></div></div>
<div class="card"><h3>Activity</h3>
<p><span class="tag g">Done</span> UI review</p>
<p><span class="tag b">Active</span> API work</p>
<p><span class="tag y">Pending</span> Migration</p></div>
</div></div>
<footer>2024 TaskFlow Inc.</footer>
</body></html>"""

# =============================================================================
# HTTP 路由处理
# =============================================================================

_start_time = time.time()

async def index_handler(request):
    return web.Response(text=FAKE_PAGE, content_type='text/html')

async def health_handler(request):
    return web.json_response({
        'status': 'healthy',
        'uptime': int(time.time() - _start_time),
        'version': '2.1.0'
    })

async def api_projects(request):
    return web.json_response({
        'projects': [
            {'id': 1, 'name': 'Website Redesign', 'progress': 75},
            {'id': 2, 'name': 'Mobile App', 'progress': 45},
        ],
        'total': 2
    })

async def api_tasks(request):
    return web.json_response({
        'tasks': [
            {'id': 1, 'title': 'Fix login bug', 'status': 'done'},
            {'id': 2, 'title': 'Add dark mode', 'status': 'active'},
        ],
        'total': 2
    })

async def robots_handler(request):
    return web.Response(
        text="User-agent: *\nDisallow: /api/\nAllow: /\n",
        content_type='text/plain'
    )

async def favicon_handler(request):
    return web.Response(status=204)


# ---------- 订阅 ----------

async def sub_handler(request):
    """
    访问方式: https://域名/{SUB_PATH}
    和原版一样简单直接
    """
    await init_net_info()

    i = _net_info
    name = f"{NAME}-{i['isp']}" if NAME else i['isp']
    d = i['domain']
    p = i['port']
    tls = i['tls']
    ws = quote(f'/{WS_PATH}', safe='')

    links = []

    # VLESS (v2rayN 原生支持)
    links.append(
        f"vless://{UUID}@{d}:{p}"
        f"?encryption=none&security={tls}&sni={d}"
        f"&fp=chrome&type=ws&host={d}&path={ws}"
        f"#{name}"
    )

    # Trojan (v2rayN 原生支持)
    links.append(
        f"trojan://{UUID}@{d}:{p}"
        f"?security={tls}&sni={d}"
        f"&fp=chrome&type=ws&host={d}&path={ws}"
        f"#{name}"
    )

    # Shadowsocks (需要 v2ray-plugin)
    ss_cred = base64.b64encode(f"none:{UUID}".encode()).decode()
    ss_tls = 'tls;' if tls == 'tls' else ''
    links.append(
        f"ss://{ss_cred}@{d}:{p}"
        f"?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{d}"
        f";path%3D{ws};{ss_tls}"
        f"sni%3D{d};skip-cert-verify%3Dtrue;mux%3D0"
        f"#{name}"
    )

    content = base64.b64encode('\n'.join(links).encode()).decode()
    return web.Response(text=content + '\n', content_type='text/plain')

# =============================================================================
# 中间件
# =============================================================================

@web.middleware
async def headers_middleware(request, handler):
    try:
        resp = await handler(request)
    except web.HTTPNotFound:
        return web.json_response({'error': 'Not found'}, status=404)
    except web.HTTPException as e:
        raise e
    resp.headers['Server'] = 'nginx'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    return resp

# =============================================================================
# 启动
# =============================================================================

def find_port(start, attempts=100):
    for p in range(start, start + attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', p))
            s.close()
            return p
        except OSError:
            continue
    return None


async def main():
    port = find_port(PORT)
    if not port:
        logger.error("No available port")
        sys.exit(1)

    app = web.Application(middlewares=[headers_middleware])

    # ---- 伪装路由（让网站看起来正常）----
    app.router.add_get('/', index_handler)
    app.router.add_get('/favicon.ico', favicon_handler)
    app.router.add_get('/robots.txt', robots_handler)
    app.router.add_get('/api/health', health_handler)
    app.router.add_get('/api/v1/projects', api_projects)
    app.router.add_get('/api/v1/tasks', api_tasks)

    # ---- 核心路由 ----
    # WebSocket 代理入口
    app.router.add_get(f'/{WS_PATH}', ws_handler)
    # 订阅接口：和原版一样，域名/路径 即可访问
    app.router.add_get(f'/{SUB_PATH}', sub_handler)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()

    # 打印使用信息
    logger.info("=" * 60)
    logger.info("  Server started successfully")
    logger.info(f"  Port      : {port}")
    logger.info(f"  WS Path   : /{WS_PATH}")
    logger.info(f"  Sub Path  : /{SUB_PATH}")
    if DOMAIN:
        logger.info(f"  Sub URL   : https://{DOMAIN}/{SUB_PATH}")
    else:
        logger.info(f"  Sub URL   : http://localhost:{port}/{SUB_PATH}")
    logger.info("=" * 60)

    try:
        await asyncio.Future()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
