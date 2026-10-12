"""Source-network boundary for a directly published WebAdmin (HTTP and WSS)."""
from __future__ import annotations

import ipaddress


class AdminNetworkBoundary:
    def __init__(self, app, allowed_cidrs=None):
        self.app = app
        # None preserves existing private deployments. An explicit empty list
        # fails closed; external setup always supplies a non-empty allowlist.
        self.networks = None if allowed_cidrs is None else tuple(
            ipaddress.ip_network(value, strict=False) for value in allowed_cidrs
        )

    async def __call__(self, scope, receive, send):
        if scope['type'] not in {'http', 'websocket'} or self.networks is None:
            return await self.app(scope, receive, send)
        try:
            address = ipaddress.ip_address((scope.get('client') or ('', 0))[0])
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            permitted = any(address in network for network in self.networks)
        except ValueError:
            permitted = False
        # Deliberately ignore X-Forwarded-For and similar user-controlled headers.
        if permitted:
            return await self.app(scope, receive, send)
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': 1008})
        else:
            body = b'Administrative access is restricted to approved networks.'
            await send({'type': 'http.response.start', 'status': 403,
                        'headers': [(b'content-type', b'text/plain'),
                                    (b'content-length', str(len(body)).encode())]})
            await send({'type': 'http.response.body', 'body': body})
