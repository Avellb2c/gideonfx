#!/usr/bin/env python3
"""Run from a client outside the GIDEON server to verify DNS/TLS/HTTP, never using -k."""
import argparse
import ipaddress
import json
import socket
import ssl
import urllib.request
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-url', required=True)
    parser.add_argument('--agent-url', required=True)
    parser.add_argument('--ca', help='CA pública GIDEON para laboratorio; nunca la clave privada.')
    parser.add_argument('--expected-ip', help='IP externa fija esperada en DNS.')
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca)
    if args.ca:
        context.verify_flags &= ~getattr(ssl, 'VERIFY_X509_STRICT', 0)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    results = []
    for name, base, path in (('WebAdmin', args.admin_url, '/healthz'), ('Agents', args.agent_url, '/health')):
        row = {'service': name, 'url': base, 'status': 'FAIL'}
        try:
            url = urlsplit(base)
            if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
                raise ValueError('Use una URL base HTTPS sin credenciales/ruta/query.')
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(url.hostname, url.port or 443, type=socket.SOCK_STREAM)})
            row['dns_addresses'] = addresses
            if args.expected_ip and str(ipaddress.ip_address(args.expected_ip)) not in addresses:
                raise ValueError('DNS no contiene la IP externa esperada.')
            with opener.open(base.rstrip('/') + path, timeout=15) as response:
                if response.status != 200 or urlsplit(response.url).netloc != url.netloc:
                    raise ValueError('Respuesta/redirect inesperado.')
                response.read(4096)
                row['status'] = 'PASS'
        except Exception as error:
            row['error'] = str(error)
        results.append(row)
    print(json.dumps({'endpoints': results, 'scope': 'DNS + verified TLS + HTTP health; WSS/RDP/SSH require functional sessions'}, indent=2))
    return 0 if all(row['status'] == 'PASS' for row in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
