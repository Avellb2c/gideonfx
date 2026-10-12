"""Dependency-free validation of native installer hostnames before installation."""
import ipaddress
import re
import sys


def bootstrap_host(value):
    value = value.strip().lower().rstrip('.')
    if value == 'localhost':
        return value
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if (len(value) > 253 or '.' not in value or re.fullmatch(r'[0-9.]+', value)
                or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                           for p in value.split('.'))):
            raise ValueError('Hostname/IP inválido: use FQDN, IPv4 o localhost, sin URL, puerto ni ruta.')
        return value
    if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ValueError('Use IPv4 unicast; el bootstrap local admite 127.0.0.1.')
    return str(address)


if __name__ == '__main__':
    try:
        for value in sys.argv[1:]:
            print(bootstrap_host(value))
    except ValueError as exc:
        raise SystemExit(str(exc))
