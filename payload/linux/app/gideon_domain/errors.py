from __future__ import annotations


class GIDEONError(Exception):
    """Base para errores controlados de la plataforma."""


class ValidationError(GIDEONError):
    """Entrada, configuración o compatibilidad inválida."""


class TransportError(GIDEONError):
    """Error del canal de transporte."""


class ConnectivityError(TransportError):
    """No existe ruta o sesión utilizable hacia el destino."""


class IntegrityError(GIDEONError):
    """Hash, tamaño o manifiesto no coincide."""


class PersistenceError(GIDEONError):
    """No se pudo persistir o recuperar el estado del Job."""


class CancellationError(GIDEONError):
    """No se pudo cancelar de forma segura."""


class RemoteExecutionError(GIDEONError):
    """El proceso remoto devolvió un resultado no satisfactorio."""
