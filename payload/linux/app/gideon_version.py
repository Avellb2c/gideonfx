"""Single source of truth for product/build-time version identifiers.

Standalone deployable runtimes (Agent/Gateway) retain a stamped local VERSION
inside their self-contained script/package; tests assert they match these values.
"""

PRODUCT_VERSION = "6.3.4-rc30"
AGENT_VERSION = "2.4.56"
GATEWAY_VERSION = "2.4.3"
AGENT_PROTOCOL_VERSION = "2.0"
FANOUT_PROTOCOL_VERSION = "3.3"
MANIFEST_SCHEMA_VERSION = 4
REMOTE_PACKAGE_SCHEMA_VERSION = 4
EVENT_SCHEMA_VERSION = 3
