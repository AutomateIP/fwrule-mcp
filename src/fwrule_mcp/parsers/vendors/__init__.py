"""
Vendor parsers sub-package.

Each sub-directory contains a self-contained parser for one firewall vendor.
Vendor parsers register themselves with the global registry on import via
their __init__.py files.

The registry auto-imports all vendor packages on first use — callers do not
need to import vendor packages directly.  However, direct imports are safe
and idempotent (double-registration is handled gracefully).

Supported vendors:
  - panos/      : Palo Alto Networks PAN-OS and Panorama (XML format)
  - asa/        : Cisco ASA (flat text / show running-config format)
  - ftd/        : Cisco Firepower Threat Defense via FMC JSON export
  - checkpoint/ : Check Point management API JSON package export
  - juniper/    : Juniper SRX hierarchical set-command format
"""
