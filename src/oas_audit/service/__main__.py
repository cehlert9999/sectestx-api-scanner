"""``python -m oas_audit.service`` — startet den Dienst lokal."""

import os

import uvicorn

from oas_audit.service.app import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host=os.environ.get("OAS_AUDIT_HOST", "127.0.0.1"),
                port=int(os.environ.get("OAS_AUDIT_PORT", "6010")), log_level="info",
                access_log=False)  # kein Access-Log: keine IPs, keine Pfade auf Platte
