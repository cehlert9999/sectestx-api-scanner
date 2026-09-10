# Betrieb des Scan-Dienstes

Ziel: `api.sectestx.leanofy.de` auf dem Hetzner-Server (<SERVER-IP>), Nginx davor,
der Dienst selbst nur auf `127.0.0.1:6010`.

## Einmalig auf dem Server

```bash
useradd --system --home /opt/oas-audit --shell /usr/sbin/nologin oas-audit
mkdir -p /opt/oas-audit /etc/oas-audit
python3 -m venv /opt/oas-audit/.venv
/opt/oas-audit/.venv/bin/pip install "/opt/oas-audit/src[service]"     # Checkout liegt unter src/
cp deploy/env.example /etc/oas-audit/env && chmod 600 /etc/oas-audit/env  # Secret eintragen!
cp deploy/oas-audit.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now oas-audit
cp deploy/nginx.api.sectestx.leanofy.de.conf /etc/nginx/sites-available/api.sectestx.leanofy.de
ln -s /etc/nginx/sites-available/api.sectestx.leanofy.de /etc/nginx/sites-enabled/
certbot --nginx -d api.sectestx.leanofy.de && nginx -t && systemctl reload nginx
curl -s https://api.sectestx.leanofy.de/healthz
```

## Jenkins

Pipeline nach dem vorhandenen Hetzner-Muster: `git pull` in `/opt/oas-audit/src`,
`pip install -e ".[service]"`, `pytest -q`, `systemctl restart oas-audit`, Healthcheck.
Test-Instanz analog auf Port 6011 unter `api-test.sectestx.leanofy.de`.

## Was der Dienst zusichert

| Zusicherung | Wo das steht |
|---|---|
| Spezifikation nur im RAM, nie auf Platte | `service/app.py`, `tests/test_free_isolation.py` |
| Kein Request an die beschriebene API, kein URL-Fetch | `tests/test_free_isolation.py` |
| Kein Access-Log, IPs nur als Tages-Hash | `service/limits.py`, Nginx-Konfiguration |
| Jede Analyse im eigenen Prozess mit Limits | `service/sandbox.py` |
| 2 MB, 5 Scans/h, 20/Tag, 500/Tag global | `service/settings.py` |
| Ergebnis HMAC-signiert, Speicherung erst beim Bericht (v1.1) | `service/signing.py` |
