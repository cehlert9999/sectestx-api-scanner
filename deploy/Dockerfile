# Dasselbe Image für die öffentliche Instanz und für Selbst-Hosting.
# Wer die Spezifikation nicht hochladen darf, betreibt es intern:
#   docker run --rm -p 6010:6010 -e OAS_AUDIT_HOST=0.0.0.0 oas-audit
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[service]"

FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home audit
COPY --from=build /install /usr/local
USER audit
ENV OAS_AUDIT_HOST=0.0.0.0 OAS_AUDIT_PORT=6010 PYTHONDONTWRITEBYTECODE=1
EXPOSE 6010
# read-only Root-FS, kein Docker-Socket, keine neuen Privilegien — siehe README
CMD ["python", "-m", "oas_audit.service"]
