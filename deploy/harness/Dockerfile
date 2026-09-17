# Harness and tool-service image. Build context: repository root.
# Built offline from local artifacts: run `python deploy/fetch_artifacts.py` once first.
ARG BASE_IMAGE=alpine:latest
FROM ${BASE_IMAGE}
COPY deploy/.cache/python.tar.gz /tmp/python.tar.gz
RUN tar -xzf /tmp/python.tar.gz -C /opt && rm /tmp/python.tar.gz \
 && adduser -S -D -H -u 10001 harness \
 && mkdir -p /data /secrets /tool-credential /agent-credentials \
 && chown 10001 /data /secrets /tool-credential /agent-credentials
COPY deploy/.cache/yaml /opt/app/yaml
COPY deploy/.cache/pylibs /opt/app
COPY src/harness /opt/app/harness
ENV PATH=/opt/python/bin:/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH=/opt/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8080
CMD ["python3", "-m", "harness.cli", "serve", "/config/server.yaml", "--host", "0.0.0.0", "--port", "8080", "--transport", "uvicorn"]
