# Untrusted agent image: a Python runtime, the thin client SDK and the agent
# script. No harness package, no tool code, no configuration, no secrets.
ARG BASE_IMAGE=alpine:latest
FROM ${BASE_IMAGE}
COPY deploy/.cache/python.tar.gz /tmp/python.tar.gz
RUN tar -xzf /tmp/python.tar.gz -C /opt && rm /tmp/python.tar.gz && adduser -S -D -H -u 20001 agent
COPY sdk/python/capgate_client /app/capgate_client
COPY examples/adversarial-agent/malicious_agent.py /app/malicious_agent.py
ENV PATH=/opt/python/bin:/usr/bin:/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
USER 20001
CMD ["python3", "malicious_agent.py"]
