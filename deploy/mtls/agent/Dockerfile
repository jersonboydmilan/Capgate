ARG BASE_IMAGE=alpine:latest
FROM ${BASE_IMAGE}
COPY deploy/.cache/python.tar.gz /tmp/python.tar.gz
RUN tar -xzf /tmp/python.tar.gz -C /opt && rm /tmp/python.tar.gz && adduser -S -D -H -u 20001 agent
COPY deploy/mtls/agent/agent.py /agent/agent.py
ENV PATH=/opt/python/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 20001
ENTRYPOINT ["python3", "/agent/agent.py"]
