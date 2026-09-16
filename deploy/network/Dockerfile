# netguard: owns the agent's network namespace and installs the egress allowlist.
# Built offline; apk verifies package signatures against the base image's keys.
ARG BASE_IMAGE=alpine:latest
FROM ${BASE_IMAGE}
COPY deploy/.cache/apk /tmp/apk
RUN apk add --no-network /tmp/apk/*.apk && rm -rf /tmp/apk
COPY deploy/network/netguard.sh /netguard.sh
ENTRYPOINT ["/bin/sh", "/netguard.sh"]
