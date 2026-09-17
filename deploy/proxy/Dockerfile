# Edge proxy in front of the harness API: the only service on the agent's network
# that forwards anything. Built offline; apk verifies package signatures.
ARG BASE_IMAGE=alpine:latest
FROM ${BASE_IMAGE}
COPY deploy/.cache/apk-proxy /tmp/apk
RUN apk add --no-network /tmp/apk/*.apk && rm -rf /tmp/apk \
 && adduser -S -D -H -u 10002 proxy \
 && rm -rf /etc/nginx/http.d /var/lib/nginx/html
COPY deploy/proxy/nginx.conf /etc/nginx/nginx.conf
USER 10002
EXPOSE 8080
ENTRYPOINT ["nginx", "-e", "/dev/stderr", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
