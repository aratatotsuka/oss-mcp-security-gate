FROM scratch
ARG SCANNER_FILE=scanner
COPY --chown=65532:65532 ${SCANNER_FILE} /scanner
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT ["/scanner"]
