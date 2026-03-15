FROM gcr.io/distroless/base

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/ctp-auth-sso ./ctp-auth-sso
COPY templates/ ./templates/
COPY static/ ./static/
COPY favicon.ico ./favicon.ico

CMD ["/ctp-auth-sso"]