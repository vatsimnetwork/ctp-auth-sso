FROM gcr.io/distroless/base

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/ctp-auth-sso ./ctp-auth-sso
COPY templates/ ./templates/
COPY static/ ./static/

CMD ["/ctp-auth-sso"]