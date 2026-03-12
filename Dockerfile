FROM gcr.io/distroless/base

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/ctp-auth-sso ./ctp-auth-sso

CMD ["/ctp-auth-sso"]