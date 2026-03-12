FROM gcr.io/distroless/base

COPY ctp-auth-sso ./ctp-auth-sso
 
CMD ["/ctp-auth-sso"]