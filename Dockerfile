FROM golang:1.26 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN curl -sLo tailwindcss https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 && \
    chmod +x tailwindcss && \
    ./tailwindcss -i static/themes.css -o static/tailwind.css --minify

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o /ctp-auth-sso .

FROM gcr.io/distroless/base

COPY --from=builder /ctp-auth-sso ./ctp-auth-sso
COPY --from=builder /app/templates/ ./templates/
COPY --from=builder /app/static/ ./static/
COPY --from=builder /app/favicon.ico ./favicon.ico

CMD ["/ctp-auth-sso"]
