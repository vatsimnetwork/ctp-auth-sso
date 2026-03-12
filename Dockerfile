FROM gcr.io/distroless/base

COPY egm-fraktions-bot ./egm-fraktions-bot
 
CMD ["/egm-fraktions-bot"]