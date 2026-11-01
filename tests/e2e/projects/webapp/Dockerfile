FROM alpine:3.20

# The app runs with the developer's ids, so that what it writes to the mounted src/ stays theirs.
ARG UID=1000
ARG GID=1000
RUN addgroup -g "$GID" app && adduser -D -u "$UID" -G app app

WORKDIR /app
COPY --chown=app:app src/ src/
USER app
EXPOSE 8000
CMD ["httpd", "-f", "-v", "-p", "8000", "-h", "/app/src"]
