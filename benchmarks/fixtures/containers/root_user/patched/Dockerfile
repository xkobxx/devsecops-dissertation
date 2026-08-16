# Patched benchmark equivalent. It is not a deployable image.
FROM scratch
COPY --chown=10001:10001 app /app
USER 10001:10001
ENTRYPOINT ["/app"]
