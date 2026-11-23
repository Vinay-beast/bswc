# syntax=docker/dockerfile:1
ARG BASE=node:20
FROM ${BASE} AS build
RUN curl -fsSL https://example.com/setup.sh \
    | sh
RUN npm ci
FROM gcr.io/distroless/nodejs20@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ADD https://example.com/tool.tgz /opt/tool.tgz
COPY --from=build /app /app
CMD ["app.js"]
