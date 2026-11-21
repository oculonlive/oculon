# Oculon web server for a public deployment (Railway, Fly, any Docker host).
# Data lives in /data: mount a persistent volume there, or every redeploy starts from an empty database.

FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-slim
WORKDIR /app
ENV NODE_ENV=production \
    OCULON_HOME=/data \
    HOST=0.0.0.0 \
    OCULON_PUBLIC=1
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY README.md LICENSE ./
EXPOSE 8080
# Public mode: overview, docs and a read-only API for visitors; the dashboard needs OCULON_ADMIN_TOKEN.
CMD ["node", "dist/cli.js", "serve", "--host", "0.0.0.0", "--public", "--watch", "15", "--live"]
