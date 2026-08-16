# Vikunja MCP (streamable HTTP) — fork build for htz-metal-1.
#
# Two stages so the runtime image carries no toolchain: the build needs dev
# dependencies (TypeScript) and runs patch-package via postinstall, but none of
# that belongs in the image that holds the Vikunja API token.
#
# The patches/ directory is copied BEFORE npm ci in both stages: patch-package
# runs from the postinstall hook and silently no-ops if the patches are absent,
# which would ship an image that still calls Vikunja 0.24 endpoints.

FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY patches ./patches
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY patches ./patches
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /app/dist ./dist
# Drop root — nothing at runtime needs to write to disk.
USER node
EXPOSE 3100
CMD ["node", "dist/http.js"]
