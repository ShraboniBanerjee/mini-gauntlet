# syntax=docker/dockerfile:1

# ---- Build: compile the dashboard to static files ----------------------------------
FROM node:22.23.5-alpine3.23 AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# ---- Runtime: nginx as a non-root user serving the build and proxying /api ---------
FROM nginxinc/nginx-unprivileged:1.29.5-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# The base image's nginx user (uid 101); stated explicitly.
USER 101
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
