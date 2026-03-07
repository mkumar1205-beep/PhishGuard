# ── Frontend container ─────────────────────────────────────────────────────
# Stage 1: build Vite app
# Stage 2: serve with Nginx (which also proxies /analyze → backend)
# ───────────────────────────────────────────────────────────────────────────

FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: Nginx
FROM nginx:alpine

COPY --from=builder /app/dist/public /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80