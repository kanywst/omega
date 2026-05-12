# syntax=docker/dockerfile:1.7
#
# Production container for the Omega admin dashboard.
# Two-stage build using Next.js standalone output, served from a distroless
# Node.js runtime so the final image has no shell and no package manager.

FROM node:26-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian12 AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000
USER nonroot
CMD ["server.js"]
