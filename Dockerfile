# SentryScan production image. Uses the official Playwright image so the render
# scanner's headless Chromium is preinstalled (matching the playwright dep).
FROM mcr.microsoft.com/playwright:v1.49.1-jammy

ENV NODE_ENV=production
WORKDIR /app

# Install dependencies against the committed lockfile for reproducible builds.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# App source.
COPY . .

# The user store lives here at runtime; keep it writable. Mount a volume in prod
# so accounts survive redeploys (or swap store.js for a real database).
RUN mkdir -p /app/data

# Render/most PaaS inject PORT; default to 3000 if unset.
ENV PORT=3000
EXPOSE 3000

# Run as the non-root user provided by the Playwright base image.
USER pwuser

CMD ["node", "server.js"]
