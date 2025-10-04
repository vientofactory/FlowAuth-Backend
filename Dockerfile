# Backend Dockerfile
FROM node:22-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Copy package files
COPY ./backend/package.json ./backend/package-lock.json ./
RUN npm ci --omit=dev

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app

# Copy package files and shared module
COPY ./backend/package.json ./backend/package-lock.json ./
COPY ./shared ./shared

# Fix shared path for Docker and install dependencies
RUN sed -i 's|"file:../shared"|"file:./shared"|g' package.json && npm install

# Copy source code
COPY ./backend ./backend

# Build shared module first
WORKDIR /app/shared
RUN npm ci && npm run build

# Copy built shared module to node_modules
RUN cp -r /app/shared/dist/* /app/node_modules/@flowauth/shared/

# Go back to backend directory
WORKDIR /app/backend

# Build the application
RUN npm run build

# Build the application
RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production

# Create a non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nestjs

    # Copy the built application
    COPY --from=builder /app/backend/dist ./dist
    COPY --from=builder /app/node_modules ./node_modules
    COPY --from=builder /app/backend/package*.json ./
    COPY --from=builder /app/backend/.env ./.env
    COPY --from=builder /app/shared ./shared

    # Note: Using node_modules copied from builder stage to preserve @flowauth/shared module
    RUN mkdir -p uploads/avatars uploads/documents uploads/logos

# Change ownership of the app directory
RUN chown -R nestjs:nodejs /app
USER nestjs

EXPOSE 3000

ENV PORT 3000

# Start the server
CMD ["npm", "run", "start:prod"]