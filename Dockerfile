FROM node:22-alpine

WORKDIR /app

# Install system dependencies for Git repository cloning & TLS
RUN apk add --no-cache git ca-certificates

# Copy dependency files
COPY package*.json ./
COPY backend/package*.json ./backend/

# Install dependencies
RUN npm install --prefix backend

# Copy source code and dataset
COPY . .

# Expose Web UI & API port
EXPOSE 3001

ENV PORT=3001
ENV NODE_ENV=production

# Start platform
CMD ["node", "--experimental-strip-types", "backend/src/server.ts"]
