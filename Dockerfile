# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY yarn.lock* ./

# Install dependencies
RUN npm install --legacy-peer-deps || yarn install

# Copy source files
COPY . .

# Build React app
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY yarn.lock* ./

# Install only production dependencies
RUN npm install --production --legacy-peer-deps || yarn install --production

# Copy built files and server
COPY --from=builder /app/build ./build
COPY index.js ./
COPY db.json* ./

# Expose port
EXPOSE 3001

# Start server
CMD ["node", "index.js"]


