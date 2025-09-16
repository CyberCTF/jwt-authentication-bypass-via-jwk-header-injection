# Use Node.js 20 LTS
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY build/package.json ./
COPY build/keys/ ./keys/

# Install dependencies
RUN npm install --production

# Copy application source
COPY build/src/ ./src/

# Generate RSA keys if they don't exist
RUN if [ ! -f keys/server-private.pem ]; then node keys/generate-keys.js; fi

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Change ownership of the app directory
RUN chown -R nodejs:nodejs /app
USER nodejs

# Expose port
EXPOSE 3206

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3206/', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Start the application
CMD ["npm", "start"]
