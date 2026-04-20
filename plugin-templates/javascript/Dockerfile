FROM node:20-slim

# Copy plugin code — no npm install needed (zero external dependencies)
COPY package.json /app/package.json
COPY main.js /app/main.js
COPY .plugger/metadata.yaml /.plugger/metadata.yaml
RUN mkdir -p /data && chown node:node /data

# Run as built-in non-root user (uid 1000)
USER node
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["node", "main.js"]
