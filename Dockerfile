FROM node:20-bookworm-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY scripts ./scripts
COPY database ./database
COPY server.js ./
COPY swagger.yaml ./

EXPOSE 3000

USER node
CMD ["node", "server.js"]
