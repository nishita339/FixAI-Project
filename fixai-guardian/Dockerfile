# Stage 1: Build React app
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

ARG VITE_FASTAPI_URL=""
ARG VITE_CONVEX_URL=""
ENV VITE_FASTAPI_URL=$VITE_FASTAPI_URL
ENV VITE_CONVEX_URL=$VITE_CONVEX_URL

RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
