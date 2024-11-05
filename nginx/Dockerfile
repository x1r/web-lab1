FROM nginx:alpine

# Копируем наш конфигурационный файл nginx.conf в контейнер
COPY nginx.conf /etc/nginx/nginx.conf

# Указываем директорию для статических файлов (например, если сайт обслуживает статический контент)
WORKDIR /usr/share/nginx/html
