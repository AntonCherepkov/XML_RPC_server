# Dockerfile
FROM python:3.8-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем все файлы проекта в контейнер
COPY . .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Открываем порт для HTTP сервера
EXPOSE 8080

# Команда для запуска приложения
CMD ["python", "app.py"]