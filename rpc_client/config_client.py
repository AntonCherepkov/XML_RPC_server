from dotenv import load_dotenv, find_dotenv
import os


if not find_dotenv():
    exit('Переменные окружения не загружены, нет файла .env')
else:
    load_dotenv()

class ConfigClient:
    SERVER_URL = os.getenv('SERVER_URL')
