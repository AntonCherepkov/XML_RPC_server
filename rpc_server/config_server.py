import os
from dotenv import load_dotenv, find_dotenv


if not find_dotenv():
    exit('Переменные окружения не загружены, нет файла .env')
else:
    load_dotenv()


class ConfigServer:
    POSTGRES_USER = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
    POSTGRES_DB = os.getenv("POSTGRES_DB")
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", 5432)

    # URL подключения к базе данных:
    SQLALCHEMY_DATABASE_URL = (
        f"postgresql+psycopg2://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
        f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    )
