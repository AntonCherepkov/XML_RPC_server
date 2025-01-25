import sqlalchemy.exc
from sqlalchemy import create_engine

from sqlalchemy.orm import sessionmaker
from rpc_server.db_models import User, AppData, Base

class DataBaseManager:
    """Класс для работы с БД, используемая ORM: SQLAlchemy, плюс context manager"""
    def __init__(self, db_url):
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
        self.session = None


    def __enter__(self):
        """Инициализация сессии при входе в контекст-менеджер"""
        self.session = self.Session()
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        """Закрытие сессии при выходе из контекст-менеджера"""
        self.session.close()


    def create_tables(self):
        """Метод для создания таблиц (первый запуск)"""
        Base.metadata.create_all(self.engine)


    def execute_raw_query(self, query, params=None):
        """Использовать для выполнения сырых SQL-запросов"""
        with self.engine.connect() as connection:
            result = connection.execute(query, params or {})
            return result.fetchall()


    def get_app_data(self, key):
        """Получить значение из app_data по ключу"""
        result = self.session.query(AppData).filter(AppData.key == key).first()
        return result.value if result else None


    def add_app_data(self, key, value):
        """Метод для добавления новых данных в БД, если ключ уже существует - обновляет значение"""
        try:
            existing_data = self.session.query(AppData).filter_by(key=key).first()

            if existing_data:
                existing_data.value = value
                self.session.commit()
                print(f"Обновлено значение для ключа {key}")
                return f"Value updated for key: {key}"

            new_data = AppData(key=key, value=value)
            self.session.add(new_data)
            self.session.commit()
            print(f"Добавлена новая запись: {key} -> {value}")
            return "New information added"

        except (sqlalchemy.exc.IntegrityError, Exception) as e:
            print(f'Ошибка добавления информации: {e}')
            return 'An error of adding information'


    def get_user_by_username(self, username):
        """Получить пользователя по имени"""
        return self.session.query(User).filter(User.username == username).first()


    def add_user(self, user_name: str, password: str):
        """Метод для добавления новых пользователей в БД"""
        try:
            new_user = User(username=user_name, password=password)
            self.session.add(new_user)
            self.session.commit()
            return 'User registered successfully'

        except (sqlalchemy.exc.IntegrityError, Exception) as e:
            print(f'Ошибка регистрации: {e}')
            return 'Error registering user'
