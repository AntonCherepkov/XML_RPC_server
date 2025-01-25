import hashlib
import functools
import hmac
from typing import Dict, Any, Callable, List, Optional
from session_managment import SessionManager
import time
import secrets
import json
from werkzeug.security import check_password_hash, generate_password_hash

from rpc_server.db_manager import DataBaseManager
from rpc_server.config_server import ConfigServer


def class_decorator_for_methods(methods_to_decorate: List[str]) -> Callable:
    """Декоратор для класса, применяющийся только к указанным методам"""
    def class_decorator(cls):
        """Поиск указанных в параметре методов для их нахождения в переданном классе"""
        for method_name in methods_to_decorate:
            if hasattr(cls, method_name):
                original_method = getattr(cls, method_name)
                def make_wrapper(method_name, original_method):
                    """Функция-обертка для метода, чтобы выполнить проверку сессии именно для него"""
                    @functools.wraps(original_method)
                    def wrapped_method(self, *args, **kwargs):
                        """Проверка валидности сессии в действительном экземпляре переданного класса"""
                        print(f"Вызов метода на сервере: {method_name}")

                        session_id = kwargs.get('session_id') or (args[0] if args else None)
                        if not session_id or session_id not in self.sessions.sessions:
                            print('Сессия не найдена')
                            return 'Session invalid or expired'
                        session_data = self.sessions.sessions[session_id]
                        if session_data['expiry'] < time.time():
                            print('Срок действия сессии истек')
                            return 'Session expired'

                        print('Сессия валидна')
                        return original_method(self, *args, **kwargs)

                    return wrapped_method

                wrapped_method = make_wrapper(method_name, original_method)
                setattr(cls, method_name, wrapped_method)
        return cls
    return class_decorator


@class_decorator_for_methods(['generate_secret', 'get_challenge', 'get_data', 'add_data'])
class XMLRPCMethods:
    """
    Класс, реализующий API сервера для обработки запросов XML-RPC

    Атрибуты:
    :param session: словарь, содержащий информацию о текущей сессии
    :param db_config: словарь, содержащий параметры подключения к БД
    """
    def __init__(self) -> None:
        self.sessions = SessionManager()


    def ping(self):
        """Метод для проверки соединения с сервером, при вызове клиентом метода ping, сервер возвращает pong"""
        return "pong"


    def login(self, user_name, password):
        """Метод для авторизации пользователя. Проверяет логин и пароль пользователя в БД"""
        try:
            with DataBaseManager(db_url=ConfigServer.SQLALCHEMY_DATABASE_URL) as db:
                user = db.get_user_by_username(username=user_name)

                if not user or not check_password_hash(user.password, password):
                    return 'Access denied'

                session_id = self.sessions.create_session(user_name)
                return session_id

        except Exception as e:
            print(f'Ошибка авторизации: {e}')
            return 'Access denied'


    def generate_secret(self, session_id: str, client_public_key: int, prime_num=5, generator_num=23) -> int:
        """Метод для генерации секрета для аутентификации клиента, реализуемый методом Диффи-Хеллмана"""
        print(f'Генерация секрета сервера для сессии {session_id}')

        server_private_key = secrets.randbelow(prime_num - 1) + 1
        server_public_key = pow(generator_num, server_private_key, prime_num)

        shared_secret = pow(client_public_key, server_private_key, prime_num)
        self.sessions.sessions[session_id]['shared_secret'] = shared_secret

        print(f'Публичный ключ сервера для сессии {session_id}: {server_public_key}')
        return server_public_key


    def get_challenge(self, session_id: str) -> str:
        """Метод для генерации челленджа для клиента"""
        challenge = secrets.token_hex(16)
        self.sessions.sessions[session_id]['challenge'] = challenge
        print(f'Сгенерирован челлендж: {challenge}')

        return challenge


    def register_user(self, user_name: str, password: str) -> str:
        """Метод для регистрации нового пользователя"""
        hashed_password = generate_password_hash(password=password)

        print(f'Регистрируем пользователя: {user_name}')

        with DataBaseManager(db_url=ConfigServer.SQLALCHEMY_DATABASE_URL) as db:
            if db.get_user_by_username(username=user_name):
                return 'User already exists'
            message = db.add_user(user_name=user_name, password=hashed_password)

            print(f'Результат регистрации: {message}')

            return message


    def get_data(self, session_id: str, key: str, hmac_signature: str) -> Optional[str]:
        """Получение данных из БД с проверкой HMAC-подписи"""
        if (
                self.sessions.sessions[session_id]['shared_secret'] is None or
                self.sessions.sessions[session_id]['challenge'] is None
        ):
            return 'Challenge or secret not set'

        message = {
            "key": key,
            "challenge": self.sessions.sessions[session_id]['challenge']
        }
        shared_secret_bytes = str(self.sessions.sessions[session_id]['shared_secret']).encode()
        message_bytes = json.dumps(message, separators=(',', ':')).encode()
        expected_signature = hmac.new(shared_secret_bytes, message_bytes, hashlib.sha256).hexdigest()

        if expected_signature != hmac_signature:
                return 'Invalid HMAC signature'

        with DataBaseManager(db_url=ConfigServer.SQLALCHEMY_DATABASE_URL) as db:
            result = db.get_app_data(key)

        return result if result else 'No data found'


    def add_data(self, session_id: str, key: str, value: str, hmac_signature: str) -> str:
        """Метод для добавления данных в БД с проверкой подписи"""
        if (
                self.sessions.sessions[session_id]['shared_secret'] is None or
                self.sessions.sessions[session_id]['challenge'] is None
        ):
            return 'Challenge или общий секрет не установлен'

        expected_signature = hmac.new(
            str(self.sessions.sessions[session_id]['shared_secret']).encode(),
            json.dumps({"key": key, "value": value, "challenge": self.sessions.sessions[session_id]['challenge']},
                       separators=(',', ':')).encode(),
            hashlib.sha256,
        ).hexdigest()

        if expected_signature != hmac_signature:
            return 'Неверная HMAC-подпись'

        # Добавляем данные в БД
        with DataBaseManager(db_url=ConfigServer.SQLALCHEMY_DATABASE_URL) as db:
            db.add_app_data(key=key, value=value)

        return 'The data is successfully added'
