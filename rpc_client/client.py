import xmlrpc.client
import errors.custom_errors
import secrets
from typing import Tuple, Callable, Any, Optional, Dict
import functools
import hmac
import json
import hashlib
from time import sleep

from rpc_client.config_client import ConfigClient


def server_response_validation(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapped(*args, **kwargs) -> Any:
        dct_messages = {
            'Session invalid or expired': errors.custom_errors.SessionNotActivError,
            'Session expired': errors.custom_errors.SessionLifeTimeHasExpiredError,
            'Invalid HMAC signature': errors.custom_errors.ClientSignatureError,
            'Challenge or secret not set': errors.custom_errors.SecretOrChelengeIsNotSetError,
            'Access denied': errors.custom_errors.AuthorizationError,
            'No data found': errors.custom_errors.KeyInformationNotFoundError,
            'Error registering user': errors.custom_errors.RegistrationError
        }
        result = func(*args, **kwargs)
        if result in dct_messages:
            raise dct_messages[result]()

        return result
    return wrapped


class ClientXMLRPC:
    """Класс, определяющий сущность и функционал клиента"""
    def __init__(self, url_server: str, user_name: str, password: str):
        self.user_name: str = user_name
        self.password: str = password
        self.proxy: xmlrpc.client.ServerProxy = xmlrpc.client.ServerProxy(url_server, allow_none=True)

        if not self._test_connection():
            raise ConnectionError(f"Не удалось подключиться к серверу: {url_server}")
        else:
            print(f"Подключение к серверу {url_server} успешно.")

        self.session_id: str = None
        self.shared_secret = None
        self.challenge = None

        self.__secret_client_keys = self.generate_keys(5, 23)


    def _test_connection(self) -> bool:
        """Метод для проверки соединения с сервером"""
        try:
            response = self.proxy.ping()
            return response == "pong"
        except xmlrpc.client.Fault as fault:
            print(f"Сервер вернул ошибку: {fault}")
        except xmlrpc.client.ProtocolError as error:
            print(f"Ошибка протокола: {error}")
        except ConnectionRefusedError:
            print("Соединение отклонено сервером.")
        except Exception as e:
            print(f"Неизвестная ошибка при подключении: {e}")
        return False


    @property
    def secret_key(self) -> Dict[str, int]:
        return self.__secret_client_keys


    @server_response_validation
    def authorization_request(self) -> None:
        """Метод клиента для авторизации пользователя на сервере, и получения ID сервера"""
        self.session_id = self.proxy.login(self.user_name, self.password)
        return self.session_id


    @server_response_validation
    def user_registration(self) -> None:
        """Метод для регистрации клиента в БД сервера"""
        user_reg = self.proxy.register_user(self.user_name, self.password)
        return user_reg


    def generate_keys(self, prime_num: int = 5, generator_num: int = 23) -> Dict[str, int]:
        """Метод для вычисления пары приватного и публичного ключей клиента"""
        print("Генерация ключей для клиента...")
        client_private_key = secrets.randbelow(prime_num - 1) + 1
        client_public_key = pow(generator_num, client_private_key, prime_num)
        result = {'client_public_key': client_public_key, 'client_private_key': client_private_key}
        return result


    @server_response_validation
    def generate_client_secret(self, client_public_key, client_private_key, prime_num: int = 5) -> None:
        """Метод для вычисления общего секрета клиента, с использованием публичного ключа сервера"""
        print(f"Передача публичного ключа серверу {client_public_key}... Тип ключа: {type(client_public_key)}")
        server_public_key = self.proxy.generate_secret(self.session_id, client_public_key)
        print(f"Публичный ключ сервера: {server_public_key}")
        self.shared_secret = pow(server_public_key, client_private_key, prime_num)


    @server_response_validation
    def challenge_request(self) -> None:
        self.challenge = self.proxy.get_challenge(self.session_id)


    def signature_generation(self, message: Dict[Any, Any]) -> hmac:
        """Метод для генерации HMAC-подписи сообщения клиента"""
        if not self.shared_secret:
            raise ValueError("Общий секрет еще не сгенерирован. Вызовите generate_client_secret.")

        shared_secret_bytes = str(self.shared_secret).encode()
        message_bytes = json.dumps(message, separators=(',', ':')).encode()
        signature = hmac.new(shared_secret_bytes, message_bytes, hashlib.sha256).hexdigest()

        return signature

    @server_response_validation
    def add_data(self, key: str, value: str) -> str:
        """Метод для добавления информации в БД на сервере"""
        if not self.challenge:
            raise ValueError("Challenge не установлен. Вызовите challenge_request.")
        if not self.shared_secret:
            raise ValueError("Общий секрет не установлен. Вызовите generate_client_secret.")

        message = {
            "key": key,
            "value": value,
            "challenge": self.challenge
        }
        signature = self.signature_generation(message)
        response = self.proxy.add_data(self.session_id, key, value, signature)
        print(response)
        return response


    @server_response_validation
    def get_data(self, key: str) -> str:
        """Метод клиента для получения данных из БД на сервере"""
        if not self.challenge:
            raise ValueError("Challenge не установлен. Вызовите challenge_request.")
        if not self.shared_secret:
            raise ValueError("Общий секрет не установлен. Вызовите generate_client_secret.")

        message = {
            "key": key,
            "challenge": self.challenge
        }
        signature = self.signature_generation(message)
        response = self.proxy.get_data(self.session_id, key, signature)
        print(response)
        return response


def run_client_test(url_server: Optional[str] = None) -> None:

    users = [
        {"username": "user1", "password": "password1"},
        {"username": "user2", "password": "password2"},
        {"username": "user3", "password": "password3"}
    ]

    clients = []

    for user in users:
        sleep(1)
        client = ClientXMLRPC(url_server, user["username"], user["password"])
        try:
            print(f"Регистрируем пользователя {user['username']}...")
            client.user_registration()
            print(f"Пользователь {user['username']} зарегистрирован.")
        except Exception as e:
            print(f"Ошибка при регистрации {user['username']}: {e}")
        clients.append(client)

    for client in clients:
        sleep(1)
        try:
            print(f"Авторизация пользователя {client.user_name}...")
            client.authorization_request()
            print(f"Пользователь {client.user_name} успешно авторизован. Session ID: {client.session_id}")

            print(f"Генерация общего секрета для {client.user_name}...")
            client.generate_client_secret(**client.secret_key)
            print(f"Общий секрет для {client.user_name} успешно сгенерирован.")

            print(f"Получение challenge для {client.user_name}...")
            client.challenge_request()
            print(f"Challenge для {client.user_name}: {client.challenge}")

        except Exception as e:
            print(f"Ошибка для {client.user_name}: {e}")

    for i, client in enumerate(clients):
        sleep(1)
        try:
            key = f"key_{i + 1}"
            value = f"value_{i + 1}"
            print(f"Добавляем данные для {client.user_name}: {key} -> {value}...")
            client.add_data(key, value)
            print(f"Данные для {client.user_name} добавлены.")
        except Exception as e:
            print(f"Ошибка при добавлении данных для {client.user_name}: {e}")

    for i, client in enumerate(clients):
        sleep(1)
        try:
            key = f"key_{i + 1}"
            print(f"Извлекаем данные для {client.user_name} по ключу {key}...")
            data = client.get_data(key)
            print(f"Полученные данные для {client.user_name}: {data}")
        except Exception as e:
            print(f"Ошибка при получении данных для {client.user_name}: {e}")


if __name__ == "__main__":
    sleep(5)
    print("Запуск тестового клиента... Подключение к серверу XML-RPC по адресу:", ConfigClient.SERVER_URL)
    run_client_test(url_server=ConfigClient.SERVER_URL)
