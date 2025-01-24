import xmlrpc.client
import errors.custom_errors
import secrets
from typing import Tuple, Callable, Any, Optional, Dict
import functools
import hmac
import json
import hashlib
from time import sleep


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

        self.session_id: str = None
        self.__secret_client_keys: Tuple[int, int] = self.secret_key
        self.shared_secret = None
        self.challenge = None


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


    @property
    def secret_key(self) -> Tuple[int, int]:
        return self.__secret_client_keys


    @secret_key.setter
    def secret_key(self, prime_num: int = 5, generator_num: int = 23) -> None:
        """Метод для вычисления пары приватного и публичного ключей клиента"""
        client_private_key = secrets.randbelow(prime_num - 1) + 1
        client_public_key = pow(generator_num, client_private_key, prime_num)
        self.__secret_client_keys = client_private_key, client_public_key


    @server_response_validation
    def generate_client_secret(self, client_public_key, client_private_key, prime_num: int = 5) -> None:
        """Метод для вычисления общего секрета клиента, с использованием публичного ключа сервера"""
        server_public_key = self.proxy.generate_secret(self.session_id, client_public_key)
        self.shared_secret = pow(server_public_key, client_private_key, prime_num)


    @server_response_validation
    def challenge_request(self) -> None:
        self.challenge = self.proxy.get_challange(self.session_id)


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


if __name__ == '__main__':
    try:
        pass
    except xmlrpc.client.Fault as e:
        print(f'Ошибка на сервере: {e}')

