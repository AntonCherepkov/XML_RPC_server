import hashlib
import random
import time


class SessionManager:
    def __init__(self):
        self.sessions = {}


    def generate_session_id(self, username):
        """
        Генерирует уникальный идентификатор сессии на основе логина, проверяет словарь на наличие
        такого же ключа, если не находит, то возвращает его.
        """
        while True:
            session_id = hashlib.sha256(f"{username}{random.random()}".encode()).hexdigest()

            if session_id not in self.sessions:
                return session_id


    def create_session(self, username) -> str:
        """
        Создает новую сессию для пользователя и сохраняет её в списке сессий.
        """
        session_id = self.generate_session_id(username)
        self.sessions[f'{session_id}'] = {
            'username': username,
            'expiry': time.time() + 3600,
            'shared_secret': None,
            'challenge': None
        }

        return session_id


    def delete_session(self, session_id) -> bool:
        """
        Удаляет сессию из списка сессий.
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
