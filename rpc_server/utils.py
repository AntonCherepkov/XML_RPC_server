import random
import string
import hashlib

def generate_session_id(username):
    """
    Генерирует уникальный идентификатор сессии на основе логина.
    """
    session_id = hashlib.sha256(f"{username}{random.random()}".encode()).hexdigest()
    return session_id

def generate_challenge():
    """
    Генерирует случайный челлендж для аутентификации.
    """
    challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return challenge