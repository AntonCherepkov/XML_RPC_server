class AuthorizationError(Exception):
    def __init__(self, message: str = 'Ошибка авторизации'):
        super().__init__(message)

class RegistrationError(Exception):
    def __init__(self, message: str = 'Ошибка регистрации'):
        super().__init__(message)

class SessionNotActivError(Exception):
    def __init__(self, message: str = 'Сессия не активна'):
        super().__init__(message)

class SessionLifeTimeHasExpiredError(Exception):
    def __init__(self, message: str = 'Время жизни сессии закончено'):
        super().__init__(message)

class ClientSignatureError(Exception):
    def __init__(self, message: str = 'Подпись клиента не валидна'):
        super().__init__(message)

class SecretOrChelengeIsNotSetError(Exception):
    def __init__(self, message: str = 'Секрет или челенж не установлен'):
        super().__init__(message)

class KeyInformationNotFoundError(Exception):
    def __init__(self, message: str = 'Не найдена информация по ключу'):
        super().__init__(message)
