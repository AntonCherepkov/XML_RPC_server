from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from db_manager import DataBaseManager
import socket

from rpc_server.xmlrpc_method import XMLRPCMethods
from config_server import ConfigServer


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)


def check_connection(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            print(f'Подключение к {host}:{port} успешно')
    except ConnectionRefusedError:
        print(f'Подключение к {host}:{port} не удалось')
        exit()
    except socket.timeout:
        print(f'Подключение к {host}:{port} не удалось, таймаут')
        exit()


def start_server(host, port):
    """Функция для старта XML-RPC сервера"""
    with SimpleXMLRPCServer((host, port), requestHandler=RequestHandler, allow_none=True) as server:
        check_connection(host, port)
        server.register_introspection_functions()
        xmlrpc_methods = XMLRPCMethods()
        server.register_instance(xmlrpc_methods)
        server.serve_forever()


if __name__ == '__main__':
    with DataBaseManager(db_url=ConfigServer.SQLALCHEMY_DATABASE_URL) as db:
        db.create_tables()

    start_server(host=ConfigServer.SERVER_HOST, port=ConfigServer.SERVER_PORT)
