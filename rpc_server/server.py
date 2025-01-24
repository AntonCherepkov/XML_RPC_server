from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from db_manager import DataBaseManager

from rpc_server.xmlrpc_method import XMLRPCMethods
from config_server import ConfigServer


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)


def start_server(host: str = 'localhost', port: int = 8000):
    """Функция для старта XML-RPC сервера"""
    with SimpleXMLRPCServer((host, port), requestHandler=RequestHandler, allow_none=True) as server:
        server.register_introspection_functions()
        xmlrpc_methods = XMLRPCMethods()
        server.register_instance(xmlrpc_methods)

        print(f"Сервер запущен на {host}:{port}...")
        server.serve_forever()


if __name__ == '__main__.py':
    with DataBaseManager(db_url=ConfigServer) as db:
        db.create_tables()

    start_server()
