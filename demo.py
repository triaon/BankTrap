"""Repeatable demo against a running local server; no third-party dependencies."""
import argparse
import getpass
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=8765)
args = parser.parse_args()
token = getpass.getpass('Токен оператора из окна сервера: ')

def call(title, path, data):
    request = Request(f'http://127.0.0.1:{args.port}{path}', data=json.dumps(data).encode(),
                      headers={'Content-Type':'application/json', 'X-Operator-Token':token, 'X-Demo-Session':'script-demo'})
    try:
        response = urlopen(request)
    except HTTPError as error:
        response = error
    with response:
        result = json.load(response)
        print(f'{title}: HTTP {response.status}\n{json.dumps(result, ensure_ascii=False)}\n')
        if result.get('error'):
            raise SystemExit('Исправьте ошибку и повторите демо.')

attack = {'username': "admin' OR '1'='1", 'password':'synthetic'}
call('1. Сброс', '/control/reset', {})
call('2. До правила', '/gateway/login', attack)
call('3. Атака на приманку', '/api/auth/login', attack)
call('4. Кандидат', '/control/generate', {})
call('5. Replay', '/control/validate', {})
call('6. Включение в тестовом шлюзе', '/control/activate', {})
call('7. Повтор атаки', '/gateway/login', attack)
call('8. Обычный запрос', '/gateway/login', {'username':"o'reilly"})
call('9. Откат', '/control/disable', {})
