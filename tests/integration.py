#!/usr/bin/env python3
"""Portable tests: actual controller/proxy code, no Windows isolation claim."""
import argparse
import hashlib
import itertools
import json
import pathlib
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET

def check(value, message):
    if not value:
        raise AssertionError(message)

def invoke(binary, *args, ok=True):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, encoding='utf-8', timeout=20)
    check((result.returncode == 0) == ok, (args, result.returncode, result.stdout, result.stderr))
    return result

def receive_header(sock):
    answer = b''
    while not answer.endswith(b'\r\n\r\n'):
        part = sock.recv(1)
        if not part:
            break
        answer += part
    return answer

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def proxy_start(binary, port, *extra):
    process = subprocess.Popen([str(binary), 'proxy', '--port', str(port), '--allow', 'localhost', *extra],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    check(process.stdout.readline().startswith('READY'), 'Proxy did not start')
    return process

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            part = self.request.recv(16384)
            if not part:
                break
            self.request.sendall(part)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--workspace', type=pathlib.Path, default=pathlib.Path.cwd())
    args = parser.parse_args()
    source = pathlib.Path(__file__).resolve().parents[1]
    count = 0
    with tempfile.TemporaryDirectory(prefix='winsandboxctl-tests-', dir=args.workspace) as directory:
        base = pathlib.Path(directory)
        package = base / '测试 package & symbols'
        (package / 'bin').mkdir(parents=True)
        (package / 'guest').mkdir()
        binary = package / 'bin' / args.binary.name
        shutil.copy2(args.binary.resolve(), binary)
        shutil.copy2(source / 'guest' / 'guest.ps1', package / 'guest' / 'guest.ps1')
        inputs = base / 'input & 中文'
        inputs.mkdir()
        (inputs / 'nested').mkdir()
        target = inputs / 'nested' / '测试 app.exe'
        target.write_bytes(b'NOT AN EXECUTABLE: host must never execute this.')
        (inputs / 'readonly-canary.txt').write_text('original', encoding='utf-8')
        root = base / 'boxes & 中文'
        expected_args = ['', 'space here', '"quoted"', 'C:\\with space\\', '& calc.exe', '%PATH%', '中文']
        for network, data, identity in itertools.product(['off', 'direct', 'proxy'], ['none', 'read', 'write'], ['admin', 'system']):
            name = f'{network}-{data}-{identity}'
            options = ['prepare', '--root', root, '--box', name, '--input', inputs,
                       '--app', 'nested/测试 app.exe', '--network', network, '--data', data, '--identity', identity]
            if network == 'proxy':
                options += ['--proxy', '172.20.0.1:18080']
            invoke(binary, *options, '--', *expected_args)
            profile = root / name
            run_id = (profile / 'last-run.txt').read_text().strip()
            session = profile / 'Runtime' / run_id
            launch = json.loads((session / 'control' / 'launch.json').read_text(encoding='utf-8'))
            config = ET.parse(session / 'runtime.wsb').getroot()
            check(launch['arguments'] == expected_args, 'JSON arguments corrupted')
            check(launch['identity'] == identity and launch['network'] == network, 'Manifest policy mismatch')
            check(config.findtext('Networking') == ('Disable' if network == 'off' else 'Default'), 'Network XML mismatch')
            check(config.findtext('ProtectedClient') == 'Enable', 'Protected client silently disabled')
            mappings = config.findall('./MappedFolders/MappedFolder')
            check(len(mappings) == (2 if data == 'none' else 3), 'Wrong mapping count')
            check(all(m.findtext('ReadOnly') == 'true' for m in mappings[:2]), 'Input/control not read-only')
            if data != 'none':
                check(mappings[2].findtext('ReadOnly') == ('true' if data == 'read' else 'false'), 'Wrong data mapping mode')
            for tag in ['AudioInput', 'VideoInput', 'ClipboardRedirection', 'PrinterRedirection', 'vGPU']:
                check(config.findtext(tag) == 'Disable', f'{tag} enabled')
            for mapping in mappings:
                check(pathlib.Path(mapping.findtext('HostFolder')).is_dir(), 'Mapping source missing')
            check((session / 'input' / 'nested' / '测试 app.exe').read_bytes() == target.read_bytes(), 'Snapshot differs')
            check('& calc.exe' not in config.findtext('./LogonCommand/Command'), 'Arguments leaked into shell command')
            count += 1
        check((inputs / 'readonly-canary.txt').read_text() == 'original', 'Input changed on host')
        for bad in ['../escape.exe', 'C:\\evil.exe', 'CON.exe', 'x.exe:stream', 'a//x.exe', '\\\\server\\x.exe']:
            invoke(binary, 'prepare', '--root', root, '--input', inputs, '--app', bad, ok=False)
            count += 1
        invoke(binary, 'prepare', '--root', root, '--input', root, '--app', 'x.exe', ok=False)
        invoke(binary, 'prepare', '--root', root, '--input', inputs, '--app', 'nested/测试 app.exe', '--memory', '2047', ok=False)
        count += 2
        link = inputs / 'linked.exe'
        try:
            link.symlink_to(target)
            invoke(binary, 'prepare', '--root', root, '--input', inputs, '--app', 'nested/测试 app.exe', ok=False)
            count += 1
        except (NotImplementedError, OSError):
            print('SKIP symlink setup unavailable on this machine')
        finally:
            if link.is_symlink():
                link.unlink()

        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote_port = server.server_address[1]
        try:
            port = free_port()
            proxy = proxy_start(binary, port, '--ports', str(remote_port), '--allow-private-upstream')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                    client.settimeout(5)
                    client.sendall(f'CONNECT localhost:{remote_port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
                    check(receive_header(client).startswith(b'HTTP/1.1 200 '), 'Allowed CONNECT failed')
                    payload = b'\x00binary test\xff' * 3000
                    client.sendall(payload)
                    got = b''
                    while len(got) < len(payload):
                        got += client.recv(len(payload) - len(got))
                    check(hashlib.sha256(got).digest() == hashlib.sha256(payload).digest(), 'Proxy relay data corrupted')
                    client.shutdown(socket.SHUT_WR)
                    check(client.recv(1) == b'', 'Half-close not propagated')
                count += 1
                cases = [
                    (f'CONNECT localhost.evil:{remote_port} HTTP/1.1\r\n\r\n', 403),
                    ('CONNECT localhost:1 HTTP/1.1\r\n\r\n', 403),
                    ('GET http://localhost/ HTTP/1.1\r\n\r\n', 400),
                    ('CONNECT user@localhost:443 HTTP/1.1\r\n\r\n', 400),
                    ('CONNECT localhost:99999 HTTP/1.1\r\n\r\n', 400),
                    ('CONNECT localhost:443 HTTP/1.1\nX: y\r\n\r\n', 400),
                    ('X' * 8192, 400),
                ]
                for request, expected in cases:
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                        client.sendall(request.encode())
                        reply = receive_header(client)
                        check(reply.startswith(f'HTTP/1.1 {expected} '.encode()), (request[:60], reply))
                        count += 1
            finally:
                proxy.terminate()
                proxy.wait(timeout=5)
            port = free_port()
            proxy = proxy_start(binary, port, '--ports', str(remote_port))
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                    client.sendall(f'CONNECT localhost:{remote_port} HTTP/1.1\r\n\r\n'.encode())
                    check(receive_header(client).startswith(b'HTTP/1.1 502 '), 'Private upstream was not blocked by default')
                    count += 1
            finally:
                proxy.terminate()
                proxy.wait(timeout=5)
        finally:
            server.shutdown()
            server.server_close()
    print(json.dumps({'result': 'PASS', 'integration_cases': count, 'scope': 'portable host/config/proxy; not Windows VM runtime'}, ensure_ascii=False))

if __name__ == '__main__':
    main()
