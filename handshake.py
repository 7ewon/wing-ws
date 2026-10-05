import base64
import binascii
import hashlib

# 국룰(정해져있음. 애먼 프록시나 http같은 애들 말고 웹소켓인지 확인하는 용도)
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 에러처리
class HandshakeError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status

# 파서. 클라이언트한테 헤더와 내용을 딕셔너리로 받음. 
def parser(raw):
    # 안 꺠지는 형태
    text = raw.decode("latin-1")
    rows = list(text.split("\r\n"))

    # method path version 세 개가 아니면 뭔가 잘못된거
    parts = rows[0].split(" ")
    if len(parts) != 3:
        raise HandshakeError(400, "bad request line")
    method, path, version = parts

    headers={}
    for row in rows[1:]:
        if row=="":
            continue
        if ":" not in row:
            raise HandshakeError(400, "bad header line")
        name, value=row.split(":", 1)
        headers[name.strip().lower()]=value.strip()
    return method, path, version, headers

# 문법에 맞는지 검증
# 문서에 나온 올바른 요청 형태가 맞는지 validate하는 부분

def validate(method, version, headers):
    if method != "GET":
        raise HandshakeError(400, "method must be GET")
    if version != "HTTP/1.1":
        raise HandshakeError(400, "must be HTTP/1.1")
    if "host" not in headers:
        raise HandshakeError(400, "missing Host")
    if headers.get("upgrade","").lower() != "websocket":
        raise HandshakeError(400, "Upgrade must be websocket")
    if "upgrade" not in headers.get("connection", "").lower():
        raise HandshakeError(400, "Connection must include Upgrade")
    if headers.get("sec-websocket-version") != "13":
        # 나 13만 지원한다(4.2.2.)
        raise HandshakeError(426, "version must be 13")
    key = headers.get("sec-websocket-key")
    if key is None:
        raise HandshakeError(400, "missing Key")
    try:
        #RFC규칙대로 만들어졌는지 검사. 길이 재는 데만 쓰고 계산엔 안씀
        decoded = base64.b64decode(key, validate=True)
    except binascii.Error:
        raise HandshakeError(400, "Key is not base64")
    if len(decoded) != 16:
        raise HandshakeError(400, "Key must be 16 bytes")
    return key

def compute_accept(key):
    accept=key+GUID
    # 헤더를 받은대로 돌려주면 애먼사람이 주워먹으므로 웹소켓만 알아볼 수 있게 변조
    digest = hashlib.sha1(accept.encode()).digest()
    # http헤더에 안전하게 넣을 수 있는 형태로 변환
    return base64.b64encode(digest).decode()

# 수락

def build_response(accept):
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    return response.encode()

# 거절

def build_error(status):
    if status == 426:
        response = (
            "HTTP/1.1 426 Upgrade Required\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
    else:
        response = (
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
    return response.encode()

#테스트

if __name__ == "__main__":
    raw = (
        b"GET /chat HTTP/1.1\r\n"
        b"Host: localhost:8765\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
    )

    method, path, version, headers = parser(raw)
    print(method, path, version)
    print(headers)

    key = validate(method, version, headers)
    print("key:", key)

    accept = compute_accept(key)
    print("accept:", accept)

    print(build_response(accept))