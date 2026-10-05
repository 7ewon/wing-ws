from dataclasses import dataclass


# 그릇. 데이터를 프레임이라는 정해진 바이트 형식으로 보내서, 
# server.py에 찍히는 바이트를 해석하는 코드를 만드는 단계
# 아래 클래스는 2바이트를 읽어서 fin, opcode, mask, 길이를 꺼내고
# 길이만큼 payload를 읽고 unmask로 마스킹을 풀음

@dataclass
class Frame:
    fin: bool
    opcode: int
    payload: bytes

def unmask(payload, key):
    result = bytearray()
    for i in range(len(payload)):
        # 받은 바이트를 키바이트 하나랑 xor해서 결과에 붙이기
        # 두번 xor하면 돌아오니까. client가 섞어서 보내주므로
        result.append(payload[i]^key[i%4])

async def read_frame(reader):
    head=await reader.readexactly(2)
    b1=head[0]
    b2=head[1] # 모든 프레임은 2바이트로 시작(최소)

    fin = (b1 >> 7) & 1 #True false
    opcode = b1 & 0x0F #오른쪽 네 비트 == 오피코드
    masked = (b2 >> 7 ) &1 #TF
    length = b2 & 0x7F #오른쪽 7비트==길이

    if masked:
        key = await reader.readexactly(4) # masked면 키 4바이트 읽기

    payload=await reader.readexactly(length) #구한 길이만큼 payload 읽기,
    # 핑퐁은 126안넘어가니까 예외처리 안함

    if masked:
        payload = unmask(payload,key) #바이트가 키>payload순서로 오므로 키를 먼저 읽음

    return Frame(fin == 1, opcode, payload)
    