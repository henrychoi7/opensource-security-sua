import json

from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'open source security by SUA'

key = get_random_bytes(32)
# 8 바이트 또는 12 바이트
nonce = get_random_bytes(8)

cipher = ChaCha20.new(key=key, nonce=nonce)

# ChaCha20 객체로 plaintext 암호화하기
ciphertext = cipher.encrypt(plaintext)

# nonce와 암호화된 텍스트를 base64로 인코딩하고 UTF로 디코딩
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')

# 결과 정리
result = json.dumps({'nonce':nonce, 'ciphertext':ct})

# {"nonce": "IZScZh28fDo=", "ciphertext": "ZatgU1f30WDHriaN8ts="}
print(result)

# 복호화 시작
try:
    # result에는 위에서 암호화한 JSON 결과 값이 들어감
    b64 = json.loads(result)

    # nonce와 ciphertext에 들어간 값을 다시 base64 디코딩
    nonce = b64decode(b64['nonce'])
    ciphertext = b64decode(b64['ciphertext'])
    
    # ChaCha20 객체 만들기
    cipher = ChaCha20.new(key=key, nonce=nonce)

    # ChaCha20 객체로 ciphertext 복호화하기
    plaintext = cipher.decrypt(ciphertext)

    # open source security by SUA가 출력됨
    print("The message was " + plaintext)
    
except (ValueError, KeyError) as variable:
    print("Incorrect decryption")