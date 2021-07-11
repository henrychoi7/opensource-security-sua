import json

from base64 import b64encode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'open source security by SUA'

# ChaCha20.new()에 들어갈 랜덤 바이트 만들기 (32바이트 짜리)
key = get_random_bytes(32)

# ChaCha20 객체 만들기 (nonce는 선안하지 않아서 자동으로 8바이트 짜리 생성됨)
cipher = ChaCha20.new(key=key)

# ChaCha20 객체로 plaintext 암호화하기
ciphertext = cipher.encrypt(plaintext)

# nonce와 암호화된 텍스트를 base64로 인코딩하고 UTF로 디코딩
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')

# 결과 정리
result = json.dumps({'nonce':nonce, 'ciphertext':ct})

# {"nonce": "IZScZh28fDo=", "ciphertext": "ZatgU1f30WDHriaN8ts="}
print(result)