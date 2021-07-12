#Crypto.Hash 모듈에서 SHA-512 구현하는 클래스를 호출
from Crypto.Hash import SHA512

#new로 해시 객체의 새로운 인스턴스 반환
h = SHA512.new()
#update를 활용해 Hello 데이터를 입력
h.update(b'Hello')
#메시지의 512비트 다이제스트를 출력
print(h.hexdigest())