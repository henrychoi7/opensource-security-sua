SUA에서 진행하고 있는 오픈소스 보안 스터디입니다.

# [Picocrypt]

## Introduction
Picocrypt은 매우 작고("Pico"), 매우 간단하며 안전한 파일 암호화 도구입니다. 이 도구는 최신 ChaCha20-Poly1305와 Argon2 암호화 알고리즘을 사용했습니다. 파일을 선택하고 비밀번호를 입력하면 그 파일을 암호화할 수 있으며 암호화가 완료되면 원본파일은 삭제됩니다.

## Analysis

-[Picocrypt.py](https://github.com/henrychoi7/opensource-security-sua/blob/canon827/canon827/Picocrypt/Picocrypt.py): Picocrypt가 암호화 도구로써 기능하기 위해 주요 기능인 암호화/복호화 기능을 포함한 전반적인 기능을 나타낸 코드이다.

-[file drag](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L103)

inputSelected라는 이름으로  사용자가 파일이나 폴더를 창으로 드래그할 때 발생하는 이벤트에 관여하는 함수를 정의한다. 이 함수는 GUI환경에서 커서의 상태와 창에 있는 버튼의 상태를 나타낸다.
```
def inputSelected(draggedFile):
	global inputFile,working,headerRsc,allFiles,draggedFolderPaths,files
	resetUI()
	dummy.focus()
	status.config(cursor="")
	status.bind("<Button-1>",lambda e:None)
```

-[exception](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L111)

예외 처리를 하기 위해 try에 실행할 코드를 넣은 부분이다. tmp 변수의 경우, 위에서 정의한 inputSelected의 매개변수 draggedFile에 관한 항목을 모두 출력한다. 또한, within 변수는 False로, 나머지 변수들은 공백으로 초기화 한다.
```
try:
		# Create list of input files
		allFiles = []
		files = []
		draggedFolderPaths = []
		suffix = ""
		tmp = [i for i in draggedFile]
		res = []
		within = False
		tmpName = ""
```
-[path](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L135)

for문은 python을 GUI환경으로 구성하는 tkinterdnd2의 파일 가져오기 메서드에 의해 반환된 데이터를 구문 분석한다. 파일 및 폴더를 드래그하면 if~else 문에서 해당 경로를 검증하여 그 경로를 출력 ('draggedFile'매개 변수)
```
for i in tmp:
			if i=="{":
				within = True
			elif i=="}":
				within = False
				res.append(tmpName)
				tmpName = ""
			else:
				if i==" " and not within:
					if tmpName!="":
						res.append(tmpName)
					tmpName = ""
				else:
					tmpName += i
		if tmpName:
			res.append(tmpName)

		allFiles = []
		files = []
```

-[decryption](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L176)

프로그램 사용자가 원하는 게 암호화인지 복호화인지 결정하는 부분이다. if문의 조건인 inputFile의 확장자명인 .pcv인 경우, 해당 파일을 열어서 tmp[0]에 데이터가 있을 경우, if문에 따라 파일을 끝까지 읽고 fin.seek(138)까지 실행한다. tmp[0]에 데이터가 없을 경우, 맨 뒤에서부터 데이터를 보며 else문을 실행한 다음 ad = fin.read(tmp)까지 실행한다. 
```
if inputFile.endswith(".pcv"):
			suffix = " (will decrypt)"
			fin = open(inputFile,"rb")

			# Read file metadata (a little complex)
			tmp = fin.read(139)
			reedsolo = False
			if tmp[0]==43:
				reedsolo = True
				tmp = tmp[1:]
			else:
				tmp = tmp[:-1]
			tmp = bytes(headerRsc.decode(tmp)[0])
			tmp = tmp.replace(b"+",b"")
			tmp = int(tmp.decode("utf-8"))
			if not reedsolo:
				fin.seek(138)
			ad = fin.read(tmp)
```
-[encryption](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L216)

위의 L176부분에서 if문 조건을 충족하지 못했을때 실행되는 else문이며, 파일또는 폴더를 암호화하기 위해 실행시킨 Picocrypt의 UI 구성을 나타내는 코드이다. 암호화하고 싶은 파일 또는 폴더를 잘못 가져왔을 때 초기화하는 Clear 버튼과 비밀번호를 입력하고 그 비밀번호를 한번 더 입력해 확인하는 박스에 대한 UI를 구현하도록 한다.
```
else:
			# Update the UI
			eraseBtn["state"] = "normal"
			keepBtn["state"] = "disabled"
			rsBtn["state"] = "normal"
			adArea["state"] = "normal"
			adArea.delete("1.0",tkinter.END)
			suffix = " (will encrypt)"
			adLabelString.set(adString)
			cpasswordInput["state"] = "normal"
			cpasswordInput.delete(0,"end")
			cpasswordString.set("Confirm password:")
			cpasswordLabel["state"] = "normal"
			adLabel["state"] = "normal"

		nFiles = len(files)
		nFolders = len(draggedFolderPaths)
```
-[start encryption/decryption process](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L365)

암·복호화 과정을 시작하는 부분이다. start()함수로 정의되어있다. 이 함수 아래로 if~else문을 사용하여 암호화 인지 복호화인지 선택해준다. if문이 암호화, else문이 복호화부분이다. 그 다음, try except문을 활용하여 Picocrypt에 이미 파일이 있는지 확인한다. try문에 파일 크기를 구하는 getsize() 함수를 넣어 force가 1인 아닌 경우 즉, 파일이 존재하는 경우 반환한다.
```
def start():
	global inputFile,outputFile,password,ad,kept
	global working,gMode,headerRsc,allFiles,files
	global dragFolderPath
	dummy.focus()
	reedsolo = False
	chunkSize = 2**20

	# Decide if encrypting or decrypting
	if not inputFile.endswith(".pcv"):
		mode = "encrypt"
		gMode = "encrypt"
		outputFile = inputFile+".pcv"
		reedsolo = rs.get()==1
	else:
		mode = "decrypt"
		gMode = "decrypt"
		# Check if Reed-Solomon was enabled by checking for "+"
		test = open(inputFile,"rb")
		decider = test.read(1).decode("utf-8")
		test.close()
		if decider=="+":
			reedsolo = True
```

-[Generate values for encryption](https://github.com/henrychoi7/opensource-security-sua/blob/2e154a5265da3ac9241a5db65e77132223d3953a/canon827/Picocrypt/Picocrypt.py#L468)

if문을 통해 암호화 모드일 때, 난수를 생성하는 urandom 함수를 사용하여 salt와 nonce를 정의하고, tmp를 활용해 메타데이터의 길이와 메타데이터를 정의한다. 이 부분에서 암호화시 Reed-Solomon부호를 사용하며 salt생성 시 Argon2암호화 기법을 사용하고 nonce 생성 시 ChaCha20암호화 기법을 사용하는 것을 알 수 있다.

```
if mode=="encrypt":
		salt = urandom(16)
		nonce = urandom(24)

		# Reed-Solomon-encode metadata
		ad = bytes(headerRsc.encode(ad))
		# Write the metadata to output
		tmp = str(len(ad)).encode("utf-8")
		# Right-pad with "+"
		while len(tmp)!=10:
			tmp += b"+"
		tmp = bytes(headerRsc.encode(tmp))
		fout.write(tmp) # Length of metadata
		fout.write(ad) # Metadata (associated data)

		# Write zeros as placeholders, come back to write over it later.
		# Note that 128 extra Reed-Solomon bytes are added
		fout.write(b"0"*192) # SHA3-512 of encryption key
		fout.write(b"0"*192) # CRC of file
		fout.write(b"0"*144) # Poly1305 tag
		# Reed-Solomon-encode salt and nonce
		fout.write(bytes(headerRsc.encode(salt))) # Argon2 salt
		fout.write(bytes(headerRsc.encode(nonce))) # ChaCha20 nonce
```

-[Decrypting](https://github.com/henrychoi7/opensource-security-sua/blob/2e154a5265da3ac9241a5db65e77132223d3953a/canon827/Picocrypt/Picocrypt.py#L493)

복호화할 때 파일에서 읽어오는 값 468과 이어지는 else문이다. 지난번에 생성한 메타데이터를 실제 데이터로 바꾸기 위해 read 함수를 이용해 파일을 읽어온다. 파일 내용이외에도 솔트, 난수, 다이제스트를 읽어오는 것을 코드에서 확인할 수 있다.

```
else:
		# Move past metadata into actual data
		tmp = fin.read(138)
		if tmp[0]==43:
			tmp = tmp[1:]+fin.read(1)
		tmp = bytes(headerRsc.decode(tmp)[0])
		tmp = tmp.replace(b"+",b"")
		adlen = int(tmp.decode("utf-8"))
		fin.read(int(adlen))

		# Read the salt, nonce, etc.
		cs = fin.read(192)
		crccs = fin.read(192)
		digest = fin.read(144)
		salt = fin.read(144)
		nonce = fin.read(152)
```
-[Key Derivation](https://github.com/henrychoi7/opensource-security-sua/blob/2e154a5265da3ac9241a5db65e77132223d3953a/canon827/Picocrypt/Picocrypt.py#L549)

키 유도(key derivation)와 관련된 부분이다. 키 유도 함수란, 마스터키나 비밀 정보로부터 해당 시스템이나 네트워크의 암복호화에 필요한 암호 키들을 유도하는 함수를 말한다. 위 코드 부분에서는 arog2에 대한 키를 구성하는 패스워드, 솔트, 해시 길이 등을 정의하고 있다. 또한 유도된 키의 해시값을 계산하는 부분도 구현되어 있다.
```
# Show notice about key derivation
	statusString.set(derivingNotice)

	# Derive argon2id key
	key = hash_secret_raw(
		password,
		salt,
		time_cost=8, # 8 iterations
		memory_cost=2**20, # 2^20 Kibibytes (1GiB)
		parallelism=8, # 8 parallel threads
		hash_len=32,
		type=Type.ID
	)

	# Key deriving done, set progress bar determinate
	progress.stop()
	progress.config(mode="determinate")
	progress["value"] = 0

	# Compute hash of derived key
	check = sha3_512.new()
	check.update(key)
	check = check.digest()
```

-[EOF](https://github.com/henrychoi7/opensource-security-sua/blob/2e154a5265da3ac9241a5db65e77132223d3953a/canon827/Picocrypt/Picocrypt.py#L609)
EOF인 경우를 나타내는 코드로써 EOF란, 파일의 끝(end of file)을 의미한다. if문에서는 암호화과정과 관련된 MAC tag를 삽입, 오프셋을 계산하며 키, CRC의 해시값을 적는다. else문에서는 CRC를 검증하는 코드가 구현되어 있다.

```
# If EOF
		if not piece:
			if mode=="encrypt":
				# Get the cipher MAC tag (Poly1305)
				digest = cipher.digest()
				fout.flush()
				fout.close()
				fout = open(outputFile,"r+b")
				# Compute the offset and seek to it (unshift "+")
				rsOffset = 1 if reedsolo else 0
				fout.seek(138+len(ad)+rsOffset)
				# Write hash of key, CRC, and Poly1305 MAC tag
				fout.write(bytes(headerRsc.encode(check)))
				fout.write(bytes(headerRsc.encode(crc.digest())))
				fout.write(bytes(headerRsc.encode(digest)))
			else:
				# If decrypting, verify CRC
				crcdg = crc.digest()
				if not compare_digest(crccs,crcdg):
					# File is corrupted
					statusString.set(corruptedNotice)
					progress["value"] = 100
					fin.close()
					fout.close()
```

-[CHECKSUM](https://github.com/henrychoi7/opensource-security-sua/blob/2e154a5265da3ac9241a5db65e77132223d3953a/canon827/Picocrypt/Picocrypt.py#L666)
암호화 부분은 if문으로 처리하며 리스트 형식으로 분할한 부분을 python 모듈을 이용해 암호화 한다. 이때, CRC(=체크섬)을 업데이트하고 사용자가 Reed-Solomon 부호를 사용할 경우는 if문으로 처리한다. 체크섬이란, 중복 검사의 한 형태로 데이터의 무결성을 보호해준다.
또한, 복호화 부분은 아래 else문으로 처리했는데 try~except문을 활용해 파일이 출동할 경우나 파일이 검사되지 않은 경우를 처리하고 있다.

-[Calculate speed](https://github.com/canon827/Picocrypt/blob/7325b65e03204badb9cee320fc899ff1f890594e/src/Picocrypt.py#L719)
속도를 계산하는 코드로써 예상 완료 시간을 나타낸다. 이를 위해 time 모듈을 이용했으며 if~else문을 활용해 초,분단위로 시간을 측정하는 부분을 구현한다.

```
# Calculate speed, ETA, etc.
		elapsed = (datetime.now()-previousTime).total_seconds() or 0.0001
		sinceStart = (datetime.now()-startTime).total_seconds() or 0.0001
		previousTime = datetime.now()

		percent = done*100/total
		progress["value"] = percent

		speed = (done/sinceStart)/10**6 or 0.0001
		eta = round((total-done)/(speed*10**6))
```

-[Secure delete](https://github.com/canon827/Picocrypt/blob/7325b65e03204badb9cee320fc899ff1f890594e/src/Picocrypt.py#L763)
Picocrypt를 실행시켰을때 'Securely erase and delete original file'체크박스와 연관된 부분이다. 이 부분의 코드는 보안 삭제(Secure Delete, Wiping)로써, 중요한 파일을 복구할 수 없도록 하기 위해서 사용한다. secureWipe함수를 정의한 L853에서도 sdelete64.exe를 확인할 수 있다.

```
if wipe:
		if draggedFolderPaths:
			for i in draggedFolderPaths:
				secureWipe(i)
		if files:
			for i in range(len(files)):
				statusString.set(erasingNotice+f" ({i}/{len(files)}")
				progress["value"] = i/len(files)
				secureWipe(files[i])
		secureWipe(inputFile)
```

-[MODIFIY](https://github.com/canon827/Picocrypt/blob/7325b65e03204badb9cee320fc899ff1f890594e/src/Picocrypt.py#L780)
파일이 만약 변조되었거나 변경된 경우 적절한 메시지를 띄우도록 하는 코드 부분이다. False로 규정된 변수 kept가 if문에서 not 조건일 때 성공적으로 결과물이 나왔다는 메시지를 띄운다. 그리고 else문에서 변경되었을 때, 변조되었을 때 그리고 그 나머지 경우에 대한 조건을 지정한다.
```
if not kept:
		statusString.set(f"Completed. (Click here to show output)")

		# Show Reed-Solomon stats if it fixed corrupted bytes
		if mode=="decrypt" and reedsolo and reedsoloFixedCount:
			statusString.set(
				f"Completed with {reedsoloFixedCount}"+
				f" bytes fixed. (Output: {output})"
			)
	else:
		if kept=="modified":
			statusString.set(kModifiedNotice)
		elif kept=="corrupted":
			statusString.set(kCorruptedNotice)
		else:
			statusString.set(kVeryCorruptedNotice)
```

-[Decorator](https://github.com/canon827/Picocrypt/blob/7325b65e03204badb9cee320fc899ff1f890594e/src/Picocrypt.py#L827)
에러를 처리하는 start()함수를 try~except문으로 코드를 작성한다. 여기서 함수 wrapper()은 호출할 함수를 감싸는 함수다. 그리고 그 아래 try~except문으로 코드를 작성한다.  아래 848번째 줄의 startWorker()함수는 이와 연관된 데코레이터 함수이다. 데코레이터란, 함수를 수정하지 않은 상태에서 추가 기능을 구현할 때 사용한다.
```
def wrapper():
	global working,gMode
	# Try start() and handle errors
	try:
		start()
	except:
		# Reset UI accordingly

		if gMode=="decrypt":
			resetDecryptionUI()
		else:
			resetEncryptionUI()

		statusString.set(unknownErrorNotice)
		dummy.focus()
```
-[disabled](https://github.com/canon827/Picocrypt/blob/7325b65e03204badb9cee320fc899ff1f890594e/src/Picocrypt.py#L877)
암호화/복호화 과정 중에는 다른 입력이 불가능하도록 disableAllInputs() 함수로 정의한다. picocrypt UI에서 확인할 수 있는 Password, Comfirm password 등의 항목들을 disabled로 처리한다.
```
# Disable all inputs while encrypting/decrypting
def disableAllInputs():
	passwordInput["state"] = "disabled"
	cpasswordInput["state"] = "disabled"
	adArea["state"] = "disabled"
	startBtn["state"] = "disabled"
	eraseBtn["state"] = "disabled"
	keepBtn["state"] = "disabled"
	rsBtn["state"] = "disabled"
```

-[Reset](https://github.com/canon827/Picocrypt/blob/7325b65e03204badb9cee320fc899ff1f890594e/src/Picocrypt.py#L887)
picocrypt에서 데이터를 입력받을 수 있는 각각의 항목들의 상태를 "normal"로 정의하여 리셋하는 코드 부분이다. 이 부분의 코드부터 암호화과정 후 리셋하는 함수, 복호화과정 후 리셋하는 함수, 그리고 초기 상태로 리셋하는 함수가 정의되어 있다. 
```
# Reset UI to encryption state
def resetEncryptionUI():
	global working
	passwordInput["state"] = "normal"
	cpasswordInput["state"] = "normal"
	adArea["state"] = "normal"
	startBtn["state"] = "normal"
	eraseBtn["state"] = "normal"
	rsBtn["state"] = "normal"
	working = False
	progress.stop()
	progress.config(mode="determinate")
	progress["value"] = 100
```

이 스크립트에서 쓰인 모듈이 가진 기능을 좀 더 명확하게 알아보기 위해 하나의 모듈만 쓰인 간단한 예제를 참조해서 코드를 작성했다. 그리고 해당 코드를 디버깅했을 때 어떤 결과가 나타나는 지 알아보았다.

-[crypto.hash module](https://github.com/henrychoi7/opensource-security-sua/blob/ca63e46ed518645c3f5bb1370c4c590f68c50ab8/canon827/Picocrypt/Picocrypt.py#L21)

Crypto.Hash 모듈의 동작을 알아보기 위해 참고했던 코드는 다음과 같다. 
```
from Crypto.Hash import SHA512

h = SHA512.new()
h.update(b'Hello')
print(h.hexdigest())
```
Crypto.Hash 모듈에서 SHA-512 구현하는 클래스를 호출합니다. 그리고 new로 해시 객체의 새로운 인스턴스를 반환합니다. update를 활용해 Hello 데이터를 입력하고 메시지의 512비트 다이제스트를 출력합니다. 위 코드를 실행시켰을 때 결과는 다음과 같습니다. 데이터 Hello을 입력했을때 출력되는 다이제스트를 확인할 수 있습니다. 

>C:\Users\YGH\sua-osp\test>python test.py                   
>3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315

-[Crypto Cipher module](https://github.com/henrychoi7/opensource-security-sua/blob/ca63e46ed518645c3f5bb1370c4c590f68c50ab8/canon827/Picocrypt/Picocrypt.py#L20)

Crypto Cipher모듈은 대칭 및 비대칭 키 암호화 알고리즘으로 키 또는 키 쌍에 의존하는 방식으로 일반 텍스트를 변환하여 암호문을 생성한다. 이와 관련한 예제는 다음과 같다 

```
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
```
Crypto.Cipher모듈에서 ChaCha20 방식으로 데이터를 암호화 하고자할 때 예시는 위와 같다. 위 코드를 보면 암호화할 때 사용되는 key는 32바이트 크기이고 ChaCha20의 경우 nonce는 8바이트 또는 12바이트 크기인 것을 알 수 있다. 또한, ChaCha20객체로 plaintext를 암호화하고 nonce와 암호화된 텍스트를 base64로 인코딩하고 UTF로 디코딩한다. 위 예제의 result 값은 다음과 같다.

>C:\Users\YGH\sua-osp\test>python test2.py                      
>{"nonce": "Ag+kbEEryYY=", "ciphertext": "mr2tAraSIGXoyYvCEXjX5yxAhGFPthPPOcFu"}

또한, Crypto.Cipher모듈에서 ChaCha20 방식으로 복호화하기 위해서는 암호화 과정을 바꿔서 진행하면 되는데 이를 위해 암호화한 JSON 결과 값을 base64형식으로 변환한다. 그리고 난수와 암호문에 들어간 값을 다시 base64로 디코딩하고 ChaCha20 객체를 생성해서 암호문을 복호화하면 된다.

```
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
```

이외에도 자주 쓰이는 암호화 알고리즘 몇 가지를 정리하면 다음과 같다. 

-AES 암호화 알고리즘이란 고급 암호화 표준이라고 불리며, DES 암호화 알고리즘을 대체한 암호화와 복호화 과정에서 동일한 키를 사용하는 대칭 키 암호화 알고리즘이다. 이 알고리즘은 가변 길이의 블록과 가변 길이의 키 사용이 가능한 것이 특징이다.(128bit, 192bit, 256bit) 또한, 속도와 코드 효율성 면에서 효율적이다. 




