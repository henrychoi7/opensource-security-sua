SUA에서 진행하고 있는 오픈소스 보안 스터디입니다.

# [Picocrypt]

## Introduction
Picocrypt은 매우 작고("Pico"), 매우 간단하며 안전한 파일 암호화 도구입니다. 이 도구는 최신 ChaCha20-Poly1305와 Argon2 암호화 알고리즘을 사용했습니다. 파일을 선택하고 비밀번호를 입력하면 그 파일을 암호화할 수 있으며 암호화가 완료되면 원본파일은 삭제됩니다.

## Analysis

-[Picocrypt.py](https://github.com/henrychoi7/opensource-security-sua/blob/canon827/canon827/Picocrypt/Picocrypt.py): Picocrypt가 암호화 도구로써 기능하기 위해 주요 기능인 암호화/복호화 기능을 포함한 전반적인 기능을 나타낸 코드이다.

-[file drag](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L103)

inputSelected라는 이름으로  사용자가 파일이나 폴더를 창으로 드래그할 때 발생하는 이벤트에 관여하는 함수를 정의한다. 이 함수는 GUI환경에서 커서의 상태와 창에 있는 버튼의 상태를 나타낸다.

def inputSelected(draggedFile):
	global inputFile,working,headerRsc,allFiles,draggedFolderPaths,files
	resetUI()
	dummy.focus()
	status.config(cursor="")
	status.bind("<Button-1>",lambda e:None)

-[exception](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L111)

예외 처리를 하기 위해 try에 실행할 코드를 넣은 부분이다. tmp 변수의 경우, 위에서 정의한 inputSelected의 매개변수 draggedFile에 관한 항목을 모두 출력한다. 또한, within 변수는 False로, 나머지 변수들은 공백으로 초기화 한다.

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

-[path](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L135)

for문은 python을 GUI환경으로 구성하는 tkinterdnd2의 파일 가져오기 메서드에 의해 반환된 데이터를 구문 분석한다. 파일 및 폴더를 드래그하면 if~else 문에서 해당 경로를 검증하여 그 경로를 출력 ('draggedFile'매개 변수)

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


-[decryption](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L176)

프로그램 사용자가 원하는 게 암호화인지 복호화인지 결정하는 부분이다. if문의 조건인 inputFile의 확장자명인 .pcv인 경우, 해당 파일을 열어서 tmp[0]에 데이터가 있을 경우, if문에 따라 파일을 끝까지 읽고 fin.seek(138)까지 실행한다. tmp[0]에 데이터가 없을 경우, 맨 뒤에서부터 데이터를 보며 else문을 실행한 다음 ad = fin.read(tmp)까지 실행한다. 

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

-[encryption](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L216)

위의 L176부분에서 if문 조건을 충족하지 못했을때 실행되는 else문이며, 파일또는 폴더를 암호화하기 위해 실행시킨 Picocrypt의 UI 구성을 나타내는 코드이다. 암호화하고 싶은 파일 또는 폴더를 잘못 가져왔을 때 초기화하는 Clear 버튼과 비밀번호를 입력하고 그 비밀번호를 한번 더 입력해 확인하는 박스에 대한 UI를 구현하도록 한다.

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

-[start encryption/decryption process](https://github.com/henrychoi7/opensource-security-sua/blob/5a67f7e005847ce45b706427668ad9a57701ba6b/canon827/Picocrypt/Picocrypt.py#L365)

암·복호화 과정을 시작하는 부분이다. start()함수로 정의되어있다. 이 함수 아래로 if~else문을 사용하여 암호화 인지 복호화인지 선택해준다. if문이 암호화, else문이 복호화부분이다. 그 다음, try except문을 활용하여 Picocrypt에 이미 파일이 있는지 확인한다. try문에 파일 크기를 구하는 getsize() 함수를 넣어 force가 1인 아닌 경우 즉, 파일이 존재하는 경우 반환한다.

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





# [Secure-coding-with-python]

## Introduction
Secure-coding-with-python은 말 그대로 Python을 사용한 시큐어 코딩에 대해 다루고 있다. 이 소스에는 애플리케이션 각 개발 단계에 대응하는 브랜치들이 있다. 이 개발 단계에서 일부러 보안상 취약하도록 구성하고 테스트해 최종적으로 코드를 수정하도록 한다.

## Usage

# [Python-Scripts]

## Introduction
개인이 침투테스트와 자동화를 위해 모아놓은 Python Script다. 해시값을 크랙하는 간단한 도구나 키로거 공격, 사전 공격을 가능하게 하는 스크립트, 간이포트 스캐너와 같은 침투 테스트를 위한 다양한 스크립트가 있다. 



# [오픈소스 이름]

## Introduction
예) Bandit은 Python 코드에서 일반적인 보안 취약점을 찾기 위해 설계된 도구다. 이를 위해 Bandit은 각 파일을 처리하고, 파일로부터 AST를 빌드하고, AST 노드에 대해 적절한 플러그인을 실행한다. Bandit이 모든 파일 스캔을 마치면 보고서를 생성하게 된다.

## Usage or Analysis
예1) 코드 트리에서 사용 예시는 아래와 같다.

```
bandit -r ~/your_repos/project
```

`examples` 디렉터리에서 심각도가 높은 취약점에 대해서 보고하고 세 줄의 컨텍스트를 표시하는 예시는 아래와 같다.

```
bandit examples/*.py -n 3 -lll
```

예2) 이 모듈은 아래의 디렉터리로 구성된다.

[파일 트리 이미지]

- [install-vault](https://github.com/henrychoi7/opensource-security-sua): 이 모듈은 Vault를 설치하는 데 사용할 수 있다. 그리고 Packer 템플릿에서 Vault Amazon 머신 이미지 (AMI)를 생성하는 데 사용할 수도 있다.

- [run-vault](https://github.com/henrychoi7/opensource-security-sua): 이 모듈은 Vault를 구성하고 실행하는 데 사용할 수 있다. 서버가 부팅되는 동안 Vault를 시작하기 위해 사용자 데이터 스크립트를 사용하는 기능도 있다.

- [vault-cluster](https://github.com/henrychoi7/opensource-security-sua): Auto Scaling Group을 사용하여 Vault 서버 클러스터를 배포하기 위한 Terraform 코드다.

### install-vault
[주요 파일 분석]

```
function assert_either_or {
  local -r arg1_name="$1"
  local -r arg1_value="$2"
  local -r arg2_name="$3"
  local -r arg2_value="$4"

  if [[ -z "$arg1_value" && -z "$arg2_value" ]]; then
    log_error "Either the value for '$arg1_name' or '$arg2_name' must be passed, both cannot be empty"
    print_usage
    exit 1
  fi
}

# 명령을 여러 번 실행하려고 시도하고 출력을 반환하는 재귀 함수
function retry {
  local -r cmd="$1"
  local -r description="$2"

  for i in $(seq 1 5); do
    log_info "$description"
    
    # 종료 상태가 있는 boolean 연산은 종료 상태 코드를 잃지 않고 오류 상태를 위해 즉시 스크립트를 종료하는 이 스크립트의 시작 부분에 있는 "set -e"를 일시적으로 우회한다.
    output=$(eval "$cmd") && exit_status=0 || exit_status=$?
    log_info "$output"
    if [[ $exit_status -eq 0 ]]; then
      echo "$output"
      return
    fi
    log_warn "$description failed. Will sleep for 10 seconds and try again."
    sleep 10
  done;

  log_error "$description failed after 5 attempts."
  exit $exit_status
}
```