
SUA에서 진행하고 있는 오픈소스 보안 스터디입니다.

# [오픈소스 이름]

## Introduction
npcap은 소프트웨어 라이브러리와 네트워크 드라이버로 구성된 Windows 운영 체제 용 패킷 캡처 및 네트워크 분석을 위한 도구의 일종이다. 

## Analysis

- iflist.c : 시스템의 디바이스 이름, 네트워크 IP, 패킷 등을 탐지하는 소스코드이다. 
```
  if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1)
  {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
    exit(1);
  }
```
pcap_findalldevs_ex() 함수는 pcap_open()으로 열 수 있는 네트워크 장치 목록을 만드는 함수로, pcap_findalldevs() 함수의 상위 집합으로 볼 수 있다. 두 함수의 차이점으로는 pcap_findalldevs() 힘수는 로컬 시스템에 있는 디바이스만 목록을 만들 수 있으며, pcap_findalldevs_ex()를 사용하면 원격 시스템에 있는 장치도 목록을 만들 수 있다. 
pcap_findalldevs_ex() 함수의 구조체는 다음과 같다.
pcap_findalldevs_ex() 함수의 구조는 pcap_findalldevs_ex(char *, struct pcap_rmtauth *, pcap_if_t **, char *)이다.




'source'는 조회가 수행되어야 하는 위치를 함수에 알려주는 매개변수이며 pcap_open() 과 동일한 구문을 사용합니다 .

다르게에서 pcap_findalldevs () ,합니다 (alldevs-> 이름과 링크 된 목록에있는 다른 사람에 의해 지적) 인터페이스 이름은 이미에 사용 준비가 pcap_open () 호출. 반대의 경우도 마찬가지입니다. pcap_findalldevs() 에서 나오는 출력 은 소스 식별자를 pcap_open() 에 전달하기 전에 새로운 pcap_createsrcstr() 로 형식을 지정해야 합니다 .

매개변수:
출처,: 	새로운 WinPcap 구문에 따라 '소스 지역'을 유지하는 char* 버퍼. 이 소스는 어댑터(로컬 또는 원격)(예: 소스는 로컬 어댑터의 경우 'rpcap://' 또는 원격 호스트의 어댑터의 경우 'rpcap://host:port'일 수 있음) 또는 pcap 파일(예: 소스 'file://c:/myfolder/'일 수 있음).
로컬/원격 어댑터 또는 파일을 원하는지 정의하기 위해 '소스' 앞에 추가해야 하는 문자열은 새로운 소스 사양 구문에 정의되어 있습니다.
인증: 	pcap_rmtauth 구조에 대한 포인터 . 이 포인터는 원격 호스트에 대한 RPCAP 연결을 인증하는 데 필요한 정보를 유지합니다. 이 매개변수는 로컬 호스트에 대한 쿼리의 경우 의미가 없습니다. 이 경우 NULL이 될 수 있습니다.
alldevs,: 	'struct pcap_if_t' 포인터, 이 함수 내에서 적절하게 할당됩니다. 함수가 반환되면 인터페이스 목록의 첫 번째 요소를 가리키도록 설정됩니다. 목록의 각 요소는 'struct pcap_if_t' 유형입니다.
오류,: 	오류 메시지(있는 경우)를 포함할 사용자 할당 버퍼(PCAP_ERRBUF_SIZE 크기)에 대한 포인터.
보고:
모든 것이 정상이면 '0', 일부 오류가 발생하면 '-1'. 장치 목록은 'alldevs' 변수에 반환됩니다. 함수가 올바르게 반환되면 'alldevs'는 NULL일 수 없습니다. 즉, 이 함수는 시스템에 나열할 인터페이스가 없는 경우에도 '-1'을 반환합니다.
오류 메시지는 'errbuf' 변수에 반환됩니다. 다음과 같은 몇 가지 이유로 오류가 발생할 수 있습니다.
libpcap/WinPcap이 로컬/원격 호스트에 설치되지 않았습니다.
사용자에게 장치/파일을 나열할 권한이 없습니다.
네트워크 문제
RPCAP 버전 협상 실패
기타 오류(메모리 부족 및 기타).
경고:
예를 들어 해당 프로세스가 캡처를 위해 열 수 있는 충분한 권한이 없을 수 있기 때문에 pcap_findalldevs() 를 호출하는 프로세스에 의해 pcap_open() 으로 열 수 없는 네트워크 장치가 있을 수 있습니다 . 그렇다면 해당 장치는 목록에 나타나지 않습니다.
인터페이스 목록은 pcap_freealldevs() 를 사용하여 수동으로 할당을 해제해야 합니다 .



-udpdump.c : udp 패킷을 탐지하고 탐지된 패킷의 네트워크 포트 상태를 점검하는 코드이다.
```
/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf_s("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
  ```
  pcap_findalldevs_ex() 함수는 캡처 장치 목록을 가져오거나 해당 목록을 해제할 때 쓰는 함수이다. 위의 코드는 네트워크 어뎁터 목록을 탐지하고 그 결과를 화면에 표시하고 어뎁터를 찾지 못한 경우 오류를 알려주는 소스코드이다. pcap_findalldevs_ex () 함수에는 'errbuf'라는 매개 변수가 있다. 이 매개 변수는 오류가 발생한 경우 오류에 대한 설명을 표시해준다. 
  
  



# [오픈소스 이름]

# [오픈소스 이름]
