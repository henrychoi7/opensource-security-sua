
SUA에서 진행하고 있는 오픈소스 보안 스터디입니다.

# [오픈소스 이름]

## Introduction
npcap은 소프트웨어 라이브러리와 네트워크 드라이버로 구성된 Windows 운영 체제 용 패킷 캡처 및 네트워크 분석을 위한 도구의 일종이다. npcap은 다음과 같은 기능을 제공한다.

추가 보안 : 관리자만 패킷을 스니핑할 수 있도록 Npcap을 제한할 수 있다.

WinPcap 호환성 : 호환 모드가 선택되지 않은 경우 Npcap은 동일한 시스템에서 두 드라이버가 공존할 수 있도록 다른 서비스 이름으로 다른 위치에 설치됩니다.

루프백 패킷 캡처 : Npcap은 WFP(Windows 필터링 플랫폼)를 사용하여 루프백 패킷(동일한 시스템의 서비스 간 전송)을 스니핑할 수 있습니다. 설치 후 Npcap은 Npcap Loopback Adapter라는 어댑터를 생성합니다.

루프백 패킷 주입 : Npcap은 WSK(Winsock Kernel) 기술을 사용하여 루프백 패킷을 보낼 수도 있습니다.

원시 802.11 패킷 캡처 : Npcap은 일반 무선 어댑터에서 가짜 이더넷 패킷 대신 802.11 패킷을 볼 수 있습니다.

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
pcap_findalldevs_ex()의 구조는 pcap_findalldevs_ex(char *, struct pcap_rmtauth *, pcap_if_t **, char *)이다.
원격. 로컬 시스템에 있는 디바이스 목록에 이상이 없다면, 즉, 모든 것이 정상이면 '0'을 일부 오류가 발생하면 '-1'이 반환되며, 장치 목록은 'alldevs' 이라는 매개변수에 반환된다. 이 함수는 시스템에 나열할 인터페이스가 없는 경우에도 '-1'을 반환한다. 오류 메시지는 'errbuf' 변수에 반환된다.
```
for(d=alldevs;d;d=d->next)
  {
    ifprint(d);
  }

  pcap_freealldevs(alldevs);

  return 1;
}
```
pcap_freealldevs() 함수는 장치 목록을 해제하는 함수이며, allldevs가 가리키는 장치 목록을 해제한다. 
```
void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];
  /* Name */
  printf("%s\n",d->name);
  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);
  /* Loopback Address*/
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");
  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);
   switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;
     case AF_INET6:
        printf("\tAddress Family Name: AF_INET6\n");
        if (a->addr)
          printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
       break;
      default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  printf("\n");
}
```
 위의 주어진 인터페이스에서 사용 가능한 모든 정보를 출력하는 프로그램이다. pcap_if_t 구조체 내용의 전체 내용을 인쇄하는 ifprint() 함수를 제공한다. pcap_findalldevs_ex() 함수에서 반환한 모든 항목에 대해 프로그램에서 호출한다. pcap_if_t 구조체의 데이터 필드 정의는 다음과 같다.
 
>pcap_if_t*name - pcap_open_live ()에 전달할 장치의 이름을 제공하는 문자열에 대한 포인터

>pcap_if_t*description - NULL이 아니면 사용자가 사용하고 있는 장치 설명을 제공하는 문자열에 대한 포인터

>pcap_if_t*addresses - 장치에 대한 네트워크 주소 목록의 첫 번째 요소에 대한 포인터 또는 장치에 주소가 없는 경우 NULL값을 나타낸다.

>pcap_if_t*flag - 플래그 옵션은 다음과 같다.

>PCAP_IF_LOOPBACK - 장치가 루프백 인터페이스인 경우 설정한다.

>PCAP_IF_WIRELESS - 장치가 무선 인터페이스인 경우 설정한다. 

>PCAP_IF_CONNECTION_STATUS - 어댑터가 연결되었는지 여부를 나타내는 비트마스크, 무선 인터페이스의 경우 "연결됨"은 "네트워크와 연결됨"을 의미한다.

pcap_if 구조는 다음과 같다.

>pcap_if_t(struct pcap_if_t* next) struct pcap_if_t*next는 NULL이 아닌 경우, 디바이스 목록의 다음 요소에 대한 포인터를 가리킨다.

>pcap_addr_t() 함수 - pcap_findalldevs() 함수에서 사용하는 인터페이스 주소를 표현하는 함수이다. pcap_addr_t() 함수의 데이터 필드 구조는 다음과 같다.

>struct pcap_addr_t*next 함수는 NULL이 아닌 경우, 디바이스 목록의 다음 요소에 대한 포인터를 가리킨다.

>struct struct sockaddr* addr - - 주소를 나타내는 구조체 sockaddr에 대한 포인터를 가리킨다.

>struct struct sockaddr* netmask - NULL이 아니면 addr이 가리키는 주소에 해당하는 netmask를 포함하는 sockaddr 구조체에 대한 포인터를 가리킨다.

>struct struct sockaddr* broadcast - NULL이 아니면 addr이 가리키는 주소에 해당하는 broadcast를 포함하는 sockaddr 구조체에 대한 포인터를 가리킨다. 인터페이스가 브로드캐스트를 지원하지 않는 경우에는 NULL이 될 수 있다.

>struct struct sockaddr* dstaddr - NULL이 아니면 addr이 가리키는 주소에 해당하는 목적지 주소를 포함하는 struct sockaddr에 대한 포인터. 인터페이스가 지점 간 인터페이스가 아닌 경우 null일 수 있다.

위의 내용을 간략하게 정리하자면 해당 인터페이스의 주소 목록, 넷마스크 목록, 브로드캐스트 주소 목록, 대상 주소 목록, pcap_findalldevs_ex() 함수로 지정된 로컬 폴더에 있는 원격 어댑터 및 pcap 파일 목록을 반환할 수 있다.














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
