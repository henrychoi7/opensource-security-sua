
SUA에서 진행하고 있는 오픈소스 보안 스터디입니다.

# [npcap]    

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

- readme.c - 덤프 파일에서 패킷을 읽어들이는 소스코드이다. 덤프를 한 파일이 존재한다면, 그 내용을 읽을 수 있다. 이 소스코드는 Npcap/libpcap 덤프 파일을 열고 파일에 포함된 모든 패킷을 표시한다. 
파일은 pcap_open_offline()함수를 이용하여 연 다음 일반적인 pcap_loop() 함수를 사용하여 패킷을 시퀀싱한다.

```
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
```

pcap 라이브러리에서 덤프파일을 호출해주는 함수의 프로토타입이다.  

```
if ( pcap_createsrcstr(	source,			// variable that will keep the source string
							PCAP_SRC_FILE,	// we want to open a file
							NULL,			// remote host
							NULL,			// port on the remote host
							argv[1],		// name of the file we want to open
							errbuf			// error buffer
							) != 0)
	{
		fprintf(stderr,"\nError creating a source string\n");
		return -1;
	}
  
  ```
  
  pcap_createsrcstr() 함수 - Npcap에 소스 유형을 알려주는데 사용되는 함수로 시작하는 소스 문자열을 생성하는 데 필요하다. 
 호스트 이름, 포트 등의 일련의 문자열을 수락하면 새 형식(예: 'rpcap://1.2.3.4/eth0')에 따라 전체 소스 문자열을 반환한다. 
 해당 함수의 파라미터는 다음과 같다.
 
>source : 함수가 반환하는 소스 문자열을 포함할 사용자 할당 버퍼, 새로운 소스 사양 구문에 따라 식별자로 시작한다. 할당된 버퍼가 PCAP_BUF_SIZE 바이트 이상이라고 가정한다.
 
>type : 	만들고자 하는 소스의 유형을 알려준다. 

>host : 연결하려는 호스트를 유지하는 사용자 할당 버퍼. 로컬 호스트에서 인터페이스를 열려면 NULL일 수 있다.

>port : RPCAP 프로토콜에 사용하려는 네트워크 포트를 유지하는 사용자 할당 버퍼. 로컬 호스트에서 인터페이스를 열려면 NULL일 수 있다.

>name : 사용하려는 인터페이스 이름을 유지하는 사용자 할당 버퍼(예: "eth3"). 

>error : 오류 메시지(있는 경우)를 포함할 사용자 할당 버퍼(PCAP_ERRBUF_SIZE 크기)에 대한 포인터.

해당 함수는 모든 것이 정상이면 '0', 일부 오류가 발생하면 '-1'. 완전한 source를 포함하는 문자열은 'source' 변수에 반환된다.

```
if ( (fp= pcap_open(source,			// name of the device
						65536,			// portion of the packet to capture
										// 65536 guarantees that the whole packet will be captured on all the link layers
						 PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
						 1000,				// read timeout
						 NULL,				// authentication on the remote machine
						 errbuf			// error buffer
						 ) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", source);
		return -1;
	}
  ```
  
  위의 소스코드는 캡쳐한 덤프 파일을 호출하는 소스코드이다. 
  pcap_open() 함수 - 캡처한 덤프파일을 열 때 사용하는 함수로, 모든 pcap_open_xxx() 함수들의 기능을 대체할 수 있다. 
  pcap_open() 함수 대신 pcap_open_live() 함수로도 대체가 가능하지만, 권한이 없는 관리자가 파일을 열 수 없게 하기 위해 pcap_open() 함수를 사용한 것 같다.
  pcap_open() 함수의 파라미터는 다음과 같다.
  
  >source : 사용할 디바이스의 이름을 결정하는 파라미터이다. 
  
  >snalpen : 캡처할 최대 바이트 수를 지정합니다. 이 값이 캡처된 패킷의 크기보다 작으면 해당 패킷의 첫 번째 snaplen 바이트만 캡처되어 패킷 데이터로 제공된다. 
  '65535' 값은 모든 네트워크는 아니지만 대부분의 네트워크에서 패킷에서 사용 가능한 모든 데이터를 캡처하기에 충분해야 한다.
  
  >promisc : 인터페이스가 무차별 모드로 전환되는지 여부를 지정한다. "any"에서 작동하지 않습니다. "any" 또는 NULL의 인수가 제공되면 promisc 플래그는 무시된다.
  
  >to_ms : 읽기 제한 시간을 ms(밀리세컨드) 단위로 지정하는 파라미터이다. 
  
  > errbuf :오류 또는 경고 메시지를 반환하는데 할당하는 버퍼로 사용된다.
  
  
  ```
  pcap_loop(fp, 0, dispatcher_handler, NULL);

	return 0;
}
```

위 소스코드는 EOF에 도달할 때까지 패킷을 읽고 발송하는 소스코드이다. EOF는 파일 끝(End of File, EOF[1])는 데이터 소스로부터 더 이상 읽을 수 있는 데이터가 없음을 나타낸다. 

pcap_loop() 함수 - 라이브 캡처 또는 저장 파일에서 패킷을 처리하는 함수이다. 

- basic_dump.c : 만들어진 덤프파일에서 네트워크 패킷을 추출하는 소스코드이다.

```
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
```

위 소스코드는 pcap 라이브러리에서 네트워크 패킷이 도착하면 호출해 주는 함수의 프로토타입으로, 패킷이 도착하면 'packet_handler()'라는 함수가 콜백으로 호출된다. 

```
if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
  ```
  
  pcap_findalldevs() 함수는 시스템이 가지고 있는 모든 네트워크 인터페이스에 대한 정보를 연결된 List형태로 생성하여 List의 첫번째 노드의 주소를 첫번째 인자에 넣어 반환해준다.
       

```
if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
  ```
  사용할 인터페이스의 이름을 입력받고 inum 변수에 그 값을 할당한다. 할당한 후, pcap_freealldevs() 함수를 이용하여 장치 목록을 해제하고, allldevs가 가리키는 장치 목록을 해제한다. 반환할 값이 없어도 -1의 값을 반환한다. 
  
```
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused variables
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
	
	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
}
```

위 소스코드는 winpcap과 관계 없는 유닉스 환경에서만 시간을 출력하고 패킷의 길이를 출력해주는 부분이다. 

- sendpcap.c - 패킷을 보내는 소스코드이다. 

```	
if (pcap_datalink(indesc) != pcap_datalink(outdesc))
	{
		printf("Warning: the datalink of the capture differs from the one of the selected interface.\n");
		printf("Press a key to continue, or CTRL+C to stop.\n");
		getchar();
	}
```

위의 소스코드는 MAC의 유형을 확인하는 소스코드로, 캡쳐한 인터페이스의 데이터 링크가 선택한 인터페이스의 데이터 링크와 다른지 비교 분석하는 구문이다. 

pcap_datalink()함수 - 어댑터의 링크 계층을 반환한다.

```
squeue = pcap_sendqueue_alloc(caplen);

```
위의 소스코드는 전송 큐를 할당하는 소스코드이다. 

pcap_sendqueue_alloc() 함수 - 전송 큐를 할당하는 함수로, 전송 대기열(pcap_sendqueue_transmit()) 함수를 사용하여 네트워크에서 전송될 원시 패킷 집합을 포함하는 버퍼를 할당하는 역할을 수행하는 함수이다.

pcap_sendqueue_queue() 함수를 사용하여 대기열에 패킷을 삽입하는 역할을 수행하는 함수이다.

```

if (res == -1)
	{
		printf("Corrupted input file.\n");
		pcap_sendqueue_destroy(squeue);
		return;
	}
  
  ```
  위의 소스코드는 파일의 패킷으로 채워진 큐를 나타내는 변수인 'res'값이 -1이면 전송 큐를 제거하는 소스코드이다. 
  
  pcap_sendqueue_destroy(squeue) 함수 - 큐에 전송되고 있는 파일의 패킷을 제거하는 함수이다. 패킷 보내기 대기열을 삭제하고 연결된 모든 메모리를 해제한다. 
  

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
  
  
  
  - SUA 오픈소스 보안 프로젝트 : 멘토님께서 알려주신 pcap 라이브러리를 이용한 예제 소스코드이다.

```
#include <stdio.h>
 #include <pcap.h>

 int main(int argc, char *argv[])
{
    char *dev = argv[1];
    
   printf("Device: %s\n", dev);
   return (0);
}

```

위의 소스코드는 디바이스의 이름을 설정하는 소스코드이다. dev 변수에 디바이스 인자값 하나를 할당한다.

```
#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
   char *dev, errbuf[PCAP_ERRBUF_SIZE];

   dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return (2);
    }
    printf("Device: %s\n", dev);


   return (0);
 }

```

위 소스코드는 pcap_lookupdev() 함수로 기본 디바이스 즉, 시스템의 첫 번째 유효한 디바이스의 정보를 가지고 오는 소스코드이다.

```
#include <stdio.h>
#include <pcap.h>

int main(int argc, char* argv[])
{
    pcap_t* handle;

    char* dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    printf("Device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }
    return (0);
}

```

위의 소스코드는 main 구문으로, pcap_open_live() 함수로 네트워크로부터 실시간 패킷을 캡쳐하는 과정을 나타낸다.
  
  



