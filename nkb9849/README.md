
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
 위의 주어진 인터페이스에서 사용 가능한 모든 정보를 출력하는 프로그램이다. pcap_if_t 구조체 내용의 전체 내용을 인쇄하는 ifprint() 함수를 제공한다. 












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
