
SUA에서 진행하고 있는 오픈소스 보안 스터디입니다.

# [오픈소스 이름]

## Introduction
npcap은 소프트웨어 라이브러리와 네트워크 드라이버로 구성된 Windows 운영 체제 용 패킷 캡처 및 네트워크 분석을 위한 도구의 일종이다. 

## Analysis
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
