// 디바이스 설정하기 예시
// #include <stdio.h>
// #include <pcap.h>

// int main(int argc, char *argv[])
// {
//    char *dev = argv[1];

//    printf("Device: %s\n", dev);
//    return (0);
// }

// pcap_lookupdev()로 기본 디바이스 (시스템의 첫 번째 유효한 디바이스) 정보 가지고 오기
// 위 함수가 deprecated 되어 pcap_findalldevs() 함수를 쓰자
// #include <stdio.h>
// #include <pcap.h>

// int main(int argc, char *argv[])
// {
//    char *dev, errbuf[PCAP_ERRBUF_SIZE];

//    dev = pcap_lookupdev(errbuf);
//    if (dev == NULL)
//    {
//       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
//       return (2);
//    }
//    printf("Device: %s\n", dev);


//    return (0);
// }

// pcap_open_live() 함수로 네트워크로부터 실시간 캡처를 open
/*#include <stdio.h>
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
}*/