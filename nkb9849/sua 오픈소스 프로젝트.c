// ����̽� �����ϱ� ����
// #include <stdio.h>
// #include <pcap.h>

// int main(int argc, char *argv[])
// {
//    char *dev = argv[1];

//    printf("Device: %s\n", dev);
//    return (0);
// }

// pcap_lookupdev()�� �⺻ ����̽� (�ý����� ù ��° ��ȿ�� ����̽�) ���� ������ ����
// �� �Լ��� deprecated �Ǿ� pcap_findalldevs() �Լ��� ����
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

// pcap_open_live() �Լ��� ��Ʈ��ũ�κ��� �ǽð� ĸó�� open
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