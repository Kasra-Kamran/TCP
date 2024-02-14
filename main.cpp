#include <string>
#include <string_view>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <vector>

#define MAX_PACKET_LENGTH 1024
#define INTERFACE "wlp3s0"
#define BUF_SIZE 256


void printHex(void *ptr, size_t size)
{
    unsigned char bytePtr[size];
    memcpy((void*)bytePtr, ptr, size); 
    
    printf("Hexadecimal representation:\n");
    for (size_t i = 0; i < size; ++i)
    {
        if(i % 4 == 0)
            printf("\n");
        int n = *(uint8_t*)&bytePtr[i];
        for(int i = 0; i < 8; i++)
        {
            if (n & 0b10000000)
                printf("1");
            else
                printf("0");

            n <<= 1;
        }
        printf(" ");
    }
    printf("\n");
    for (size_t i = 0; i < size; ++i)
    {
        if(i % 4 == 0)
            printf("\n");
        printf("%02X ", bytePtr[i]);
        printf(" ");
    }
    printf("\n");
}


class TcpListener
{
public:
    TcpListener(const std::string& address, int port)
    {
        _rawfd = socket(AF_PACKET, SOCK_RAW, ETH_P_IP);
        getMacAddress(INTERFACE, _srcMAC);

        struct sockaddr_ll socket_address;
        socket_address.sll_family = AF_PACKET;
        socket_address.sll_protocol = htons(ETH_P_ALL);
        socket_address.sll_ifindex = if_nametoindex(INTERFACE);
        socket_address.sll_hatype = 0;
        socket_address.sll_pkttype = PACKET_OTHERHOST;
        socket_address.sll_halen = 6;
        memcpy(socket_address.sll_addr, _srcMAC, 6);
        int res = bind(_rawfd, (struct sockaddr*)&socket_address, sizeof(socket_address));

        inet_pton(AF_INET, address.c_str(), _IPHeader.DestinationIP);
        inet_pton(AF_INET, "192.168.43.89", _IPHeader.SourceIP);
        _TCPHeader.DestinationPort = htons(port);
        _TCPHeader.SourcePort = htons(getDynamicSourcePort((char*)&_IPHeader.DestinationIP[0], _TCPHeader.DestinationPort));
    }

    void Send(void* data, size_t size)
    {
        std::vector<Segment> segments = segmentData(data, size);
        for(Segment s : segments)
        {
            _IPHeader.TotalLength = htons(sizeof(IPHeader) + sizeof(TCPHeader) + s.Size);
            _IPHeader.TOS = 0;
            _IPHeader.Version = 0b0101; // reversed
            _IPHeader.IHL = 0b0100;
            _IPHeader.Identification = _IPHeader.Checksum; // Do this better.
            _IPHeader.Flags_FragmentOffset = 0;
            *(uint8_t*)&_IPHeader.Flags_FragmentOffset |= 0b010 << 5;
            *(uint8_t*)&_IPHeader.Flags_FragmentOffset &= 0b11100000;
            *((uint8_t*)&_IPHeader.Flags_FragmentOffset + 1) = 0;
            _IPHeader.TTL = 64;
            _IPHeader.Protocol = 0x06;
            _IPHeader.Checksum = 0;
            memcpy((void*)_TCPPseudoHeader.SourceIP, (void*)_IPHeader.SourceIP, 6);
            memcpy((void*)_TCPPseudoHeader.DestinationIP, (void*)_IPHeader.DestinationIP, 6);
            _TCPPseudoHeader.Protocol = htons(6);
            _TCPPseudoHeader.TCPSegmentLength = htons(sizeof(TCPHeader) + s.Size);
            // _TCPHeader.SequenceNumber = htons(_TCPHeader.SequenceNumber + 1);
            _TCPHeader.SequenceNumber &= 0;
            _TCPHeader.SequenceNumber = htonl(1);
            _TCPHeader.AcknowledmentNumber = htons(getACKnumber());
            _TCPHeader.DataOffset_Flags = 0x0000;
            *(uint8_t*)&_TCPHeader.DataOffset_Flags |= 5 << 4;
            // *(uint8_t*)&_TCPHeader.DataOffset_Flags &= 0b0;
            *((uint8_t*)&_TCPHeader.DataOffset_Flags + 1) = 0b00001010;
            _TCPHeader.WindowSize = 0xFFFF;
            _TCPHeader.Checksum = 0;
            _TCPHeader.UrgentPointer = 0;
            calculateIPchecksum();
            calculateTCPchecksum(s);

            unsigned char packet[sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader) + s.Size];
            memcpy((void*)packet, (void*)&_EthernetHeader, sizeof(EthernetHeader));
            memcpy((void*)(packet + sizeof(EthernetHeader)), (void*)&_IPHeader, sizeof(IPHeader));
            memcpy((void*)(packet + sizeof(EthernetHeader) + sizeof(IPHeader)), (void*)&_TCPHeader, sizeof(TCPHeader));
            memcpy((void*)(packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader)), s.Data, s.Size);
            send((void*)packet, sizeof(packet));
        }
    }

    void send(void* data, size_t size)
    {
        size_t sent = ::send(_rawfd, data, size, 0);
        std::cout << sent << "\n";
    }

    void recv()
    {
        unsigned char buffer[MAX_PACKET_LENGTH];
        while(1)
        {
            int read = ::recv(_rawfd, buffer, MAX_PACKET_LENGTH, 0);
            if(buffer[12] == 0x08 && buffer[13] == 0x06 && strcmp((char*)&buffer[38], (char*)_privateIP))
            {
                memcpy((void*)_destMAC, (void*)(buffer + 22), 6);
                memcpy((void*)_EthernetHeader.DestinationMAC, (void*)(buffer + 22), 6);
                return;
            }
                
        }
    }

private:

    struct EthernetHeader
    {
        unsigned char DestinationMAC[6];
        unsigned char SourceMAC[6];
        union
        {
            uint16_t EthType;
            uint16_t Protocol;
        };
    } _EthernetHeader;

    struct ARPHeader
    {
        uint16_t HardwareType;
        uint16_t ProtocolType;
        uint8_t HardwareAddressLength;
        uint8_t ProtocolAddressLength;
        uint16_t Operation;
        unsigned char SourceMAC[6];
        unsigned char SourceIP[4];
        unsigned char DestinationMAC[6];
        unsigned char DestinationIP[4];
    } _ARPHeader;

    struct IPHeader
    {
        uint8_t Version : 4;
        uint8_t IHL : 4;
        uint8_t TOS;
        uint16_t TotalLength;
        uint16_t Identification;
        uint16_t Flags_FragmentOffset = 0;
        uint8_t TTL;
        uint8_t Protocol;
        uint16_t Checksum;
        unsigned char SourceIP[4];
        unsigned char DestinationIP[4];
        struct Options;
    } _IPHeader;

    struct TCPPseudoHeader
    {
        unsigned char SourceIP[4];
        unsigned char DestinationIP[4];
        uint16_t Protocol;
        uint16_t TCPSegmentLength;
    } _TCPPseudoHeader;

    struct TCPHeader
    {
        uint16_t SourcePort;
        uint16_t DestinationPort;
        uint32_t SequenceNumber;
        uint32_t AcknowledmentNumber;
        uint16_t DataOffset_Flags;
        uint16_t WindowSize;
        uint16_t Checksum;
        uint16_t UrgentPointer;
        struct Options;
    } _TCPHeader;

    struct Segment
    {
        void* Data;
        uint16_t Size;
    };

public:

    void setup()
    {
        // ARPrequest();
    }

    std::vector<Segment> segmentData(void* data, size_t size)
    {
        return std::vector<Segment>{{data, size}};
    }

    uint16_t calculateChecksum(unsigned char* data, int len)
    {
        uint32_t sum = 0;

        while (len > 1)
        {
            sum += *((uint16_t*)data);
            data += 2;
            len -= 2;
        }

        if (len == 1)
        {
            sum += *((uint8_t*)data);
        }

        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return ~sum;
    }

    void sumBytes(unsigned char* data, int len, uint32_t& sum)
    {
        while (len > 1) {
            sum += *((uint16_t*)data);
            data += 2;
            len -= 2;
        }

        if (len == 1) {
            sum += *((uint8_t*)data);
        }
    }

    void calculateTCPchecksum(Segment& s)
    {
        uint32_t sum = 0;
        sumBytes((unsigned char*)&_TCPPseudoHeader, sizeof(TCPPseudoHeader), sum);
        sumBytes((unsigned char*)&_TCPHeader, sizeof(TCPHeader), sum);
        sumBytes((unsigned char*)s.Data, s.Size, sum);

        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = ~sum;
        _TCPHeader.Checksum = (sum);
    }

    void calculateIPchecksum()
    {
        _IPHeader.Checksum = calculateChecksum((unsigned char*)&_IPHeader, sizeof(IPHeader));
    }

    void constructARPrequest()
    {
        memcpy((void*)_EthernetHeader.DestinationMAC, (void*)_destMAC, 6);
        memcpy((void*)&_EthernetHeader.SourceMAC, (void*)_srcMAC, 6);
        _EthernetHeader.Protocol = htons(0x0806);
        _ARPHeader.HardwareType = htons(0x0001);
        _ARPHeader.ProtocolType = htons(0x0800);
        _ARPHeader.HardwareAddressLength = 0X06;
        _ARPHeader.ProtocolAddressLength = 0x04;
        _ARPHeader.Operation = htons(0x0001);
        memcpy((void*)_ARPHeader.SourceMAC, (void*)_EthernetHeader.SourceMAC, 6);
        memset((void*)_EthernetHeader.DestinationMAC, 0xFF, 6);

        _ARPHeader.SourceIP[0] = 0xC0;
        _ARPHeader.SourceIP[1] = 0xA8;
        _ARPHeader.SourceIP[2] = 0x2B;
        _ARPHeader.SourceIP[3] = 0x59;
        _ARPHeader.DestinationIP[0] = 0xC0;
        _ARPHeader.DestinationIP[1] = 0xA8;
        _ARPHeader.DestinationIP[2] = 0x2B;
        _ARPHeader.DestinationIP[3] = 0x01;

        unsigned char packet[sizeof(EthernetHeader) + sizeof(ARPHeader)];
        memcpy((void*)packet, (void*)&_EthernetHeader, sizeof(EthernetHeader));
        memcpy((void*)(packet + sizeof(EthernetHeader)), (void*)&_ARPHeader, sizeof(ARPHeader));
        send((void*)packet, sizeof(EthernetHeader) + sizeof(ARPHeader));
        recv();
        _EthernetHeader.Protocol = htons(0x0800);
    }

    void constructEthernetHeader(unsigned char protocol[])
    {
        memcpy((void*)_EthernetHeader.DestinationMAC, (void*)_destMAC, 6);
        memcpy((void*)&_EthernetHeader.SourceMAC, (void*)_srcMAC, 6);
        _EthernetHeader.Protocol = *(uint16_t*)protocol;
    }

    void constructIPheader(unsigned char TCPheader[], size_t size)
    {

        unsigned char ipv4_header[] =
        {
            0x45, 0x00,         // Version (4), IHL (5)
            0x00, 0x14,         // Type of Service, Total Length (20 bytes)
            0x30, 0x39,         // Identification (12345)
            0x00, 0x00,         // Flags, Fragment Offset
            0x40,               // Time to Live (64)
            0x06,               // Protocol (TCP)
            0x00, 0x00,         // Header Checksum (placeholder)
            0xC0, 0xA8, 0x2B, 0x59, // Source IP Address (192.168.1.100)
            0xD8, 0xEF, 0x26, 0x78  // Destination IP Address (8.8.8.8)
        };

        ipv4_header[3] = static_cast<uint8_t>(ipv4_header[3]) + static_cast<uint8_t>(size);

        uint16_t checksum = calculateChecksum(ipv4_header, sizeof(ipv4_header));

        ipv4_header[11] = checksum >> 8;
        ipv4_header[10] = checksum & 0xFF;

        memcpy((void*)(_packet + 14), (void*)ipv4_header, 20);
        memcpy((void*)(_packet + 34), (void*)TCPheader, size);
        send((void*)_packet, 34 + size);
    }

    int getDynamicSourcePort(const char* destination_ip, int destination_port)
    {
        return 45678;

        int sockfd;
        struct sockaddr_in dest_addr, local_addr;
        socklen_t addrlen = sizeof(local_addr);

        // Create a TCP socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("socket");
            return -1;
        }

        // Specify the destination IP address and port
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_addr.s_addr = inet_addr(destination_ip);
        dest_addr.sin_port = htons(destination_port);

        // Connect to the destination
        if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
            perror("connect");
            close(sockfd);
            return -1;
        }

        // Get the local port assigned to the socket
        if (getsockname(sockfd, (struct sockaddr *)&local_addr, &addrlen) == -1) {
            perror("getsockname");
            close(sockfd);
            return -1;
        }

        close(sockfd);

        int port = ntohs(local_addr.sin_port);

        return port;
    }

    int getACKnumber()
    {
        return 0;
    }

    void constructTCPheader()
    {
        unsigned char pseudo_header[] =
        {
            0xC0, 0xA8, 0x2B, 0x59, // Source IP Address (192.168.1.100)
            0xD8, 0xEF, 0x26, 0x78,  // Destination IP Address (8.8.8.8)
            0x00, 0x06,
            0x00, 0x14
        };

        unsigned char header[] =
        {

        
            0x1F, 0x90,             // Source Port: 8080
            0x01, 0xBB,            // Destination Port: 80
            0x00, 0x00, 0x00, 0x00, // Sequence Number: 0
            0x00, 0x00, 0x00, 0x00, // Acknowledgment Number: 1
            // 0xA0,                   // Data Offset: 5 (20 bytes)
            0x50,
            0x02,                   // Flags: SYN
            0xFF, 0xFF,             // Window Size
            0x00, 0x00,             // Checksum (to be calculated)
            0x00, 0x00,             // Urgent Pointer
            // 0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,0x90,0xb0,
            // 0x97,0xb7,0x00,0x00,0x00,0x00,0x01,0x03,0x03,0x07
        };

        unsigned char* to_check = new unsigned char[sizeof(header) + sizeof(pseudo_header)];

        memcpy((void*)to_check, (void*) pseudo_header, sizeof(pseudo_header));
        memcpy((void*)(to_check + sizeof(pseudo_header)), (void*) header, sizeof(header));
        
        uint16_t checksum = calculateChecksum(to_check, sizeof(header) + sizeof(pseudo_header));

        delete[] to_check;

        header[16] = checksum & 0xFF;
        header[17] = checksum >> 8;

        unsigned char tcp_header[] =
        {
            0x9C, 0xBA, 0x01, 0xBB, 0xC7, 0x79, 0xDA, 0x3E,
            0x00, 0x00, 0x00, 0x00, 0xA0, 0x02, 0xFA, 0xF0,
            0x6D, 0x67, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
            0x04, 0x02, 0x08, 0x0A, 0xF7, 0xBB, 0x01, 0x30,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
        };


        constructIPheader(header, sizeof(header));

    }

    

    int getMacAddress(const char* interface, unsigned char* macAddress)
    {
        static bool hasRunOnce = false;
        if(hasRunOnce)
            return -1;
        hasRunOnce = true;

        struct ifreq ifr;
        int sockfd;

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            perror("socket");
            return -1;
        }

        strncpy(ifr.ifr_name, interface, IFNAMSIZ);

        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("ioctl");
            close(sockfd);
            return -1;
        }

        memcpy(macAddress, ifr.ifr_hwaddr.sa_data, 6);

        close(sockfd);

        return 0;
    }

    int _rawfd;
    uint64_t _seq;
    unsigned char _packet[MAX_PACKET_LENGTH];
    unsigned char _destMAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char _srcMAC[6];
    unsigned char _privateIP[4] = {0xC0, 0xA8, 0x2B, 0x59};
    
};



int main()
{
    TcpListener t("216.239.38.120", 443);
    t.constructARPrequest();
    int a = 0;
    t.Send((void*)&a, 4);
}