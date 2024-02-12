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

class TcpSocket
{
public:
    TcpSocket(std::string_view)
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
        bind(_rawfd, (struct sockaddr*)&socket_address, sizeof(socket_address));
    }

    void Send(void* data, size_t size)
    {
        std::vector<Segment> segments = segmentData(data, size);
        for(Segment s : segments)
        {
            _IPHeader.TotalLength = htons(sizeof(IPHeader) + sizeof(TCPHeader) + s.Size);
            _IPHeader.TOS = 0;
            _IPHeader.Version = 0b0100;
            _IPHeader.IHL = 0b0101;

            _TCPHeader.SequenceNumber++;
            calculateIPchecksum();
            calculateTCPchecksum();
        }
    }

    void send(void* data, size_t size)
    {
        size_t sent = ::send(_rawfd, data, size, 0);
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

    struct IPHeader
    {
        uint8_t Version : 4;
        uint8_t IHL : 4;
        uint8_t TOS;
        uint16_t TotalLength;
        uint16_t Identification;
        uint16_t Flags : 3;
        uint16_t FragmentOffset : 13;
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
        uint16_t TCPHeaderLength;
    } _TCPPseudoHeader;

    struct TCPHeader
    {
        uint16_t SourcePort;
        uint16_t DestinationPort;
        uint32_t SequenceNumber;
        uint32_t AcknowledmentNumber;
        uint16_t DataOffset : 4;
        uint16_t : 3;
        uint16_t Flags : 9;
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

        // Sum up 16-bit words
        while (len > 1)
        {
            sum += *((uint16_t*)data);
            data += 2;
            len -= 2;
        }

        // If there's a remaining byte
        if (len == 1)
        {
            sum += *((uint8_t*)data);
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement
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

    void calculateTCPchecksum()
    {
        uint32_t sum;
        sumBytes((unsigned char*)&_TCPPseudoHeader, sizeof(TCPPseudoHeader), sum);
        sumBytes((unsigned char*)&_TCPHeader, sizeof(TCPHeader), sum);

        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = ~sum;
        _TCPHeader.Checksum = htons(sum);
    }

    void calculateIPchecksum()
    {
        _IPHeader.Checksum = htons(calculateChecksum((unsigned char*)&_IPHeader, sizeof(IPHeader)));
    }

    void constructARPrequest()
    {
        unsigned char arp[] = {0x08, 0x06};
        constructEthernetHeader(arp);
        memcpy((void*)_packet, (void*)&_EthernetHeader, 14);
        memset((void*)_packet, 0xFF, 6);
        unsigned char ARPdata[] = 
        {
            0x00, 0x01,    // Hardware Type: Ethernet (1)
            0x08, 0x00,    // Protocol Type: IPv4 (0x0800)
            0x06,          // Hardware Address Length: 6 (Ethernet MAC address length)
            0x04,          // Protocol Address Length: 4 (IPv4 address length)
            0x00, 0x01     // Operation: ARP Request (1)
        };
        memcpy((void*)(_packet + 14), (void*)ARPdata, 8);
        memcpy((void*)(_packet + 22), (void*)(_packet + 6), 6);
        unsigned char local_ip[] = {0xC0, 0xA8, 0x2B, 0x59};
        memcpy((void*)(_packet + 28), (void*)local_ip, 4);
        // memcpy((void*)(_packet + 28), (void*)get_internal_private_ip_address(), 4);
        memset((void*)(_packet + 32), 0x00, 6);
        unsigned char default_gateway[] = {0xC0, 0xA8, 0x2B, 0x01};
        memcpy((void*)(_packet + 38), default_gateway, 4);
        // memcpy((void*)(_packet + 38), (void*)get_default_gateway(), 4);
        send((void*)_packet, 42);
        recv();
        arp[0] = 0x08;
        arp[1] = 0x00;
        constructEthernetHeader(arp);
        memcpy((void*)_packet, (void*)&_EthernetHeader, 14);
    }

    void constructEthernetHeader(unsigned char protocol[])
    {
        memcpy((void*)_EthernetHeader.DestinationMAC, (void*)_destMAC, 6);
        memcpy((void*)&_EthernetHeader, (void*)_srcMAC, 6);
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

        // Calculate checksum over the header
        uint16_t checksum = calculateChecksum(ipv4_header, sizeof(ipv4_header));

        // Update the checksum field in the header
        ipv4_header[11] = checksum >> 8;    // Most significant byte
        ipv4_header[10] = checksum & 0xFF;  // Least significant byte

        memcpy((void*)(_packet + 14), (void*)ipv4_header, 20);
        memcpy((void*)(_packet + 34), (void*)TCPheader, size);
        send((void*)_packet, 34 + size);
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

        header[16] = checksum & 0xFF;  // Least significant byte
        header[17] = checksum >> 8;    // Most significant byte

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

        // Create a socket
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            perror("socket");
            return -1;
        }

        // Set the interface name in the ifreq structure
        strncpy(ifr.ifr_name, interface, IFNAMSIZ);

        // Get the MAC address using ioctl
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("ioctl");
            close(sockfd);
            return -1;
        }

        // Copy the MAC address from ifr to the provided buffer
        memcpy(macAddress, ifr.ifr_hwaddr.sa_data, 6);

        // Close the socket
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
    TcpSocket t(std::string("hello"));
    t.constructARPrequest();
    t.constructTCPheader();
}