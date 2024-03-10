#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#define DEST_IP "192.168.107.132"
#define DEST_PORT 12345
#define TARGET_SPEED_BPS 100000000 // 100 Mbps
#define BITS_PER_BYTE 8

int main() {
    int sockfd;
    struct sockaddr_in dest_addr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    const u_char *packet;
    struct pcap_pkthdr header;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);

    pcap = pcap_open_offline("s_packet.pcap", errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    while ((packet = pcap_next(pcap, &header)) != NULL) {
        // Calculate delay to maintain 100 Mbps speed
        long delay = (header.len * BITS_PER_BYTE * 1000000) / TARGET_SPEED_BPS; // Convert delay to microseconds

        // Send the packet
        if (sendto(sockfd, packet, header.len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto failed");
            break;
        }

        usleep(delay);  // Wait for the calculated delay before sending the next packet
    }

    pcap_close(pcap);
    close(sockfd);
    return 0;
}
