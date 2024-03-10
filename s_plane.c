#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct ptp_delay_request {
    unsigned majorSdoID: 4;
    unsigned messageType: 4;
    unsigned reserved_1: 4;
    unsigned minorversionPTP: 2;
    unsigned versionPTP: 2;
    unsigned messageLength: 16;
    unsigned domainNumber: 8;
    unsigned reserved_2: 8;
    unsigned flags: 16;
    uint64_t correctionField;
    unsigned reserved_3: 32;
    uint64_t sourcePortIdentity_high; 
    unsigned sourcePortIdentity_low: 16;
    unsigned sequenceId: 16;
    unsigned control: 8;
    unsigned logMeanMessageInterval: 8;
    uint64_t originTimestamp_second; 
    unsigned originTimestamp_nanosecond: 32;
};

void create_and_save_packet(const char* filename) {
    pcap_t *pcap;
    pcap_dumper_t *pcap_dumper;
    struct pcap_pkthdr hdr;
    uint8_t packet_buffer[1500]; 

    struct ethernet_header *eth_hdr = (struct ethernet_header*)packet_buffer;
    struct ptp_delay_request *ptp_req = (struct ptp_delay_request*)(packet_buffer + sizeof(struct ethernet_header));

    // 填充 Ethernet header
    memset(eth_hdr->dest_mac, 0xff, sizeof(eth_hdr->dest_mac)); 
    memset(eth_hdr->src_mac, 0xaa, sizeof(eth_hdr->src_mac));   
    eth_hdr->ether_type = htons(0x88f7); 

  
    memset(ptp_req, 0, sizeof(struct ptp_delay_request)); 
    ptp_req->messageType = 1;
    ptp_req->versionPTP = 2;
    ptp_req->messageLength = htons(44); 



  
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper = pcap_dump_open(pcap, filename);
    if (pcap_dumper == NULL) {
        fprintf(stderr, "pcap_dump_open failed\n");
        return;
    }

 
    hdr.ts.tv_sec = 0;
    hdr.ts.tv_usec = 0;
    hdr.caplen = hdr.len = sizeof(struct ethernet_header) + sizeof(struct ptp_delay_request);
    pcap_dump((unsigned char*)pcap_dumper, &hdr, packet_buffer);


    pcap_dump_close(pcap_dumper);
    pcap_close(pcap);
}

int main() {
    create_and_save_packet("s_packet.pcap");
    return 0;
}
