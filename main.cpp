#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
// I Will Use Stucture, Next Time!
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
void print_smac(const u_char *smac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x -> ",smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
}
void print_dmac(const u_char *dmac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x, ",dmac[0],dmac[1],dmac[2],dmac[3],dmac[4],dmac[5]);
}
void print_sip(const u_char *sip){
    printf("%d.%d.%d.%d:",sip[0],sip[1],sip[2],sip[3]);
}
void print_dip(const u_char *dip){
    printf("%d.%d.%d.%d:",dip[0],dip[1],dip[2],dip[3]);
}
void print_sport(const u_char *sport){
    printf("%d -> ",sport[0]*256 + sport[1]);
}
void print_dport(const u_char *dport){
    printf("%d, ",dport[0]*256 + dport[1]);
}
void print_tcpdata(const u_char *data){
    printf("%02x|%02x|%02x|%02x|%02x|%02x|%02x|%02x|%02x|%02x \n",data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7],data[8],data[9]);
}
int test_ipcmp(const u_char *cmp){
    int ip = 0;
    if(cmp[0]+cmp[1] == 0x0008 || cmp[0]+cmp[1] == 0xDD08){
        ip = 1;
        return ip;
    }
    else {
        ip = 0;
        return ip;
    }
}
int test_tcpcmp(const u_char *cmp){
    int tc = 0;
    if(cmp[0] == 0x06){
        tc = 1;
        return tc;
    }
    else {
        tc = 0;
        return tc;
    }
}
int test_sdpcmp(const u_char *cmp){
    int dp = 0;
    int cmp1 = uint16_t(cmp[0]*256 + cmp[1]);
    int cmp2 = uint16_t(cmp[2]*256 + cmp[3]);
    if(cmp1 == 80 || cmp1 == 433 || cmp2 == 80 || cmp2 == 433){
        dp = 1;
        return dp;
    }
    else {
        dp = 0;
        return dp;
    }
}
int test_tdcmp(const u_char *cmp){
    int e_size = 14;
    int total = uint8_t(cmp[2]+cmp[3]);
    int ip_size = (uint8_t(cmp[0]) & 0x0F) * 4;
    int tcp_size = ((uint8_t(cmp[e_size+ip_size-2]) & 0xF0) >> 4) * 4;
    int tcpdata_size = uint8_t(total - ip_size - tcp_size); // TCP DATA Total Size
    int td = 0;
    if(tcpdata_size > 0){
        td = 1;
        return td;
    }
    else{
        td = 0;
        return td;
    }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // if file : pcap_open_offline
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    int e_size = 14;
    int ip_size = (uint8_t(packet[14]) & 0x0F) * 4;
    int tcp_size = ((uint8_t(packet[e_size+ip_size+12]) & 0xF0) >> 4) * 4;

    int ip = test_ipcmp(&packet[12]); //Type in Ethernet == 0800(IPv4) & 08DD(IPv6)
    int tc = test_tcpcmp(&packet[e_size+9]); //Protocol in IP Header == 6(TCP)
    int sdp = test_sdpcmp(&packet[e_size+ip_size]); //SourcePort or DestiPort 80, 433?
    int td = test_tdcmp(&packet[e_size]); //Tcp DATA Size > 0

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    if (ip == 1 && tc == 1){ //if ETHER -> IP -> TCP
    // printf("%u bytes captured\n", header->caplen);
    print_smac(&packet[6]);
    print_dmac(&packet[0]);
    print_sip(&packet[e_size+12]);print_sport(&packet[e_size+ip_size]);
    print_dip(&packet[e_size+16]);print_dport(&packet[e_size+ip_size+2]);
    if (sdp == 1 && td==1){ //if (WEB or SSL) and (TCP DATA Size > 0)
    print_tcpdata(&packet[e_size+ip_size+tcp_size]);
    }else{
        printf("-\n");
    }
    printf("============================================\n");
   }

  }

  pcap_close(handle);
  return 0;
}
