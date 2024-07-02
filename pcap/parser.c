/*
   ========================================================================================================
     Title  - Network Packet Parser
        ---------------------------------------------------------------------------------------------------
     Date   - 5th June 2014
        ---------------------------------------------------------------------------------------------------
     Brief Description

     -This is a menu driver program wherein you get the summary of all the packets or a single packet
     for inspection. 
     -Separate modules have been created to display the details of each header.
      -----------------------------------------------------------------------------------------------------
     Note

     -This code works for both the tcp.pcap and the arp.pcap files.
     -The name of the file has to been as a command line argument
   =========================================================================================================
*/

#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

//Header sizes for display purposes 
#define ETHER_HEADERSIZE 14
#define ARP_HEADERSIZE 28
//Pre-Calculated TCP Header Offset 
#define TCPHDROFFSET(th)  (((th)->dataoffset & 0xf0) >> 4)
            
/*
    ===============================================================================
    Structures to parse the headers in the pcap files - Ethernet, IP, TCP and ARP
    ===============================================================================
*/

typedef struct ether 
{
    unsigned char desthost[6]; 
    unsigned char srchost[6];  
    unsigned short type;       // IP or ARP
}ether;

typedef struct IP 
{
    unsigned char headlen;    //Holds the version << 4 and the header length >> 2 
    unsigned char tos;        //Type of Service
    unsigned short totlen;     
    unsigned short ident;      
    unsigned short offset;    //Fragment Offset Field */
    unsigned char ttl;        //Time to Live */
    unsigned char protocol;   
    unsigned short ipchecksum;     
    struct in_addr sourceip;
    struct in_addr destip;     
}IP;
  
typedef struct TCP
{
    unsigned short srcport;   
    unsigned short destport;   
    uint32_t seqno;           
    uint32_t ackno;            
    unsigned char dataoffset;    
    unsigned char flags;
    unsigned short  window;     
    unsigned short  tcpchecksum;     
    unsigned short  urgptr;     
}TCP;

typedef struct ARP 
{ 
    uint16_t hwtype;             
    uint16_t prottype;            
    unsigned char hwaddrlen;         
    unsigned char protlen;         
    uint16_t oper;                       
    unsigned char shwaddr[6];      // Sender hardware address  
    unsigned char sipaddr[4];      // Sender IP address        
    unsigned char thwaddr[6];      // Target hardware address 
    unsigned char tipaddr[4];      // Target IP address       
}ARP;


/*
     ================================
      Function Prototypes       
     ================================
*/
unsigned short dispetherdetails(const unsigned char *);
int dispipdetails(const unsigned char *);
int disptcpdetails(const unsigned char *, int );
void disparpdetails(const unsigned char *);
void printdata(int ,int ,const unsigned char *, int );
double calculate_rtt(pcap_t *pcap, struct pcap_pkthdr *header);
void parser(int ,char *);
int is_request_packet(const u_char *packet, struct pcap_pkthdr *header);
int is_reply_packet(const u_char *packet, struct pcap_pkthdr *header);

/*
     ================================
      Main Function       
     ================================
*/
int main(int argc, char *argv[])
{
    //File name is sent as an argument
    char *file = argv[1];
    int choice=0,pno=0; 
   
   //Display the menu and take the user's choice 
    while(1)
    {
        parser(pno,file);
        sleep(1);
    }
    return 0;
} 

/*
     ============================================================================================
     Function Objective - Parses the data and displays each packet's details
        -----------------
     Parameters         - (1)Packet No to be printed(default 0 for all packets to be printed), 
                          (2)PCap file name
        -----------------
     Return Value       - None 
     ============================================================================================
*/
void parser(int pno,char *file)
{
    
    //Create a packet header and a data object
    struct pcap_pkthdr *header;
    const char *data;
    
    //Variable Declarations
    unsigned short ethertype;
    struct tm *info;
    char actualtime[80];
    int i;
    int ipheadlen,tcpheadlen;
    int pktctr = 1,val;

    //Char array to hold the error. PCAP_ERRBUF_SIZE is defined as 256.
    char errbuff[PCAP_ERRBUF_SIZE];
 
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);


    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return;
    }

    printf("\nDevice: %s\n", dev);

    //Open the saved captured file and store result in pointer to pcap_t
    // pcap_t *pcap = pcap_open_offline(file, errbuff);
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
    if (parser == NULL) {
        fprintf(stderr, "Can't open %s: %s\n", dev, errbuf);
        return;
    }

    //Start reading packets one by one 
    while (val = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        
        //To find a particular packet to be displayed
        if(pno!=0)
        {
            while (pktctr!=pno)
            {
                val = pcap_next_ex(pcap, &header, &data);

                if(val >= 0)
                    pktctr++;
            }
        }

        if (is_request_packet(data, header)) {
            printf("Captured request packet\n");
        } else if (is_reply_packet(data, header)) {
            printf("Captured reply packet\n");
        } else {
            printf("Packet type unclear\n");
        }

        printf("*******************************************************\n");
        printf("\n\t\t--PACKET INFO--\n\n");
        
        // Show the packet number
        printf("Packet\t# %d\n", pktctr++);
        printf("Packet size\t: %d bytes\n", header->len);
        
        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %u bytes\n", header->len);
        
        //Conversion of Epoch Time into readable format
        info = localtime(&header->ts.tv_sec);
        strftime(actualtime,80,"%c",info);
        // printf("Epoch Time\t: %lu:%lu seconds | %s\n\n", header->ts.tv_sec, header->ts.tv_usec, actualtime);
        printf("Epoch Time\t: %s\n", actualtime);

        struct timeval receiver_tv;
        struct tm* sender_tv;

        gettimeofday(&receiver_tv, NULL);
        sender_tv = localtime(&header->ts.tv_usec);

        // long sender_timestamp = header->ts.tv_usec
        long rtt = (long) receiver_tv.tv_sec * 1000000 + receiver_tv.tv_usec - header->ts.tv_usec;

        printf("RTT\t\t: %ld\n\n", header->ts.tv_usec);
    
        ethertype=dispetherdetails(data);
        
        /*
            Display IP and TCP details for tcp.pcap file
            or display ARP details for arp.pcap file
        */
        if(ethertype==8)
        {
            ipheadlen = dispipdetails(data);
            tcpheadlen = disptcpdetails(data,ipheadlen); 
        }

        if(pno!=0)
            break;
          
        // Add two lines between packets
        printf("\n\n");

        printf("\n*******************************************************\n");
    }
}


/*
   =============================================================
    Functions to display the headers details
   =============================================================
    
   =============================================================
     Function Objective - Displays ethernet header details
        -----------------
     Parameter          - PCap Packet Data
        -----------------
     Return Value       - Ethernet Type(IP/ARP) 
   =============================================================
*/
unsigned short dispetherdetails(const unsigned char *data)
{
    ether *ethernet;
    ethernet = (ether*)(data);
    int i,flag;

    for(i=0; i<6;i++)
    {  
        if(ethernet->desthost[i]==255)
            flag=1;
        else
            flag=0;
    }

    return ethernet->type;

}

/*
   ======================================================
     Function Objective - Displays IP header details
        -----------------
     Parameter          - PCap Packet Data
        -----------------
     Return Value       - IP header length 
   ======================================================
*/

int dispipdetails(const unsigned char *data)
{
    IP *ip;
    char srcname[20],dstname[20];

    //Point to the IP header i.e. 14 bytes(Size of ethernet header) from the start 
    ip = (IP*)(data + ETHER_HEADERSIZE);

    // printf("\n\t\t--IP HEADER INFO--\n\n");
    strcpy(srcname,inet_ntoa(ip->sourceip));
    strcpy(dstname,inet_ntoa(ip->destip));


    /* Calculation of IP Header Length
        
        1)In this case ip->headlen contains 45 where 4 is the IP version and 5 is the actual length
        2)We only need the length so masking with 0x0f is done
        3)This length is in Byte Words so multiplication with 4 gives us the length in bytes
    */
    return ((ip->headlen & 0x0f)*4); 
}

/*
    
   =============================================================
     Function Objective - Displays TCP header details
        -----------------
     Parameters         - PCap Packet Data , IP header length
        -----------------
     Return Value       - TCP header length 
   =============================================================
*/

int disptcpdetails(const unsigned char *data, int ipheadlen)
{
    TCP *tcp;
    unsigned short srcport,dstport;
    
    //Point to the TCP header as explained in IP
    tcp = (TCP*)(data + ETHER_HEADERSIZE + ipheadlen);
   
    printf("\n\t\t--TCP HEADER INFO--\n\n");

    printf("Source Port\t: %d\nDestination Port: %d \n", ntohs(tcp->srcport), ntohs(tcp->destport));
    printf("SEQ Number\t: %u\nACK Number\t: %u \n", ntohl(tcp-> seqno), ntohl(tcp->ackno));
    // printf("Header Length\t: %d Bytes\n",(unsigned int)(TCPHDROFFSET(tcp)*4));
    printf("Window\t\t: %d\n",ntohs(tcp->window));
    // printf("Checksum\t: %d\n",ntohs(tcp->tcpchecksum));

    /*Calculation of TCP Header Length 
        1)Byte Offset 12 is TCP HDR LEN
        2)Format is 50 or similar
        3)We need the MSB so masking with 0xf0 is done and the right shifting by 4 bits(>>4)
        4)Now multiplication with 4 done to get length in bytes  
    */

    return (TCPHDROFFSET(tcp)*4);
}

/*
    
   ======================================================
     Function Objective - Displays ARP header details
        -----------------
     Parameter          - PCap Packet Data 
        -----------------
     Return Value       - None 
   ======================================================
*/

void disparpdetails(const unsigned char *data)
{
 
    ARP *arp;
    int i;
    
    // Point to the ARP header 
    arp = (ARP*)(data+ETHER_HEADERSIZE); 
 
    printf("\n\t\t--ARP HEADER INFO--\n\n");
    if(ntohs(arp->hwtype) == 1)
        printf("Hardware type\t\t\t\t: Ethernet (0001)\n"); 
    if(ntohs(arp->prottype) == 0x0800)
        printf("Protocol type\t\t\t\t: IPv4 (0800)\n");
    printf("Link Layer Hardware Address Length\t: %d Bytes\n",(unsigned int)(arp->hwaddrlen));
    printf("Network Protocol Address Length\t\t: %d Bytes\n",(unsigned int)(arp->protlen));
    if(ntohs(arp->oper)==1)
        printf("Operation\t\t\t\t: ARP Request\n");
    else
        printf("Operation\t\t\t\t: ARP Reply\n"); 

    // If Hardware type is Ethernet and Protocol is IPv4, print packet contents  
    if (ntohs(arp->hwtype) == 1 && ntohs(arp->prottype) == 0x0800)
    { 
         
        printf("Sender Hardware Address\t\t\t: "); 
        for(i=0; i<6;i++)
            printf("%02X:", arp->shwaddr[i]);
    
        printf("\nTarget Hardware Address\t\t\t: "); 
        for(i=0; i<6;i++)
            printf("%02X:", arp->thwaddr[i]); 
        
        printf("\nSender Network Protocol Address\t\t: "); 
        for(i=0; i<4;i++)
            printf("%d.", arp->sipaddr[i]); 

        printf("\nTarget Network Protocol Address\t\t: "); 
            for(i=0; i<4; i++)
            printf("%d.", arp->tipaddr[i]); 

        printf("\n"); 
    }    

}

/*
   ==========================================================================================================
     Function Objective - Displays the PCap packet data
        -----------------
     Parameters         - (1)Start byte for printing, (2)End byte to stop printing, 
                          (3)PCap Packet Data, (4)Flag is 0 to print in hex or 1 to print in readable form 
        -----------------
     Return Value       - None 
   ==========================================================================================================
*/
void printdata(int offset,int size,const unsigned char *data, int flag)
{
    int i,j;
    
    for (i=offset,j=0; (i < size) ; i++,j++)
    {
        // Start printing on the next after every 16 octets
        if ( (j % 16) == 0) 
            printf("\n");
        if(flag==1)
        {
            //Check if the packet data is printable
            if(isprint(data[i]))                
                printf(" %c ",data[i]);
            else
               printf(" . ",data[i]); 
        }
        else
            printf(" %.2x",data[i]);          
    }
}

int is_request_packet(const u_char *packet, struct pcap_pkthdr *header) {
    struct TCP *tcp_header = (struct TCP *)(packet + 14); // Assuming Ethernet header size is 14 bytes
    return (tcp_header->flags && !tcp_header->ackno); // Check for SYN flag (new connection) without ACK flag
}

int is_reply_packet(const u_char *packet, struct pcap_pkthdr *header) {
    struct TCP *tcp_header = (struct TCP *)(packet + 14); // Assuming Ethernet header size is 14 bytes
    return tcp_header->ackno; // Check for ACK flag (acknowledgment)
}
