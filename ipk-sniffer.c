/*
 * IPK project 2 - Packet sniffer
 * Author: Martin Zovinec  
 * Login: xzovin00
 * 
 */


/* 
 * Used sources:
 *
 * Parsing arguments:
 * https://stackoverflow.com/questions/19604413/getopt-optional-arguments
 * 
 * Time:
 * https://stackoverflow.com/questions/13804095/get-the-time-zone-gmt-offset-in-c
 * https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811
 * 
 * Packet sniffer:
 * http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
 * https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 * https://www.tcpdump.org/pcap.html 
*/

#include<pcap.h>
#include<stdbool.h>
#include<getopt.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

#include<time.h>
#include<math.h>

void err_print(char* message, int err_num){
    fprintf(stderr,"Error %d: %s\n", err_num, message);
    exit(err_num);
}

/* 
* Function for printing time
* Combination of: 
* https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811
* https://stackoverflow.com/questions/13804095/get-the-time-zone-gmt-offset-in-c
*/
void print_time(){
    char buffer[26], timezone[56];
    int millisec;
    struct tm* tm_info;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    millisec = tv.tv_usec/1000.0; // Round to nearest millisec
    if (millisec>=1000) { // Allow for rounding up to nearest second
        millisec -=1000;
        tv.tv_sec++;
    }

    tm_info = localtime(&tv.tv_sec);

    strftime(buffer, 26, "%Y-%m-%dT%H:%M:%S", tm_info);
    strftime(timezone, 26, "%z", tm_info);
    printf("%s.%03d%s ", buffer, millisec, timezone);
}

/*
 * Function for printing data
 * Inspired by: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
int PrintData (const u_char * data , int Size, int offset){
	int i , j;
	for(i=0 ; i < Size ; i++){
        //if one line of hex printing is complete...
		if( i!=0 && i%16==0) {
			printf("         ");
			for(j = i - 16 ; j<i ; j++){
                if(j %8 == 0 && j % 16 != 0) 
                    printf(" ");
				if(data[j]>=32 && data[j]<=128)
					printf("%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else printf("."); //otherwise print a dot
			}
			printf( "\n");
		} 
		
		if(i % 16 == 0) 
            printf("0x%04x: ", offset);
		else if(i % 8 == 0) 
            printf(" ");

        printf( " %02X",(unsigned int)data[i]);
		offset++;

		if(i == Size-1){  //print the last spaces
            printf(" ");
			for(j=0; j<15-i%16; j++)
			    printf( "   "); //extra spaces
			
			printf( "         ");
			
			for(j = i-i % 16 ; j<=i ; j++){
				if(data[j] >= 32 && data[j] <= 128) {
				    printf("%c",(unsigned char)data[j]);
				}else {
				    printf(".");
				}
			}
			printf(  "\n" );
		}
	}
    return offset;
}

/*
 * Function for printing TCP packets
 * Inspired by: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void print_tcp_packet(const u_char * Buffer, int Size){

	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	struct sockaddr_in source;
    struct sockaddr_in dest;

    // print time
    print_time();

    // print source port and IP
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    printf(" %s : %u > ", inet_ntoa(source.sin_addr), ntohs(tcph->source) );

    // print destination port and IP
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf(" %s : %u, length %d bytes\n\n", inet_ntoa(dest.sin_addr), ntohs(tcph->dest), Size);

    // print offset
    int offset = PrintData(Buffer,iphdrlen, 0);

    // print hexa_bytes 
    offset = PrintData(Buffer+iphdrlen,tcph->doff*4, offset);
    printf("\n");

    //print ascii_bytes
    offset = PrintData(Buffer + header_size , Size - header_size, offset);
    printf("\n");
}

/*
 * Function for printing UDP packets
 * Inspired by: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void print_udp_packet(const u_char *Buffer , int Size){
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
    struct sockaddr_in source;
    struct sockaddr_in dest;
    

    // print time
    print_time();

    // print source IP and port
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    printf(" %s : %u > ",  inet_ntoa(source.sin_addr), ntohs(udph->source) );

    // print destination IP and port
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    printf("%s : %u, length %d bytes \n\n",  inet_ntoa(dest.sin_addr),  ntohs(udph->dest), Size);

    // print offset
    int offset = PrintData(Buffer,iphdrlen, 0);

    // print hexa_bytes 
    offset = PrintData(Buffer+iphdrlen, sizeof udph, offset);
    printf("\n");

    //print ascii_bytes
    offset = PrintData(Buffer + header_size , Size - header_size, offset);
    printf("\n");
}

/*
 * Function for printing ICMP packets
 * Inspired by: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void print_icmp_packet(const u_char * Buffer , int Size){
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
    struct sockaddr_in source;
    struct sockaddr_in dest;

    // print time
    print_time();

    // print source IP and port
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    printf(" %s > ",  inet_ntoa(source.sin_addr) );

    // print destination IP and port
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    printf("%s, length %d bytes \n\n",  inet_ntoa(dest.sin_addr), Size);

    // print offset
    int offset = PrintData(Buffer,iphdrlen, 0);

    // print hexa_bytes 
    offset = PrintData(Buffer+iphdrlen, sizeof icmph, offset);

	//print ascii_bytes
	offset = PrintData(Buffer + header_size , Size - header_size, offset);
    printf("\n");
}

/* Function for processing packets
 * Inspired by: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
    int size = header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
    //Check the Protocol and do accordingly...
    switch (iph->protocol){
        case 1:  //ICMP Protocol
            print_icmp_packet(buffer , size);
            break;
		
		case 6:  //TCP Protocol
			print_tcp_packet(buffer, size);
			break;
		
        case 17: //UDP Protocol
        	print_udp_packet(buffer , size);
        	break;
		
		default:
			break;
	}
}

/* 
 * Prints all devices
 * Inspired by: http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
 */
void print_devices(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;

    if(pcap_findalldevs(&interfaces,error)==-1)
        err_print("Can't find any devices!", 2);

    printf("\nThe interfaces present on the system are:");
    for(temp=interfaces;temp;temp=temp->next)
        printf("\n%d  :  %s",i++,temp->name);
    
    printf("\n");
    exit(0);
}

int main(int argc, char *argv[]){
    bool udp_flag = false;
    bool tcp_flag = false;
    bool icmp_flag = false;
    bool arp_flag = false;
    bool all_flag = true;

    char* device = "";
    char* port = "";
    char* packet_num_string = "";
    char* characters;

    int packet_count = 1;
    int argument;

    // parsing arguments
    while (true){
        int option_index = 0;
        static struct option long_options[] = {
            {"udp", no_argument, NULL, 'u'},
            {"tcp", no_argument, NULL, 't'},
            {"icmp", no_argument, NULL, 'm'},
            {"arp", no_argument, NULL, 'r'},
            {0, 0, 0, 0}
        };

        argument = getopt_long(argc, argv, ":tui:p:n:", long_options, &option_index);
        if (argument == -1)
            break;
        
        switch (argument){

            /*
            * This case allows the usage of -i argument without any value
            * Ispired by: https://stackoverflow.com/questions/19604413/getopt-optional-arguments
            */
            case ':':
                switch (optopt){
                    case 'i':
                        device = "";
                        break;
                    
                    default:
                        err_print("Invalid argument", 1);
                        break;
                }
                break;

            case 'p':
                if(optarg)
                    port = optarg;
                else if(!optarg && NULL != argv[optind] && '-' != argv[optind][0])
                    port = argv[optind++];
                break;

            case 'i':
                if(optarg)
                    device = optarg;
                else if(!optarg && NULL != argv[optind] && '-' != argv[optind][0])
                    device = argv[optind++];
                break;

            case 'n':
                if(optarg)
                    packet_num_string = optarg;
                else if(!optarg && NULL != argv[optind] && '-' != argv[optind][0])
                    packet_num_string = argv[optind++];
                else
                    exit(0);
                // convert packet_num_string to integer
                packet_count = strtol(packet_num_string, &characters, 10);
                
                if (strlen(characters)>0)
                    err_print("-n argument requires an integer value", 10);
                
                if(packet_count < 0){
                    err_print("-n argument requires a positive value", 10);
                }
                break;

            case 't':
                tcp_flag = true;
                all_flag = false;
                break;

            case 'u':
                udp_flag = true;
                all_flag = false;
                break;

            case 'm':
                icmp_flag = true;
                all_flag = false;
                break;

            case 'r':
                arp_flag = true;
                all_flag = false;
                break;

            case '?':
                err_print("Invalid argument", 1);
                break;
                            
            default:
                abort();
        }
    }

    // if device wasn't specified, then print all devices and exit
    if (!strcmp(device, ""))
        print_devices();

    /*************************************
    * Open the device for sniffing
    * Taken from https://www.tcpdump.org/pcap.html 
    */

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        exit(2);
    }

    /*** End of code from https://www.tcpdump.org/pcap.html ***/

    // Creating a filter string for pcap_compile
    char filter[100];

    if(all_flag || (icmp_flag && arp_flag))
        strcpy(filter,"icmp or arp");
    else if(icmp_flag)
        strcpy(filter,"icmp");
    else if(arp_flag)
        strcpy(filter,"arp");
    else
        strcpy(filter,""); //important for strcat

    if(all_flag || ((tcp_flag || udp_flag) && (icmp_flag || arp_flag))){
        strcat(filter," or ");
    }

    if (udp_flag || tcp_flag || all_flag){
        if (strcmp(port, ""))
                strcat(filter,"(");

        if((tcp_flag && udp_flag) || all_flag){
            strcat(filter,"(tcp or udp)");
        }else if (tcp_flag)
            strcat(filter,"tcp");
        else
            strcat(filter,"udp");
        
        if(strcmp(port, "") && (tcp_flag || udp_flag || all_flag)){
            strcat(filter, " and port ");
            strcat(filter, port);
            strcat(filter,")");
        }
        
    }

    /*************************************
    * Set filters
    * Taken from https://www.tcpdump.org/pcap.html 
    */

    struct bpf_program fp;  /* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of the sniffing device */
	bpf_u_int32 net;		/* The IP of the sniffing device */

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
	}

    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        exit(2);
    }

    pcap_loop(handle, packet_count, process_packet, NULL);

    /*** End of code taken from https://www.tcpdump.org/pcap.html  ***/

    return 0;
}
