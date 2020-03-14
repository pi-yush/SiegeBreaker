
/*
Author : SiegeBreaker Devs.
Purpose : This file contains code responsible to managing "Center" aka center for managing individual connections
 i.e it spawns threads for each individual connection and manages what to pass on to each thread.
*/
#include "custom_base64.h"
#include "custom_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>

#define PORT 443
#define maxsize 65536

// System's IP Address
#define self_ip "192.168.2.5"
// URL to fetch
#define URL_VAL "https://10.1.5.2/test_file.txt"

/**
 * Handles each DR request as seperate thread spawned by Center.
 * This function contains code to be executed by each thread.
 * @param  {void*} _void_thread_mgr Struct containing connection specific params
 * @return {NULL}
 */
void *thread_handler_function(void *_void_thread_mgr) {

    thread_mgr *thMgr = (thread_mgr *) _void_thread_mgr;

    //Create New IP Port entry in Database of active connections and get it's ID
    int db_id = gen_entry_and_add(thMgr->weak_db_ref, (thMgr->last_pkt)->ip, (thMgr->last_pkt)->port);

    //Initialize a new string for passing command line arguments
    char system_str[2048] = {" "};

    int len_base64;
    //Convert string to base64 as string is encrypted and passing encrypted string as command line argument
    //can cause unexpected behaviour.
    char *baseOP = base64((thMgr->last_pkt)->msg, 32, &len_base64);

    // Append other necessary information along with encrypted message to be passed to single connection process.
    printf("Running Single Conn Queue\n");
    int inserted_char = sprintf(system_str, "./single_conn_queue.o \"%lu::%lu::%d::%d::%d::%d::%s::%d::%d::",
                                (thMgr->last_pkt)->reply_ack,
                                (thMgr->last_pkt)->reply_seq,
                                (thMgr->last_pkt)->urg_ptr,
                                (thMgr->last_pkt)->window,
                                (thMgr->last_pkt)->port,
                                (thMgr->last_pkt)->length,
                                (thMgr->last_pkt)->ip,
                                0,
                                len_base64
    );

    //Add additional stuff to passed on string.
    strncpy(&system_str[inserted_char], baseOP, len_base64);
    inserted_char += len_base64;

    //Adding seperator
    strncpy(&system_str[inserted_char], "::", 2);

    inserted_char += 2;


    int size_msg = strlen(&((thMgr->last_pkt)->msg[32]));


    strncpy(&system_str[inserted_char], &((thMgr->last_pkt)->msg[32]), size_msg);

    strncpy(&system_str[inserted_char + size_msg], "::\"", 3);


    strncpy(&system_str[inserted_char + size_msg + 3], "  ;\0", 4);


    int end = inserted_char + size_msg + 3 + 4;

    printf("CMD : ");
    //Check if we have encountered any unexpected string, if we do, abort.
    //TODO We should raise exception here of some sort as this could potentially compromise successful
    // connection establishment
    int i;
    for (i = 0; i < end; ++i) {

        if (system_str[i] == '&')
            break;

        if (system_str[i] == '\0' || system_str[i] == '\n') {
            printf("culprit at index %d", i);
        }

    }
    printf("\n");
    //Flushing output of previous logging.
    fflush(stdout);

    int delay = 10000;
    //Adding some delay for us to analyse logged string
    while (delay--) {}
    //Spawn new process and expect it to handle connection from now on.
    system(system_str);


    return NULL;
}

int main() {

    // Init descriptors
    int server_fd, new_socket, valread;
    char buffer[maxsize] = {0};

    // Initialize libpcap related variables.
    // TODO : Pull out interface name programmatically.
    char dev[] = {"eth0"};
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;
    struct bpf_program filter;
    // Init empty filter
    char filter_exp[1024] = {""};

    // Look for packets destined to me{see self_ip} , My system's IP is 192.168.2.5;
    // We don't ICMP packets and size should be greater than 150 - a rough estimate for decoy routing requests.
    int bytes_written = sprintf(filter_exp,
                                "dst port %d and dst host 192.168.2.5 and not src host 192.168.2.4 and not icmp and greater 150",
                                443);

    //Log filter expression for verification.
    printf("filter_exp %s\n", filter_exp);

//    char filter_exp[] = "dst port 443";


    bpf_u_int32 ipaddr;

    u_char *ptr; /* printing out hardware header info */

    printf("DEV: %s\n", dev);

    /* open the device for sniffing.
       pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
       char *ebuf)

       snaplen - maximum size of packets to capture in bytes
       promisc - set card in promiscuous mode?
       to_ms   - time to wait for packets in miliseconds before read
       times out
       errbuf  - if something happens, place error string here

       Note if you change "prmisc" param to anything other than zero, you will
       get all packets your device sees, whether they are intendeed for you or
       not!! Be sure you know the rules of the network you are running on
       before you set your card in promiscuous mode!!     */


    descr = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);

    if (descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    if (pcap_compile(descr, &filter, filter_exp, 0, ipaddr) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(descr));
        return 2;
    }
    if (pcap_setfilter(descr, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(descr));
        return 2;
    }

    //Begin reading via libpcap

    printf("-> Starting Reading from SOCK_RAW Socket %d\n", PORT);

    //Initializing 10 threads for now
    //TODO : Allow dynamic allocation of thread instances.
    pthread_t inc_x_thread[10];

    int g_thread_counter = 0;
    db_mgr *g_db_structure = init_db();


// listen for new connections indefinitely.
    while (1) {

        //Allocate required strcutures.
        KeyObj *iKey = (KeyObj *) malloc(sizeof(KeyObj));
        iKey->key_value = (char *) malloc(sizeof(char) * 32);
        iKey->isRSA_priv = 1;


        printf("Listening....\n");
        //Sniff decoy routing request and get parsed data as return value;
        Sniff_response *packtObj = sniff_center(descr, self_ip, NULL, 1, iKey, g_db_structure);


        if (packtObj == NULL) continue;

        //Copy Packets's message into key value.
        strncpy(iKey->key_value, packtObj->msg, 32);

        if (!packtObj->msg || packtObj->msg[32] != 'h')
        {
            printf("Invalid url inside center  \n");
            fflush(stdout);

            continue;
        }

        iKey->isRSA_priv = 0;

        //Logging captured Decoy Routing Request details
        printf("-> printing packet\n");
        printf("-> packet ip : %s\n", packtObj->ip);
        printf("-> port : %d\n", packtObj->port);

        printf("-> D  port : %d\n", packtObj->dport);

        printf("-> seq : %lu\n", packtObj->reply_seq);
        printf("-> ack : %lu\n", packtObj->reply_ack);

        if (validate_new_connection(g_db_structure, packtObj))
        {
            //Threads arguments setup ;
            thread_mgr *thMgr = (thread_mgr *) calloc(sizeof(thread_mgr), 1);
            thMgr->last_pkt = NULL;
            thMgr->last_pkt = (packtObj);
            //Setting socket id to be zero for now ; to be assigned later.
            thMgr->socket_id = 0;
            thMgr->weak_db_ref = g_db_structure;

            //Create thread and pass on data structure to thread.
            if (pthread_create(&(inc_x_thread[g_thread_counter]), NULL,
                               thread_handler_function, &(*thMgr))) {
                fprintf(stderr, "Error creating thread\n");
                return 1;
            }

        }

    }

}

