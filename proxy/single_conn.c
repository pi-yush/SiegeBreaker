
/*
Author : SiegeBreaker Devs.
 Purpose : This file contains code responsible to managing "Single Connections" aka this is the thread spawned
 by center for managing individual connections
*/

#include <assert.h>
#include "custom_base64.h"
#include "custom_parser.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <pthread.h>
#include <math.h>
#include <semaphore.h>


#define TIMEOUT_SECS 4
#define CHUNK_SIZE 1024
#define DEBUG 0

// This system's IP
uint8_t self_ip[32] = "192.168.2.5";

// Over Destination IP
#define OD_IP "192.168.2.4"

#define IS_PRINTF_ON 1

int no_of_packets = 0;
int MSS = 1024;
long double RTT, prev_RTT;
int ssthresh = 8;
int curr_size = 1;
int window_size = 1;
int prev_size = 1;
int a_param = 0;
long double BWE = 0, BWE_p = 0;
long double bk, bk_p;
long double alpha = 0.5;
int state = 1;  //  1 for slow start

pthread_mutex_t mutex; // mutex to be shared between client and proxy threads
pthread_cond_t condc, condp;
sem_t sem;

typedef struct packet {
    char content[1024];
    struct packet *next;
    int length;
    Sniff_response *resp;
} pkt;

pkt *head;
pkt *tail;

typedef struct {
    SSL_CTX *ctx;
    Sniff_response *resp;
} ODC;

/* Start point of functions and code for proxy to client communication */

/*  
    Additional header for providing reliability
*/

// Signal handler for sigalarm
void sig_handler(int signo) {
    timeout = 0;
    state = 0;
    //printf("Timeout Occured\n");
    //alarm(2);
    if (curr_size < ssthresh) {
        a_param++;
        if (a_param > 4) {
            a_param = 4;
        }
    }

    if (curr_size >= ssthresh)
        a_param = 1;

    if (prev_size > ssthresh)
        curr_size >>= 1;
    else
        curr_size--;

    if (!curr_size)
        curr_size = 1;


    if (BWE) {
        if (DEBUG) printf("BWE : %Lf\n", BWE);
        if (DEBUG) printf("RTT: %Lf\n", prev_RTT);
        if (DEBUG) printf("a_param : %d\n", a_param);
        if (DEBUG) printf("adjusted cwin : %d\n", curr_size);
        if (DEBUG) ssthresh = (unsigned int) floor((BWE * prev_RTT) / (MSS * a_param));
        if (DEBUG) printf("\t\t\t ADJUSTED ssthresh : %d\n", ssthresh);
    }

    if (DEBUG) printf("BWE : %Lf\n", BWE);
    if (DEBUG) printf("RTT: %Lf\n", prev_RTT);
    if (DEBUG) printf("a_param : %d\n", a_param);


    if (ssthresh < 2) {
        ssthresh = 2;
        curr_size = 1;
    }
    window_size = curr_size;
    if (DEBUG) printf("\t\t\t ADJUSTED ssthresh : %d\n", ssthresh);
    ualarm(0, 0);
    //alarm(0);
}


// Set Reliable Header Fields
void set_rel_header(rel_header *rhdr, u_int32_t seq, u_int32_t ack, long double timestamp, u_int32_t type,
                    u_int32_t length) {
    rhdr->seq = seq;
    rhdr->ack = ack;
    rhdr->timestamp = timestamp;
    rhdr->type = type;
    rhdr->length = length;
}

/**
 * Sends data from proxy to client for each connection
 * @param  {void*} key object pointer which contains key specific data.
 * @return {void}
 */

void *proxy_to_client(void *_void_key_obj_ptr)
{
    KeyObj *iKey = (KeyObj *) _void_key_obj_ptr;


    pkt *curr;//=(pkt *)malloc(sizeof(pkt));
    pkt *curr_posi, *curr_acked, *del;
    //start=curr;
    long double t0 = get_time();
    pcap_t *descr = (pcap_t *) iKey->descr;
    usleep(500000);
    //sleep(1);
    int psize, last_ack = 1, oldopts, first_iter = 1;

    unsigned int snd_bufsize = 10000, rcv_bufsize = 65535;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        printf("Socket Error!\n");
        return NULL;
    }

    if (setsockopt(s, 0, SO_SNDBUF, &snd_bufsize, sizeof(unsigned int)) <
        0)
        printf("\n setsockopt(SO_SNDBUF) fails : %s", strerror(errno));

    if (setsockopt(s, 0, SO_RCVBUF, &rcv_bufsize, sizeof(unsigned int)) <
        0)
        printf("\n setsockopt(SO_RCVBUF) fails : %s", strerror(errno));

    //Datagram to reprepent the packet
    char datagram[1024], source_ip[32], *data, *pseudogram, *reply, *rec_data;
    reply = malloc(1024);
    if (reply == NULL) {
        printf("Memory error!\n");
        return NULL;
    }

    //zero out the packet buffer
    memset(datagram, 0, 1024);
    memset(reply, 0, 1024);

    //start->hdr = (rel_header *)datagram;
    int var = 0;
    while (head == NULL) {
        printf("Waiting for data!\n");
        static struct timespec time_to_wait = {0, 0};
        time_to_wait.tv_sec = get_time() + TIMEOUT_SECS;
        //int r = pthread_cond_timedwait(&condc, &mutex, &time_to_wait);
        int r = sem_timedwait(&sem, &time_to_wait);
        if (r == ETIMEDOUT || r == -1) {
            printf("Wait timed out! No data from OD\n");
            var++;
        }
        if (var > 1)
            pthread_exit(NULL);
    }
    curr_posi = head;
    curr_acked = head;

    struct sockaddr_in sin, cli_addr;
    rel_header *rhdr = (rel_header *) head->content, *rec_rhdr = (rel_header *) malloc(sizeof(rel_header));
    rec_rhdr->ack = 0;
    rhdr->seq = 1;
    rhdr->ack = 0;
    rhdr->timestamp = get_time();
    rhdr->type = 2;

    signal(SIGALRM, sig_handler);
    int bytes = 1, i = 1;
    int first = 1, expected_ack = 1, next_ack, offset;
    //int curr_posi=0;//=ftell(ifp);
    int test = 1, retransmit = 0, type = 2, count = 1;
    //printf("%d\n",sizeof(rel_header));
    Sniff_response *client_resp;
    while (1) {

        //Send the packet
        RTT = 0;
        retransmit:
        while (window_size--) {

            int semval;
            bytes = curr_posi->length + sizeof(rel_header);
            rhdr = (rel_header *) curr_posi->content;
            set_rel_header(rhdr, expected_ack, 2, get_time(), type, bytes);
            sem_getvalue(&sem, &semval);

            no_of_packets--;
            if (no_of_packets <= 1) {
                rhdr->type = 10;
                printf("Total time spent in sending : %Lf", get_time() - t0);

            }

            if (DEBUG) printf("sending TLS packet to %s!\n", curr_posi->resp->ip);
            send_tls_packet(curr_posi->resp, curr_posi->content, s, curr_posi->resp->ip,
                            curr_posi->length + sizeof(rel_header), iKey);
            if (DEBUG) printf("\n%d : %d : %Lf : %d\n", rhdr->seq, rhdr->ack, rhdr->timestamp, rhdr->type);
            expected_ack += rhdr->length;
            if (first) {
                next_ack = expected_ack;
                first = 0;
            }

            if (curr_posi->next == NULL && no_of_packets > 1) {
                while (curr_posi->next == NULL);
                //printf("\n Waiting for Datain queue!");
            } else if (no_of_packets < 2) {
                kill(getpid(), SIGKILL);
            } else {}


            curr_posi = curr_posi->next;

        }
        ualarm(500000, 0);

        duplicate:
        if (DEBUG) printf("Waiting for pkt from client!\n");
        //************************libpcap*************************


        client_resp = sniff(descr, self_ip, NULL, 1, iKey);

        if (timeout == 0) {
            int file_offset;
            retransmit = 1;
            printf("Retransmitting\n");
            timeout = 1;
            if (expected_ack > 1025)
                expected_ack = offset;

            curr_posi = curr_acked;
            //set_rel_header(rhdr,((curr_size-window_size)*(bytes+sizeof(rel_header)))+offset,2,(int)time(NULL),2);
            goto retransmit;
        }
        if (client_resp == NULL) {
            printf("Got no response from client.\n");
            return NULL;
        }
        reply = client_resp->msg;
        if (DEBUG) printf("ACK Received before timeout!\n");
        rec_rhdr = (rel_header *) reply;
        rec_data = reply + sizeof(rel_header);
        RTT = RTT + (get_time() - rec_rhdr->timestamp);
        if (DEBUG)
            printf("Printing header before freeing   %d : %d : %Lf : %d\n", rec_rhdr->seq, rec_rhdr->ack,
                   rec_rhdr->timestamp, rec_rhdr->type);
        offset = rec_rhdr->ack;
        last_ack = rec_rhdr->ack;
        if (last_ack == next_ack) {
            del = curr_acked;
            curr_acked = curr_acked->next;
            free(del);

            if (DEBUG) printf("Freed packet %d!!\n", count++);
            if (curr_posi != NULL)
                next_ack = next_ack + curr_posi->length + sizeof(rel_header);
            //if(DEBUG || 1) printf("Next ack = %d\n",next_ack);
            //continue;
        }
        if (last_ack == expected_ack) {
            ualarm(0, 0);

            RTT = RTT / curr_size;
            //printf("RTT : %Lf\n",RTT);
            bk = (long double) ((2 * MSS) / RTT);
            if (!first_iter)
                BWE = (long double) ((alpha * BWE_p) + ((1 - alpha) * ((bk + bk_p) / 2)));
            else {
                BWE = bk;
                first_iter = 0;
            }
            if (DEBUG) printf("\n bk=%Lf", bk);
            bk_p = bk;
            BWE_p = BWE;
            if (state) {
                prev_size = curr_size;
                curr_size *= 2;
            } else {
                if (curr_size < ssthresh) {
                    prev_size = curr_size;
                    curr_size = curr_size << 1;

                } else {
                    prev_size = curr_size;
                    curr_size++;
                }
            }
            window_size = curr_size;
            if (DEBUG) printf("\nws=%d\n", window_size);
            prev_RTT = RTT;
            if (rhdr->type == 10 || curr_posi == NULL)
                //exit(0);
                return NULL;

        } else
            goto duplicate;

    }
    close(s);
    return 0;
}

/* End of proxy to client code  */

URL *parse_url(char *url) {
    URL *u = malloc(sizeof(URL));
    u->hostname = malloc(100);
    u->path = malloc(100);
    if (!u->hostname) return NULL;
    if (!u->path) return NULL;
    sscanf(url, "https://%99[^/]/%99[^\n]", u->hostname, u->path);
    if (DEBUG) printf("Parsed url %s: %s,%s\n", url, u->hostname, u->path);
    return u;
}

void add_pkt(char *content, Sniff_response *resp, int length) {
    if (head == NULL) {
        head = malloc(sizeof(pkt));
        if (head == NULL) {
            printf("Memory error! in add_pkt");
            return;
        }
        if (length > 1024) {
            printf("Data too bif in add_pkkt!\n");
        }
        tail = head;
        head->resp = resp;
        head->next = NULL;
        head->length = length;
        memcpy(head->content + sizeof(rel_header), content, length);
        head->content[1023] = 0;
    } else {
        tail->next = malloc(sizeof(pkt));
        if (!tail->next) return;
        tail->next->resp = resp;
        tail->next->length = length;
        memcpy(tail->next->content + sizeof(rel_header), content, length);
        tail->next->next = NULL;
        tail = tail->next;
    }
}


/**
 * Pulls OD content from SSL Context and Packet passed via struct odc.
 * @param  {void*} odc Struct containing SSL context and Packet.
 * @return {void}
 */
void *get_od_content(void *odc) {
    //printf("In od content! %p\n", odc);
    ODC *o = (ODC *) odc;
    Sniff_response *resp = (Sniff_response *) o->resp;
    if (resp == NULL || resp->msg == NULL) {
        printf("Invalid resp object in get_od_content\n");
        return NULL;
    }
    //printf("od content: %s\n", resp->msg);
    struct hostent *host;
    struct sockaddr_in addr;
    SSL *ssl;
    if (strncmp(resp->msg + 32, "https://", 8) != 0) {
        printf("Error in gettng CD content!!");
        return NULL;
    }
    URL *u = parse_url(resp->msg + 32);
    if (!u) return NULL;

    //SSL initialization
    BIO *bio;
    SSL_CTX *ctx = (SSL_CTX *) o->ctx;
    ssl = SSL_new(ctx);
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    char con_str[200];
    snprintf(con_str, 200, "%s:https", u->hostname);
    BIO_set_conn_hostname(bio, con_str);
    if (BIO_do_connect(bio) <= 0) {
        printf("Can't connect to OD\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }


    char *real_req = malloc(300);
    char *req = "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n";
    sprintf(real_req, req, u->path, u->hostname);
    //printf("%s\n", real_req);
    int req_len = strlen(real_req);
    BIO_write(bio, real_req, req_len);
    int SSL_CHUNK = CHUNK_SIZE - sizeof(rel_header);
    char *od_resp = malloc(CHUNK_SIZE);
    int i = SSL_CHUNK;
    //printf("SSL Chunk size = %d",SSL_CHUNK);
    int total = 0;
    long double t0 = get_time(), t1, t2 = 0.0, t3;
    long long int first = 1, cont_len = 0;

    while (i > 0) {
        memset(od_resp, 0, SSL_CHUNK);
        //printf("Blocking!\n");
        i = BIO_read(bio, od_resp, SSL_CHUNK);
        t2 = t2 + get_time() - t1;
        t3 = get_time() - t1;

        if (first) {
            long double t = get_time();
            int fd;
            fd = open("Response", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (fd == -1) {
                printf("Cannot open output file\n");
                return 0;
            }
            write(fd, od_resp, SSL_CHUNK);
            close(fd);

            FILE *fp;
            char cont[100];
            //int i;


            fp = popen("/bin/cat Response | grep -a Content-Length | cut -d \" \" -f 2", "r");
            if (fp == NULL) {
                printf("Failed to run command\n");
                //exit(1);
            }


            while (fgets(cont, sizeof(cont) - 1, fp) != NULL) {
                cont_len = atoi(cont);
                printf("Content-Length : %lld\n", cont_len);
            }

            pclose(fp);
            first = 0;

            //cont_len = 20000002;

            no_of_packets = (cont_len / SSL_CHUNK);
            if (cont_len % SSL_CHUNK > 0)
                no_of_packets += 1;

            total += i;
            pthread_mutex_lock(&mutex);
#ifdef IS_PRINTF_ON
            printf("I am adding pkt!\n");
#endif
            add_pkt(od_resp, resp, i);
            //if (DEBUG)
            //printf("added pkt!\n");
            pthread_mutex_unlock(&mutex);
            sem_post(&sem);

            //printf("\n Time spent in extracting content length : %Lf \t No_ofPackets : %d\n",get_time()-t,no_of_packets);
        } else {
            total += i;
            pthread_mutex_lock(&mutex);
            //if (DEBUG) printf("I am adding pkt!\n");
            add_pkt(od_resp, resp, i);
            //if (DEBUG)
            //printf("added pkt!\n");
            pthread_mutex_unlock(&mutex);
            sem_post(&sem);
        }
        if (total == cont_len || cont_len < SSL_CHUNK) {
            printf("\n Last packet!");
            break;
        }


    }
#ifdef IS_PRINTF_ON
    //printf("\nTime to download and make queue : %Lf\n Time to just read : %Lf \n\n Time for last read : %Lf",get_time()-t0,t2,t3);
    //printf("Goodbye OD %d; total: %d\n", i, total);
#endif
    pthread_cond_signal(&condc);  /* wake up consumer */
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return NULL;
}


/**
 * Two utility functions to parse Int and unsigned long
 * @param  {char*} string to be parsed
 * @return {int or unsigned long : based on function name}
 */
int make_string_to_int(char *myarray) {
    int i;
    sscanf(myarray, "%d", &i);
    return i;
}
unsigned long make_string_to_uL(char *myarray) {
    unsigned long i;
    sscanf(myarray, "%lu", &i);
    return i;
}

/**
 * Tokenizes string literal based on demilitor, which is assumed to be ::
 * Moreover, this functions assumes that string ends with delim ::
 * Thus, asd::ASd::asd:: will work but asd:Asd::asd will NOT.
 * @param  {const chat*} my_str_literal String to be parsed.
 * @return {char**} pointer to pointer containing parsed string.
 */

char **tokenize_with_sep(const char *my_str_literal) {

    char **retString = (char **) malloc(10);

    int tot_size = strlen(my_str_literal);
    int index = 0;

    char *cpy = strdup(my_str_literal);

    int last_index = 0;
    int i;

    for (i = 0; i < tot_size;) {
        if ((cpy[i] == ':' && cpy[i + 1] == ':')
            //|| cpy[i+1] == '\0'
                ) {
            (retString[index]) = (char *) malloc(i - last_index + 1);

            strncpy(retString[index], &cpy[last_index], i - last_index);


#ifdef IS_PRINTF_ON
            printf("%d %d %s\n",  last_index , i , retString[index]);
#endif

            last_index = i + 2;
            i = last_index;
            index++;
        } else
            i++;
    }

    return retString;
}

/**
 * Parses command line arguments sent by center whilst spawning new process.
 * @param  {Sniff_response*} packtObj Struct containing per packet params
 * @return {void}
 */

Sniff_response *parse_cmd_line_args(int argc, char *argv[]) {

    Sniff_response *packtObj = (Sniff_response *) malloc(sizeof(Sniff_response));

//     ypedef struct SNIFF_RESPONSE {
//   char *msg;
//   unsigned long reply_ack;
//   unsigned long reply_seq;
//   int urg_ptr;
//   int window;
//   int port;
//   int length;
//   char *ip;
// } Sniff_response;

#ifdef IS_PRINTF_ON
    printf("Proceeding with parsing\n");
#endif

    packtObj->reply_ack = make_string_to_uL(argv[0]);
    packtObj->reply_seq = make_string_to_uL(argv[1]);
    packtObj->urg_ptr = make_string_to_int(argv[2]);
    packtObj->window = make_string_to_int(argv[3]);
    packtObj->port = make_string_to_int(argv[4]);
    packtObj->length = make_string_to_int(argv[5]);
    packtObj->ip = argv[6];
    //Raw Socket is at 7th position
    int len_base64 = make_string_to_int(argv[8]);
    char *baseOP = argv[9];
    int ubLen;
    // Revert back base64 encoding
    unsigned char *unBaseOp = unbase64(baseOP, len_base64, &ubLen);

    if (ubLen != 32) {

        printf(" KEY DECRPT FAILED\n");
        exit(0);

    }
    char *url_string = argv[10];
    int len_url = strlen(url_string);

    char *combined_msg = (char *) malloc(sizeof(char) * (len_url + len_base64));

    strncpy(combined_msg, unBaseOp, 32);

    strncpy(&(combined_msg[32]), url_string, len_url);

    packtObj->msg = combined_msg;


    return packtObj;

}

/**
 * Displays contents of packet captured via sniffing
 * @param  {Sniff_response*} packtObj Struct containing per packet params
 * @return {void}
 */
void display_packet(Sniff_response *packtObj) {
    printf("Single Connection");
    printf("-> printing packet :\n");
    printf("-> packet msg : %s\n", packtObj->msg);
    printf("-> ack : %lu\n", packtObj->reply_ack);
    printf("-> seq : %lu\n", packtObj->reply_seq);
    printf("-> ptr %d window : %d\n", packtObj->urg_ptr, packtObj->window);
    printf("-> port : %d length: %d\n", packtObj->port, packtObj->length);
    printf("-> packet ip : %s\n", packtObj->ip);
}


int main(int argc, char *argv[])
{
    if (argc != 2) {
#ifdef IS_PRINTF_ON
        printf(" argc %d\n", argc);
        printf("Usage: sudo ./single_conn  reply_ack  reply_seq  urg_ptr  window        port  length  ip sock_raw  len_base64 base64String URL\n");
#endif
        return -1;
    }
    char **argumentValue = tokenize_with_sep(argv[1]);
    int x = 0;

#ifdef IS_PRINTF_ON
    for (x = 0; x < 9; x++)
        printf(" %d %s", x, argumentValue[x]);
#endif
    Sniff_response *resp = parse_cmd_line_args(argc, argumentValue);
    strcpy(self_ip, resp->ip);
    printf("System IP = %s\n", self_ip);

#ifdef IS_PRINTF_ON
    printf("-> printing packet :\n");
#endif

    display_packet(resp);

    pthread_t od_thread, client_thread;
    head = NULL;
    tail = head;
    int i;
    int sd;
    BIO *outbio = NULL;

    SSL_CTX *ctx;
    char *req;
    int req_len;
    char certs[] = "/etc/ssl/certs/ca-certificates.crt";
    int bytes;
    char buf[128];

    // added this to test
    BIO *certbio = NULL;
    X509 *cert = NULL;
    X509_NAME *certname = NULL;
    BIO *outbio2 = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (SSL_library_init() < 0) {
        BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
    }

    const SSL_METHOD *method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    memset(buf, '\0', sizeof(buf));
    if (IS_PRINTF_ON) printf("\nSniffing for responses!\n");


    // Intialization of libpcap
    // TODO : Pull out name of interface programmatically.
    char dev[] = {"eth0"};
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct bpf_program filter;
    char filter_exp[1024] = {""};

    int bytes_written = sprintf(filter_exp, "dst port %d and src port %d and src host %s",
                                443, resp->port, resp->ip);

#ifdef IS_PRINTF_ON
    printf("filter_exp %s\n", filter_exp);
#endif

    bpf_u_int32 ipaddr;

    u_char *ptr; /* printing out hardware header info */

#ifdef IS_PRINTF_ON
    printf("DEV: %s\n", dev);
#endif

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


    descr = pcap_open_live(dev, BUFSIZ, 0, 500, errbuf);

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

    //Only Need to process single connection
    KeyObj *iKey = (KeyObj *) malloc(sizeof(KeyObj));
    iKey->key_value = (char *) malloc(sizeof(char) * 32);
    iKey->isRSA_priv = 1;




    strncpy(iKey->key_value, resp->msg, 32);

    if (!resp->msg || resp->msg[32] != 'h')
    {
        printf("Invalid url in single_conn -> %s\n", &resp->msg[32]);
        exit(0);
    }
    iKey->isRSA_priv = 0;

#ifdef IS_PRINTF_ON
    printf("Response Message : %s\n", resp->msg + 32);
#endif

    int pkt_size = sizeof(struct tcphdr);
    char *tpkt = malloc(pkt_size);
    struct sockaddr_in dest;
    int sklen;
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = inet_addr(OD_IP);
    dest.sin_port = htons(443);
    dest.sin_family = AF_INET;
    sklen = sizeof(struct sockaddr_in);

    create_tcp_packet(pkt_size, tpkt, resp->urg_ptr,
                      resp->window, resp->reply_seq,
                      resp->reply_ack,
                      resp->port, SSL_PORT, resp->ip, OD_IP, 1);

    printf("Sending rst to OD %s. port: %d\n", OD_IP, resp->port);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        printf("Socket Error!\n");
        return 1;
    }


    if (sendto(sock, tpkt, pkt_size, 0, (struct sockaddr *) &dest, sklen) < 0)
    {
        printf("Failed to send rst packet to the OD!\n");
        return 0;
    }
    close(sock);
    iKey->descr = descr;

    ODC *od_content = malloc(sizeof(ODC));
    if (od_content == NULL)
    {
        printf("No more memory!\n");
        return 1;
    }
    od_content->ctx = ctx;
    od_content->resp = resp;
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&condc, NULL);    /* Initialize consumer condition variable */
    pthread_cond_init(&condp, NULL);    /* Initialize producer condition variable */


    pthread_create(&od_thread, NULL, get_od_content, od_content);
    pthread_create(&client_thread, NULL, proxy_to_client, &(*iKey));
    pthread_join(od_thread, NULL);
    pthread_join(client_thread, NULL);
    free(od_content);


    pthread_mutex_destroy(&mutex);  /* Free up the_mutex */
    pthread_cond_destroy(&condc);   /* Free up consumer condition variable */
    pthread_cond_destroy(&condp);   /* Free up producer condition variable */
    //  close(sd);
    SSL_CTX_free(ctx);
    return 0;
}



