/*
Author : SiegeBreaker Devs.
*/
#include "RSA_encrypt_decrypt.h"
#include "struct_file.h"
#include "custom_string_manager.h"
#include <pcap.h>

#define SSL_PORT 443

int timeout = 1;


#define DEBUG 0

typedef struct SSL_data_hdr {
    char type;
    short version;
    short length;
} SSL_data_hdr;

typedef struct Reliable_header {
    u_int32_t seq;
    u_int32_t ack;
    long double timestamp;
    u_int32_t type;
    u_int32_t length;
} rel_header;


typedef struct KEY_OBJ_SRT
{
    // Key for encryption-decryption
    char *key_value;
    //Boolean Indicating which kind of encryption-decryption method to perform
    // 0 indicates RSA - public private crypto
    int isRSA_priv;
    //libpcap descriptor for reading data.
    pcap_t *descr;
} KeyObj;


typedef struct {
    char *hostname;
    char *path;
} URL;

struct pseudo {
    unsigned int saddr;
    unsigned int daddr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
};

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
        return -1;
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
        return -1;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handleErrors();
        return -1;
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors();
        return -1;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


long double get_time() {
    struct timeval tv;
    struct timezone tz;
    long double cur_time;

    if (gettimeofday(&tv, &tz) < 0) {
        perror("get_time() fails, exit\n");
        exit(1);
    }

    cur_time = (long double) tv.tv_sec + ((long double) tv.tv_usec / (double) 1000000.0);
    return cur_time;
}


uint32_t parseIPV4string(char *ipAddress) {
    unsigned int ipbytes[4];
    sscanf(ipAddress, "%uhh.%uhh.%uhh.%uhh", &ipbytes[3], &ipbytes[2], &ipbytes[1], &ipbytes[0]);
    return ipbytes[0] | ipbytes[1] << 8 | ipbytes[2] << 16 | ipbytes[3] << 24;
}

u_short in_cksum(register u_short *addr, register int len) {
    register int nleft = len;
    register u_short *w = addr;
    register u_short answer;
    register int sum = 0;

    /*  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += *(u_char *) w;

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);     /* add carry */
    answer = ~sum;        /* truncate to 16 bits */
    return (answer);
}

/* create_ipv4_packet : 
 * description : create the ipv4 packet with the given inputs (very specific , useful for only
 * this program )
 * input:
 * pkt : pointer to the buffer which is to be packetized (expecting a buffer with all zeros)
 * daddr : dest addr
 * saddr : source addr
 * protocol : protocol number (see /etc/protocols)
 * ttl : time to live 
 * frag_off: fragment offset
 * id : id
 * tot : total length 
 * tos : type of service bits
 * ihl : ip header length  (number of 32-bit words)
 */
static inline int
create_ipv4_packet(void *pkt, unsigned int daddr, unsigned int saddr,
                   unsigned char protocol, unsigned char ttl,
                   unsigned short frag_off, unsigned short id,
                   unsigned short tot_len, unsigned char tos,
                   unsigned char ihl) {
    static struct iphdr *iph;
    iph = (struct iphdr *) pkt;
    iph->daddr = daddr;
    iph->saddr = saddr;
    iph->protocol = protocol;
    iph->ttl = ttl;
    iph->frag_off = htons(frag_off);
    iph->id = htons(id);
    iph->tot_len = htons(tot_len);
    iph->tos = tos;
    iph->ihl = ihl;
    iph->version = 4;
    iph->check = 0;
    iph->check = in_cksum((u_short *) iph, sizeof(struct iphdr));
    return 0;
}

unsigned short tcp_sum_calc(unsigned short len_tcp, unsigned int saddr, unsigned int daddr, const unsigned char *buff) {
    struct tcphdr *tcphdr;
    struct pseudo *pseudo;
    unsigned short sum = 0;

    int psize;
    unsigned char *pbuff;

    psize = sizeof(struct pseudo) + len_tcp;
    tcphdr = (struct tcphdr *) buff;
    tcphdr->check = 0;
    pbuff = (unsigned char *) malloc(len_tcp + 12);
    memset(pbuff, 0, 12);
    memcpy(pbuff + sizeof(struct pseudo), buff, len_tcp);
    pseudo = (struct pseudo *) pbuff;
    pseudo->saddr = saddr;
    pseudo->daddr = daddr;
    pseudo->zero = 0;
    pseudo->protocol = IPPROTO_TCP;
    pseudo->length = htons(len_tcp);
    sum = (unsigned short) in_cksum((unsigned short *) pseudo, psize);
    return ((unsigned short) sum);
}

/*create a default tcp packet 
  description : this function is used for creating a complete TCP
                packet ; this internally calls the create_ipv4_packet()
                to create the ipv4 packet
  tot_len : total length field to be passed to the create_ipv4_packet() function
  pkt     : pointer to the buffer which is to be packetized
  urg_ptr : tcp urgent ptr 
  window  : tcp window size
  seq     : tcp sequence number field
  ack_seq : tcp ack_seq field 
  dest    : dest port
  source  : source port
  tcp_syn : syn flag      -- either is being used. when one is used the other isn't. either tcp syn or tcp rst
  tcp_rst : rst flag         is being used one at a time
*/
static inline int
create_tcp_packet(int tot_len, void *pkt, unsigned short urg_ptr,
                  unsigned short window, unsigned int seq,
                  unsigned int ack_seq, int dest,
                  int source, char *self_ip, char *target_ip, int rst) {
    static struct tcphdr *tcph;
    unsigned int id;

    id = random();
    tcph = (struct tcphdr *) pkt;
    tcph->urg_ptr = htons(urg_ptr);
    tcph->window = htons(window);
    tcph->ack_seq = htonl(ack_seq);
    tcph->seq = htonl(seq);
    tcph->dest = htons(dest);
    tcph->source = htons(source);
    tcph->doff = 5;
    if (rst) {
        tcph->fin = 1;
        tcph->rst = 1;
    } else {
        tcph->psh = 1;
        tcph->ack = 1;
    }
    tcph->syn = 0;
    tcph->urg = 0;
    tcph->check = tcp_sum_calc(tot_len - sizeof(struct iphdr), parseIPV4string(self_ip), parseIPV4string(target_ip),
                               (unsigned char *) tcph);
    return 0;
}

char *getip(int ip) {
    char *ipv4 = malloc(100);
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    snprintf(ipv4, 100, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
    return ipv4;
}

/* Callback: Is called whenever a packet is recieved at the raw socket!
   Should be threaded probably.
*/

Sniff_response *callback(char *pkt, int pkt_len, char *self_ip, char *target_ip) {
    struct in_addr ip_addr;
    Sniff_response *sniff;
    static struct iphdr *iph;
    static struct tcphdr *tcph;
    static struct ethhdr *ethh;


    SSL_data_hdr *sslhdr;

    ethh = (struct ethhdr *) pkt;
    iph = (struct iphdr *) (pkt + sizeof(struct ethhdr));

    unsigned long reply_ack = 0, reply_seq = 0;
    char *src_addr = getip(ntohl(iph->saddr));
    char *dst_addr = getip(ntohl(iph->daddr));

    // now parse the TCP header
    tcph = (struct tcphdr *) (pkt + sizeof(struct iphdr) + sizeof(struct ethhdr));

    int sport = ntohs(tcph->source);
    int dport = ntohs(tcph->dest);

    char *ssl_pkt = pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                    sizeof(struct tcphdr);// + 12;  //+12 in case there are TCP options
    //printf("%x %x %x\n", *ssl_pkt, *(ssl_pkt + 1), *(ssl_pkt + 2));

    sslhdr = malloc(sizeof(SSL_data_hdr));

    sslhdr->type = ssl_pkt[0];
    sslhdr->version = ntohs(*(short *) (ssl_pkt + 1));
    sslhdr->length = ntohs(*(short *) (ssl_pkt + 3));


    if (sslhdr->type != 23) {
        if (DEBUG) printf("\n\nReturned because not a SSL data packet!!");
        return NULL; // not a content packet
    }


    //int data_length = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr) - 12;
    int data_length = sslhdr->length;
    unsigned long seq = ntohl(tcph->seq);
    sniff = malloc(sizeof(Sniff_response));
    reply_ack = seq + data_length;
    reply_seq = ntohl(tcph->ack_seq);
    sniff->reply_ack = reply_ack;
    sniff->reply_seq = reply_seq;
    sniff->urg_ptr = ntohs(tcph->urg_ptr);
    sniff->window = ntohs(tcph->window);
    sniff->port = sport;
    sniff->msg = malloc(sslhdr->length + 1);
    sniff->length = sslhdr->length;
    sniff->ip = src_addr;
    memcpy(sniff->msg, ssl_pkt + 5, sslhdr->length);

    return sniff;
}


Sniff_response *decode_salsa(Sniff_response *s, KeyObj *iKey, int isCenter) {

    int plaintext_len;
    char *priv = malloc(256);
    char *decrypted = malloc(256);
    memcpy(priv, s->msg, 256);


    if (iKey->isRSA_priv) {
        //printf("priv : %s\n len %d",priv,s->length);
        plaintext_len = private_decrypt(priv, 256, privateKey, decrypted);
        if (plaintext_len == -1) {
            printLastError("Private Decrypt failed ");
            //exit(0);
            return s;
        }
        //printf("Decrypted content!! %s",decrypted);
        free(s->msg);
        free(priv);
        s->msg = decrypted;
        s->length = plaintext_len;
        return s;
    } else {
        uint8_t *nonce = malloc(17);
        memcpy(nonce, s->msg, 16);
        nonce[16] = 0;
        unsigned char *some = malloc(s->length - 16);
        if (!some) return NULL;
        memcpy(some, s->msg + 16, s->length - 16);
        uint8_t *plain = malloc(s->length - 16 + 256);
        plaintext_len = decrypt(some, s->length - 16, iKey->key_value, nonce, plain);
        if (plaintext_len == -1) {
            free(some);
            return s;
        }

        free(s->msg);
        free(some);
        s->msg = plain;
        s->length = plaintext_len;
        return s;
    }
}


Sniff_response *sniff(pcap_t *descr, char *self_ip, char *target_ip, int decode_content, KeyObj *iKey) {
    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;
    struct pcap_pkthdr hdr;


    char *buf;// = malloc(65536);
    //if  (!buf) return NULL;
    Sniff_response *msg, *resp;
    while (1) {
        if (timeout == 0) {
            //printf("Sniff timeout!\n");
            return NULL;
        }

        buf = pcap_next(descr, &hdr);
        if (buf == NULL)
            continue;
        msg = callback(buf, hdr.len, self_ip, target_ip);
        if (msg != NULL) {
            if (decode_content)
                resp = decode_salsa(msg, iKey, 0);
            //free(buf);
            return resp;
        }
    }
    //free(buf);
    return NULL;
}

Sniff_response *sniff_center(pcap_t *descr, char *self_ip,
                             char *target_ip, int decode_content, KeyObj *iKey, db_mgr *g_db_structure) {

    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;
    struct pcap_pkthdr hdr;


    char *buf;

    Sniff_response *msg, *resp;
    while (1) {
        if (timeout == 0) {
            //printf("Sniff timeout!\n");
            return NULL;
        }

        buf = pcap_next(descr, &hdr);
        if (buf == NULL)
            continue;
        msg = callback(buf, hdr.len, self_ip, target_ip);
        /*
        if( msg!=NULL && msg->ip!=NULL && validate_new_connection( g_db_structure  , msg)  )
        {

        }
        else
        {
        free(msg);
        msg = NULL;
        }
        */
        if (msg != NULL) {
            if (decode_content)
                resp = decode_salsa(msg, iKey, 1);
            //free(buf);
            return resp;
        }

    }
    //free(buf);
    return NULL;
}


/* send_tls_packet: Crafts a "tls" packet, encrypted by the PSK of proxy.
  Called everytime you want to send a packet to the proxy, can be threaded as well */
int send_tls_packet(Sniff_response *resp, char *content, int sock_raw, char *tip, int length, KeyObj *iKey) {


    if (DEBUG)
        printf("Sending pak seq=%ld ack=%ld content-len: %d, tip: %s!\n", resp->reply_seq, resp->reply_ack, length,
               tip);
    char *encrypted = malloc(length + 256);
    int i;
    uint8_t *nonce = malloc(17);
    for (i = 0; i < 16; i++) {
        int r = rand();
        nonce[i] = r % (0xFF + 1);
    }
    nonce[16] = 0;
    int enc_content;

    //printf("\n Lengh before encrypting : %d",length);
    /*if(use_pub_priv)
    {
    enc_content= public_encrypt(content,length,publicKey,encrypted);
          if(enc_content == -1)
    {
        printLastError("Public Encrypt failed ");
        exit(0);
        //return s;
    }
    printf(" content enc : %s \n len : %d",encrypted,enc_content);
          //use_pub_priv=0;
    }
    else*/

    enc_content = encrypt(content, length, iKey->key_value, nonce, encrypted);
    //printf("%d:%d\n", length, enc_content);
    int content_len = enc_content;
    unsigned short tls_length = htons(16 + content_len);
    //printf("Sending tls packet %d %s to %s\n", content_len, tip, content + sizeof(rel_header));
    int pkt_size = sizeof(struct tcphdr) + ntohs(tls_length) + 1 + 2 + 2;
    // create a response packet
    void *tcpip_pkt = malloc(pkt_size);
    memset(tcpip_pkt, 0, pkt_size);

    struct sockaddr_in dest;
    int sklen;
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = inet_addr(tip);
    //printf("Port %d\n", resp->port);
    dest.sin_port = htons(resp->port);
    dest.sin_family = AF_INET;
    sklen = sizeof(struct sockaddr_in);

    create_tcp_packet(pkt_size, tcpip_pkt, resp->urg_ptr,
                      resp->window, resp->reply_seq,
                      resp->reply_ack, resp->port,
                      443, resp->ip, tip, 0);

    // create TLS packet
    char *tls_start = tcpip_pkt + sizeof(struct tcphdr);
    tls_start[0] = 23;    // tls data packet
    tls_start[1] = 0x03; // version
    tls_start[2] = 0x03;
    memcpy(tls_start + 3, &tls_length, 2); // tls length
    srand(time(NULL));


    memcpy(tls_start + 5, nonce, 16); // add nonce in the begginging of packet

    memcpy(tls_start + 5 + 16, encrypted, content_len);
    tryagain:
    if (sendto(sock_raw, tcpip_pkt, pkt_size, 0, (struct sockaddr *) &dest, sklen) < 0) {
        goto tryagain;
        printf("Failed to send packets to the proxy!\n");
        free(encrypted);
        return 0;
    }
    free(encrypted);
    return 1;
}

// set reliable header.
void set_rel_hdr(rel_header *rhdr, u_int32_t seq, u_int32_t ack, long double timestamp, u_int32_t type)
{
    rhdr->seq = seq;
    rhdr->ack = ack;
    rhdr->timestamp = timestamp;
    rhdr->type = type;
}

