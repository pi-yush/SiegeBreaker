/*
 * Author : SiegeBreaker Devs
 * Purpose : This file contains code of SiegeBreaker client and demonstrates it's protocol while using email based client
 * available inside webmail directory i.e client_email.py
 */

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
#include <netinet/tcp.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "siegebreaker_c.h"


//#define DEBUG 0
char *target_ip;
//This is client's IP
#define self_ip "192.168.2.3"

/*
 * Client's Main function : Responsible for actual communication as a anti censorship solution.
 * Please note that this uses webmail based email client_email.py for email communication and then listens for packets.
 * Example Usage : sudo ./client.o PROXY_IP 443 URL TIMEOUT
 * You may refer to README for details.
 */
int main(int argc, char *argv[])
{
    if (argc != 5) {
        printf("Usage: ./client <OD> <OD_port> <CD URL> <Timeout_value>\n");
        return -1;
    }
    int i;
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    BIO *outbio = NULL;

    SSL_CTX *ctx;
    SSL *ssl;
    char *req;
    int req_len;
    char *hostname = argv[1];
    target_ip = argv[1];
    int port = atoi(argv[2]);
    int bytes;
    char *url = argv[3];
    char initial_packet[100];
    char buf[128];
    unsigned int snd_bufsize = 1000000, rcv_bufsize = 1000000;

    // init openssl
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

    // connect to Overt destination
    host = gethostbyname(hostname);
    sd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *) (host->h_addr);

    //Set up SSL connection
    if (connect(sd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        BIO_printf(outbio, "%s: Cannot connect to host %s [%s] on port %d.\n", argv[0], hostname,
                   inet_ntoa(addr.sin_addr), port);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sd);
    SSL_connect(ssl);

    unsigned char out[32], out1[32], out2[200];
    size_t indx;
    SSL_get_client_random(ssl, out, 32);

    SSL_get_server_random(ssl, out, 32);
    SSL_SESSION_get_master_key(SSL_get_session(ssl), out1, 48);
    out1[32] = '\0';
    printf("\n");
    strncpy(key, out1, 32);

    // Send an initial GET request
    req = "GET / HTTP/1.1\r\nHost: 192.168.2.4\r\n\r\n";
    req_len = strlen(req);
    SSL_write(ssl, req, req_len);
    memset(buf, '\0', sizeof(buf));

    // Wait for response, and start crafting decoy packets
    printf("\nSniffing for responses!\n");
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); // make sure this is the only raw_socket in use
    if (sock_raw < 0) {
        printf("Socket Error!\n");
        return 1;
    }

    int optval = 0, socklen = 4;
    if (getsockopt(sock_raw, SOL_SOCKET, SO_RCVBUF, &optval, &socklen) < 0)
        printf("getsock Fails 1\n");
    printf("RCV Buffer size before Setsockopt : %d\n", optval);

    if (setsockopt(sock_raw, 0, SO_SNDBUF, &snd_bufsize, sizeof(unsigned int)) <
        0)
        printf("\n setsockopt(SO_SNDBUF) fails : %s", strerror(errno));

    if (setsockopt(sock_raw, 0, SO_RCVBUF, &rcv_bufsize, sizeof(unsigned int)) <
        0)
        printf("\n setsockopt(SO_RCVBUF) fails : %s", strerror(errno));

    optval = 0;
    if (getsockopt(sock_raw, SOL_SOCKET, SO_RCVBUF, &optval, &socklen) > 0)
        printf("getsock fails 2\n");
    printf("RCV Buffer size : %d", optval);


    Sniff_response *resp = sniff(sock_raw, self_ip, target_ip, 0);

    char *str = (char *) malloc(100);
    int len;
    len = snprintf(str, 100, "../webmail/client_send.py 192.168.2.4 192.168.2.4 %s %d", argv[4], resp->port);
    printf("\n%s\n",str);
    system(str);

    int fd;
    fd = open("client_output", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1) {
        printf("Cannot open output file\n");
        return 0;
    }
    rel_header *rhdr;
    char *data;
    int total = 0;//,cont_len=0;
    int addr_size;
    setvbuf(stdout, NULL, _IONBF, 0);
    bytes = 1;
    int flag = 0;
    int count = 0;

    sprintf(initial_packet, "%s%s", out1, url);

    //Display Initial TLS packet before sending
    printf("Initial : %s\n key : %s\n", initial_packet + 32, out1);

    //Send actual TLS packet.
    send_tls_packet(resp, initial_packet, sock_raw, target_ip, strlen(url) + 32 + 1);

    long double t0 = get_time();

    int pkt_count = 0;
    while (1) {
        pid_t pid;
        Sniff_response *sr = sniff(sock_raw, self_ip, NULL, 1);
        sr->port = resp->port;
        if (sr == NULL) continue;
        char *buff = sr->msg + sizeof(rel_header);
        rel_header *rhdr = malloc(sizeof(rel_header));
        memcpy((char *) rhdr, sr->msg, sizeof(rel_header));
        if (rhdr->type == 10)

        data = buff;
        if (rhdr->type > 10) { // check for noise!
            free(sr->msg);
            free(sr);
            continue;
        }
        if (DEBUG) printf("Got seq: %d, length: %d\n", rhdr->seq, rhdr->length);
        if (rhdr->seq == total + 1)
        {
            pkt_count++;
            if (DEBUG) printf("\nReceivd header \t%d : %d : %Lf : %d : %d\n", rhdr->seq, rhdr->ack, rhdr->timestamp,
                       rhdr->type, rhdr->length);
            bytes = rhdr->length;
            total += bytes;


            write(fd, data, bytes - sizeof(rel_header));
            if (DEBUG)
            {
                printf("wrote_data %d:bytes %d:total %d:", count++, bytes, total);
            }

        }


        set_rel_hdr(rhdr, 1, total + 1, rhdr->timestamp, rhdr->type);
        if (DEBUG) printf("\nSent Header\t%d : %d : %Lf : %d\n", rhdr->seq, rhdr->ack, rhdr->timestamp, rhdr->type);
        if (rhdr->type == 10)
        {
            char *msg = "Exit";
            rhdr->type = 10;
            char *some = malloc(2048);
            memset(some, 0, 976);
            memcpy(some, rhdr, sizeof(rhdr));
            strcpy(some + sizeof(rhdr), msg);
            send_tls_packet(sr, some, sock_raw, target_ip, sizeof(rhdr) + strlen(msg));
            free(some);
            long double total_time = get_time() - t0;
            long double data_rate = total / (total_time * 1000);
            //At the very least, we should output File Download time and size.
            printf("\n Total Bytes downloaded : %d\n Total time to download file : %Lf\n Data rate %Lf KBps\n", total,
                   total_time, data_rate);

            close(fd);
            exit(0);
            while (1);
            break;
        }

        if (rhdr->type == 2) {

            char *reply = malloc(1028);
            memcpy(reply, rhdr, sizeof(rel_header));
            send_tls_packet(sr, reply, sock_raw, target_ip, sizeof(rel_header));

        }
        free(sr->msg);
        free(sr);
    }

}

