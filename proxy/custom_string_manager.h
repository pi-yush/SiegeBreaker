/*
Author : SiegeBreaker Devs.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <pthread.h>
#include <math.h>
#include <semaphore.h>


typedef struct SNIFF_RESPONSE {
    char *msg;
    unsigned long reply_ack;
    unsigned long reply_seq;
    int urg_ptr;
    int window;
    int port;
    int length;
    char *ip;

    int dport;

} Sniff_response;

/*
 * Structure used to pass on data to pthread instance.
 *
 */
typedef struct thread_mgr
{
    //Socket to listen to
    int socket_id;
    //Port for binding
    int port_to_bind_to;
    //Reference to Center's DB structure.
    db_mgr *weak_db_ref;
    //Packet sniffed via libpacp.
    Sniff_response *last_pkt;

} thread_mgr;

/**
 * Concatenates two strings by allocating new memory, so that we're guaranteed to not run out of buffer.
 * Please note that this is different from strcat family.
 * @param  {const char*} s1 First string to be copied into output string
 * @param  {const char*} s2 Second string to be copied into output string
 * @return {NULL}
 */

char *concat_2_strings(const char *s1, const char *s2) {
    char *result = malloc(strlen(s1) + strlen(s2) + 1);

    strcpy(result, s1);
    strcat(result, s2);
    return result;
}


char *combine_ip_and_port(const char *ipaddress, int port) {
    char *ipaddress_buffer = concat_2_strings(ipaddress, ":");

    char port_buffer[20];
    sprintf(port_buffer, "%d", port);

    char *char_db_entry = concat_2_strings(ipaddress_buffer, port_buffer);
    return char_db_entry;
}

db_mgr *init_db() {
    db_mgr *g_db_structure = (db_mgr *) malloc(sizeof(db_mgr));

    g_db_structure->db_size = 0;

    return g_db_structure;
}


int gen_entry_and_add(db_mgr *db, const char *ipaddress, int source_port) {
    int index = (db)->db_size;

    (db)->tcp_id[index].port = source_port;

    (db)->db_size = (db)->db_size + 1;

    printf(" DB Increased %d\n", db->db_size);


}


int check_if_exists(db_mgr *db, int source_port) {

    int i;
    int db_size = (db)->db_size;
    for (i = 0; i < db_size; ++i) {
        if (source_port == (db)->tcp_id[i].port)
            return 1;
    }
    return 0;

}


int display_db(db_mgr *db) {
    int db_size = (db)->db_size;

    int i;
    printf("Gonna Display\n");
    for (i = 0; i < db_size; ++i) {
        printf("Entry %d -> %d\n", i, (db)->tcp_id[i].port);

    }

}


int validate_new_connection(db_mgr *weak_db_ref, Sniff_response *packetObj) {

    if (!check_if_exists((weak_db_ref), packetObj->port)) {
        printf("\n??Validated ");
        printf("??Check Guy as %s :: %d \n", packetObj->ip, packetObj->port);

        return 1;
    }


    return 0;

}



/*
int check_main(db_mgr *d)
{
	gen_entry_and_add(d, "192.168.29.19", 445);
	gen_entry_and_add(d, "192.168.529.29", 448);
	gen_entry_and_add(d, "192.168.529.39", 44);
	gen_entry_and_add(d, "192.168.629.49", 4495);
	
	display_db(d);
	int stst = check_if_exists(d,  "192.168.529.39:44" );
	printf("%d\n", stst );


	stst = check_if_exists(d, "192.168.529.39:4489" );
	printf("%d\n", stst );

	return 0;
}

*/
