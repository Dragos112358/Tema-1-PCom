#ifndef _SKEL_H_
#define _SKEL_H_

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Valori magice și coduri de protocol
#define MAX_PACKET_LENGTH 1600
#define NUM_INTERFACES 3
#define MAC_ADDRESS_LENGTH 6
#define IP_ADDRESS_LENGTH 4
#define DEFAULT_TTL 64

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERNET_HARDWARE_TYPE 1
#define ICMP_PROTOCOL_NUMBER 1
#define ARP_REQUEST_OP 1
#define ICMP_TIME_EXCEDEED_TYPE 11
#define ICMP_TIME_EXCEDEED_CODE 0
#define ICMP_DEST_UNREACHABLE_TYPE 3
#define ICMP_DEST_UNREACHABLE_CODE 0
#define IPV4_HEADER_START sizeof(struct ether_header)
#define ARP_HEADER_START sizeof(struct ether_header)
#define ARP_REPLY_OP 2
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_CODE 0
#define ICMP_HEADER_START sizeof(struct iphdr) + sizeof(struct ether_header)
#define ICMP_DATA_START sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)
#define ICMP_DATA_MAX_SIZE sizeof(struct iphdr) + 8


int send_to_link(int interface, char *frame_data, size_t length);

/*
 * @brief Receives a packet. Blocking function, blocks if there is no packet to
 * be received.
 *
 * @param frame_data - region of memory in which the data will be copied; should
 *        have at least MAX_PACKET_LEN bytes allocated
 * @param length - will be set to the total number of bytes received.
 * Returns: the interface it has been received from.
 */
int recv_from_any_link(char *frame_data, size_t *length);

/* Route table entry */
struct route_table_entry {
	uint32_t prefix;
	uint32_t dest_urm;
	uint32_t mask;
	int interface;
} __attribute__((packed));

/* ARP table entry when skipping the ARP exercise */
struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
};
// allocates memory for new trie node
struct nod_arbore *new_nod_arbore(void);

// inserts route table entry into trie
void adauga_nod(struct route_table_entry *entry, struct nod_arbore *root);

// returns best match for a given IP
struct nod_arbore *cauta(struct nod_arbore *root, uint32_t ip);

// deallocates all memory allocated to the trie
void eliberare_memorie_arbore(struct nod_arbore *root);

char *get_interface_ip(int interface);

/**
 * @brief Get the interface mac object. The function writes
 * the MAC at the pointer mac. uint8_t *mac should be allocated.
 *
 * @param interface
 * @param mac
 */
void get_interface_mac(int interface, uint8_t *mac);

/**
 * @brief Homework infrastructure function.
 *
 * @param argc
 * @param argv
 */

/**
 * @brief IPv4 checksum per  RFC 791. To compute the checksum
 * of an IP header we must set the checksum to 0 beforehand.
 *
 * also works as ICMP checksum per RFC 792. To compute the checksum
 * of an ICMP header we must set the checksum to 0 beforehand.

 * @param data memory area to checksum
 * @param size in bytes
 */
uint16_t checksum(uint16_t *data, size_t len);

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

/* Populates a route table from file, rtable should be allocated
 * e.g. rtable = malloc(sizeof(struct route_table_entry) * 80000);
 * This function returns the size of the route table.
 */
int read_rtable(const char *path, struct nod_arbore *rtable);

/* Parses a static mac table from path and populates arp_table.
 * arp_table should be allocated and have enough space. This
 * function returns the size of the arp table.
 */
int parse_arp_table(char *path, struct arp_entry *arp_table);

void init(int argc, char *argv[]);

#define DIE(condition, message, ...) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[(%s:%d)]: " # message "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

struct nod_arbore {
	struct route_table_entry *entry;
	struct nod_arbore *left;
	struct nod_arbore *right;
};

#endif /* _SKEL_H_ */
