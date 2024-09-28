#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "tree.h"

#define MAX_INPUT_BUF_LENGTH 1600
#define MAX_RTABLE_ENTRIES 100000
#define MAX_ARP_ENTRIES 100
#define NR_OF_ROUTER_INTERFACES 3
#define MAC_LENGTH 6
#define IP_ADDR_LENGTH 4
#define ARP_TYPE 0x0806
#define IP_TYPE 0x0800
#define DEST_UNREACHABLE_TYPE 3
#define ARP_REQUEST_OP 1
#define ARP_REPLY_OP 2
#define ARP_ETHER_TYPE 1
#define TIME_EXCEEDED_TYPE 11
#define ICMP_PROTOCOL_CODE 1
#define ICMP_REPLY_CODE 0
#define ICMP_REQUEST_TYPE 8
#define ICMP_REPLY_TYPE 0
#define DEFAULT_TTL 64

struct route_table_entry *rtable;
size_t rtable_len = 0;

struct arp_table_entry *arp_table;
size_t arp_table_len = 1;
size_t current_arp_table_idx = 0;

struct queue_packet
{
	char* original_packet;
	size_t original_packet_len;
	uint32_t next_hop_ip;
};

queue waiting_queue;

/* Checks if the MAC address contains only 1's */
int is_broadcast_mac(uint8_t dest_mac[MAC_LENGTH]) {

	char count = 0;

	for (size_t i = 0; i < MAC_LENGTH; i++){
		if (dest_mac[i] == 0xff) {
			count++;
		}
	}

	if (count == MAC_LENGTH) {
		return 1;
	}

	return 0;
}

/* Checks if this router has an interface whose
* MAC address is the destination MAC address */
int router_contains_mac(uint8_t dest_mac[MAC_LENGTH]) {

	// iterate through all router's interfaces
	uint8_t current_mac[MAC_LENGTH];
	for (size_t i = 0; i < NR_OF_ROUTER_INTERFACES; i++) {
		get_interface_mac(i, current_mac);

		// check if destination MAC == current interface MAC
		int count = 0;
		for (int i = 0; i < MAC_LENGTH; i++) {
			if (current_mac[i] == dest_mac[i]) {
				count++;
			}
		}

		if (count == MAC_LENGTH) {
			// dest MAC == one of this router's interfaces MAC
			return 1;
		}
	}

	// a matching interface MAC has not been found
	return 0;

}

/* Checks if this router has an interface whose
* IP address is the destination IP address */
int router_contains_ip(uint32_t dest_ip) {
	// iterate through all router's interfaces
	struct in_addr current_ip;
	for (size_t i = 0; i < NR_OF_ROUTER_INTERFACES; i++) {
		char* ip_string = get_interface_ip(i);

		int ret = inet_aton(ip_string, &current_ip);
		DIE(ret == 0, "address");

		// check if destination IP == current interface IP
		if (current_ip.s_addr == dest_ip) {
			return 1;
		}
	}
	// a matching interface IP has not been found
	return 0;
}

struct arp_table_entry *get_arp_entry(uint32_t ip_addr) {
	for (size_t i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_addr) {
			return &arp_table[i];
		}
	}

	// the ip address was not found in the ARP table
	return NULL;
}

void add_arp_entry(struct arp_header *arp_hdr) {

	// allocate double memory for ARP table entries
	if (current_arp_table_idx >= arp_table_len - 1) {
		arp_table = realloc(arp_table, 2 * arp_table_len * sizeof(struct arp_table_entry));
		arp_table_len = 2 * arp_table_len;
	}

	DIE(arp_table == NULL, "memory");

	// copy IP of reply sender
	arp_table[arp_table_len].ip = arp_hdr->spa;

	// copy MAC of reply sender
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		arp_table[arp_table_len].mac[i] = arp_hdr->sha[i];
	}

	arp_table_len++;
}

/* Function that sends an ARP reply to the source */
void arp_send_reply(char *buf, size_t buf_len, int interface, struct arp_header *arp_hdr) {

	// get this interface MAC and copy it in source field
	uint8_t interface_mac[MAC_LENGTH];
	get_interface_mac(interface, interface_mac);

	// swap source/target ip adresses
	uint32_t temp = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = temp;

	/* there's no need to convert ip/mac adresses to host order,
	* because both are in network order */

	// target address will be the source address
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		arp_hdr->tha[i] = arp_hdr->sha[i];
	}

	// update source address with MAC of matching interface
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		arp_hdr->sha[i] = interface_mac[i];
	}

	// set op from "request" to "reply"
	arp_hdr->op = htons(ARP_REPLY_OP);

	/* preparing to send Ethernet frame to next hop, containing ARP reply */

	// destination MAC will be previous source mac
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
	}

	// source MAC will be current interface MAC
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		eth_hdr->ether_shost[i] = interface_mac[i];
	}

	// send reply to source
	send_to_link(interface, buf, buf_len);
}

/* function that sends a broadcast request in case the next hop ip is not in ARP cache table */
void arp_send_request(struct route_table_entry *best_route) {
	// allocate memory for ether header + arp header
	struct ether_header *eth_hdr = calloc(1, sizeof(struct ether_header) + sizeof(struct arp_header));

	struct arp_header *arp_hdr = (struct arp_header *)(((char*)eth_hdr) + sizeof(struct ether_header));

	// get this router interface MAC and copy it in sender field
	uint8_t interface_mac[MAC_LENGTH];
	get_interface_mac(best_route->interface, interface_mac);

	// to get current interface's ip in number format
	struct in_addr router_interface_ip;

	int ret;
	ret = inet_aton(get_interface_ip(best_route->interface), &router_interface_ip);
	// if address is not valid
	DIE(ret == 0, "address");

	// set source/target ip adresses
	arp_hdr->spa = router_interface_ip.s_addr;
	arp_hdr->tpa = best_route->next_hop;

	// set source MAC address of router interface
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		arp_hdr->sha[i] = interface_mac[i];
	}

	// set target MAC address to 0
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		arp_hdr->tha[i] = 0;
	}

	// set op to "request"
	arp_hdr->op = htons(ARP_REQUEST_OP);

	// set default field values
	arp_hdr->plen = IP_ADDR_LENGTH;
	arp_hdr->hlen = MAC_LENGTH;
	arp_hdr->ptype = htons(IP_TYPE);
	arp_hdr->htype = htons(ARP_ETHER_TYPE);

	/* preparing to send ethernet frame to next hop, containing arp request */

	eth_hdr->ether_type = htons(ARP_TYPE);

	// source MAC will be current router interface MAC
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		eth_hdr->ether_shost[i] = interface_mac[i];
	}
	// fill with broadcast MAC
	for (size_t i = 0; i < MAC_LENGTH; i++) {
		eth_hdr->ether_dhost[i] = 0xff;
	}

	// send the ARP request
	send_to_link(best_route->interface, (char*) eth_hdr, sizeof(struct ether_header) + sizeof(struct arp_header));
}

/* Function that processes ARP packets */
void process_arp(char* buf, size_t buf_len, int interface) {
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// check variable
	int matching_interface = -1;

	// checks if this specified destination matches with one of this router's interfaces

	for (size_t i = 0; i < NR_OF_ROUTER_INTERFACES; i++) {

		// to get current interface's IP in number format
		struct in_addr current_interface_ip;

		int ret;
		ret = inet_aton(get_interface_ip(i), &current_interface_ip);
		// if address is not valid
		DIE(ret == 0, "address");

		// there's no need to convert adresses to host order,
		// because both are in network order
		if (current_interface_ip.s_addr == arp_hdr->tpa) {
			matching_interface = i;
			break;
		}

	}

	if (matching_interface != -1) {

		// Dest IP == One of this router's interfaces IP

		/* if the router receives an ARP request */
		if (ntohs(arp_hdr->op) == ARP_REQUEST_OP) {

			/* send an ARP reply message to the source, containing this router's interface MAC */
			arp_send_reply(buf, buf_len, matching_interface, arp_hdr);

		} else if (ntohs(arp_hdr->op) == ARP_REPLY_OP) {
			/* if the router receives an ARP reply */

			// the ARP source address is not in the ARP Table, add source MAC and IP to cache ARP table
			if (get_arp_entry(arp_hdr->spa) == NULL) {
				add_arp_entry(arp_hdr);
			}

		}
	}
	// else, Dest IP != This router's interface IP. The packet was dropped
}

void fill_icmp_packet(uint8_t type, uint8_t code, struct icmphdr *icmp_packet,
						struct iphdr *received_ip_packet) {
	icmp_packet->type = type;
	icmp_packet->code = code;

	/* complete the rest of the ICMP packet, considering the type and code */

	// initializing len with icmphdr size
	uint32_t icmp_packet_len = sizeof(struct icmphdr);

	// generate packet with "time exceeded" reply
	// or "destination unreachable" reply
	if ((type == TIME_EXCEEDED_TYPE && code == ICMP_REPLY_CODE) ||
	    (type == DEST_UNREACHABLE_TYPE && code == ICMP_REPLY_CODE)) {

		// add the internet header + the first 64 bits of original IP packet data
		icmp_packet_len = sizeof(struct icmphdr) + received_ip_packet->ihl * 4 + 8;
		char* ip_info = ((char*)icmp_packet) + sizeof(struct icmphdr);

		memcpy(ip_info, received_ip_packet, icmp_packet_len - sizeof(struct icmphdr));
	} else if (type == ICMP_REPLY_TYPE && code == ICMP_REPLY_CODE) {
		/* generate packet with "ECHO REPLY" content */

		// set id and sequence fields from the received icmp header data
		struct icmphdr* received_icmp_data = (struct icmphdr*) (((char*)received_ip_packet) + received_ip_packet->ihl * 4);
		icmp_packet->un.echo.id = received_icmp_data->un.echo.id;
		icmp_packet->un.echo.sequence = received_icmp_data->un.echo.sequence;

		// include the ICMP data (after the header) of received icmp packet
		received_icmp_data = (struct icmphdr*) (((char*)received_icmp_data) + sizeof(struct icmphdr));
		char* icmp_data = ((char*)icmp_packet) + sizeof(struct icmphdr);
		icmp_packet_len = ntohs(received_ip_packet->tot_len) - sizeof(struct iphdr);
		memcpy(icmp_data, received_icmp_data, icmp_packet_len - sizeof(struct icmphdr));
	}

	/* compute checksum of ICMP packet */
	icmp_packet->checksum = 0;
	icmp_packet->checksum = htons(checksum((uint16_t*)icmp_packet, icmp_packet_len));
}

void fill_ip_header(struct iphdr* new_ip_hdr, struct iphdr* received_ip_hdr, uint16_t new_tot_len, int interface, uint8_t ttl) {

	/* default values of ip header*/
	new_ip_hdr->tos = 0;
	new_ip_hdr->frag_off = 0x40;
	new_ip_hdr->version = 4;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->id = 1;
	new_ip_hdr->protocol = 1;

	/* custom values of ip header */
	new_ip_hdr->tot_len = htons(new_tot_len);
	new_ip_hdr->ttl = ttl;

	// to get current interface's IP in number format
	struct in_addr current_interface_ip;

	int ret;
	ret = inet_aton(get_interface_ip(interface), &current_interface_ip);
	// if address is not valid
	DIE(ret == 0, "address");

	new_ip_hdr->saddr = current_interface_ip.s_addr;
	new_ip_hdr->daddr = received_ip_hdr->saddr;

	// compute checksum of IP header
	new_ip_hdr->check = 0;
	new_ip_hdr->check = htons(checksum((uint16_t*)new_ip_hdr, new_tot_len));

}

/* Function that fills the ether header and returns new_ether_hdr if successful */
struct ether_header *fill_ether_header(struct ether_header *new_ether_hdr, uint16_t ether_type, struct route_table_entry* rtable_entry) {
	/* get MAC of next hop by IP address */
	struct arp_table_entry *arp_entry;

	arp_entry = get_arp_entry(rtable_entry->next_hop);
	if (arp_entry != NULL) {
		// copy MAC from entry to destination
		memcpy(new_ether_hdr->ether_dhost, arp_entry->mac, MAC_LENGTH);
		new_ether_hdr->ether_type = htons(ether_type);
		get_interface_mac(rtable_entry->interface, new_ether_hdr->ether_shost);

		return new_ether_hdr;
	}

	// In case the next-hop's MAC is not in the ARP table, send an ARP request to next_hop
	// (if the ether header is for an ICMP unreachable message)
	arp_send_request(rtable_entry);
	
	// there was NOT an ARP cache entry for the next hop
	return NULL;
}

void icmp_echo_reply(char *buf, int interface, struct TreeNode *trie) {
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// generate an ICMP packet with type 0, code 0
	struct icmphdr *icmp_packet = calloc(1, ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4);
	fill_icmp_packet(ICMP_REPLY_TYPE, ICMP_REPLY_CODE, icmp_packet, ip_hdr);

	// generate an IP header for the encapsulated ICMP packet
	struct iphdr *new_ip_hdr = calloc(1, sizeof(struct iphdr));
	fill_ip_header(new_ip_hdr, ip_hdr, ntohs(ip_hdr->tot_len), interface, ip_hdr->ttl-1);

	// generate an Ethernet header for the encapsulated IP packet
	struct ether_header *new_ether_hdr = calloc(1, sizeof(struct ether_header));

	// to send the reply via Ethernet, the router finds the best route
	struct route_table_entry *ret_route = get_best_route(ntohl(new_ip_hdr->daddr), trie);

	if (ret_route != NULL) {

		struct ether_header *ret_ether_header = NULL;
		ret_ether_header = fill_ether_header(new_ether_hdr, IP_TYPE, ret_route);

		// the ether header was filled successfully, combine all protocols and send the Ethernet frame
		if (ret_ether_header != NULL) {
			uint16_t send_buf_len = sizeof(struct ether_header) + ntohs(new_ip_hdr->tot_len);
			char* send_buf = calloc(1, send_buf_len);
			// copy ether header contents
			memcpy(send_buf, new_ether_hdr, sizeof(struct ether_header));
			// copy ip header contents
			memcpy(send_buf + sizeof(struct ether_header), new_ip_hdr, sizeof(struct iphdr));
			// copy ICMP packet contents
			memcpy(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_packet, ntohs(new_ip_hdr->tot_len) - sizeof(struct iphdr));
			// send an ICMP packet with the message "Time exceeded" back to the sender
			send_to_link(ret_route->interface, send_buf, send_buf_len);
			free(send_buf);
		} // else, the ether header cannot be filled because the destination address is NOT in the rtable, so the packet is dropped

		free(icmp_packet);
		free(new_ip_hdr);
		free(new_ether_hdr);

	}
	// else, there is no such an address in the rtable, so drop the packet
}

void icmp_time_exceeded(char *buf, int interface, struct TreeNode *trie) {

	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// generate an ICMP packet with type 11, code 0;
	// contains the IP header + first 64 bits of IP packet payload
	struct icmphdr *icmp_packet = calloc(1, sizeof(struct icmphdr) + ip_hdr->ihl * 4 + 8);
	fill_icmp_packet(TIME_EXCEEDED_TYPE, ICMP_REPLY_CODE, icmp_packet, ip_hdr);

	// generate an IP header for the encapsulated icmp_packet
	struct iphdr *new_ip_hdr = calloc(1, sizeof(struct iphdr));
	fill_ip_header(new_ip_hdr, ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr) + ip_hdr->ihl * 4 + 8, interface, DEFAULT_TTL);

	// generate an Ethernet header for the encapsulated IP packet
	struct ether_header *new_ether_hdr = calloc(1, sizeof(struct ether_header));

	// to send the reply via Ethernet, find the best route
	struct route_table_entry *ret_route = get_best_route(ntohl(new_ip_hdr->daddr), trie);

	if (ret_route != NULL) {

		struct ether_header *ret_ether_header;
		ret_ether_header = fill_ether_header(new_ether_hdr, IP_TYPE, ret_route);

		if (ret_ether_header != NULL) {
			// the ether header was filled successfully, combine all protocols and send the Ethernet frame
			uint16_t send_buf_len = sizeof(struct ether_header) + ntohs(new_ip_hdr->tot_len);
			char* send_buf = calloc(1, send_buf_len);
			// copy ether header contents
			memcpy(send_buf, new_ether_hdr, sizeof(struct ether_header));
			// copy IP header contents
			memcpy(send_buf + sizeof(struct ether_header), new_ip_hdr, sizeof(struct iphdr));
			// copy ICMP packet contents
			memcpy(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_packet, sizeof(struct icmphdr) + ip_hdr->ihl * 4 + 8);
			// send a ICMP packet with the message "Time exceeded" back to the sender
			send_to_link(ret_route->interface, send_buf, send_buf_len);
			free(send_buf);
		} // else, the ether header cannot be filled

		free(icmp_packet);
		free(new_ip_hdr);
		free(new_ether_hdr);

	} // else, there is no such an address in the rtable, so drop the packet

}

void icmp_dest_unreachable(char *buf, int interface, struct TreeNode *trie) {
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// generate an ICMP packet with type 3, code 0;
	// contains ip header + first 64 bits of ip packet payload
	struct icmphdr *icmp_packet = calloc(1, sizeof(struct icmphdr) + ip_hdr->ihl * 4 + 8);
	fill_icmp_packet(DEST_UNREACHABLE_TYPE, ICMP_REPLY_CODE, icmp_packet, ip_hdr);

	// generate an IP header for the encapsulated icmp_packet
	struct iphdr *new_ip_hdr = calloc(1, sizeof(struct iphdr));
	fill_ip_header(new_ip_hdr, ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr) + ip_hdr->ihl * 4 + 8, interface, DEFAULT_TTL);

	// generate an Ethernet header for the encapsulated IP packet
	struct ether_header *new_ether_hdr = calloc(1, sizeof(struct ether_header));

	// to send the reply via Ethernet, find the best route back to the sender
	struct route_table_entry *ret_route = get_best_route(ntohl(new_ip_hdr->daddr), trie);

	if (ret_route != NULL) {

		struct ether_header *ret_ether_header;
		ret_ether_header = fill_ether_header(new_ether_hdr, IP_TYPE, ret_route);

		// the ether header was filled successfully, combine all protocols and send the Ethernet frame
		if (ret_ether_header != NULL) {
			uint16_t send_buf_len = sizeof(struct ether_header) + ntohs(new_ip_hdr->tot_len);
			char* send_buf = calloc(1, send_buf_len);
			// copy ether header contents
			memcpy(send_buf, new_ether_hdr, sizeof(struct ether_header));
			// copy ip header contents
			memcpy(send_buf + sizeof(struct ether_header), new_ip_hdr, sizeof(struct iphdr));
			// copy ICMP packet contents
			memcpy(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_packet, sizeof(struct icmphdr) + ip_hdr->ihl * 4 + 8);
			// send a ICMP packet with the message "Time exceeded" back to the sender
			send_to_link(ret_route->interface, send_buf, send_buf_len);
			free(send_buf);
		} // else, could not fill the ether header, the packet was dropped

		free(icmp_packet);
		free(new_ip_hdr);
		free(new_ether_hdr);

	} // else, there is no such an address in the rtable, so drop the packet
}

void forward_ip_packet(char* buf, struct TreeNode *trie, struct route_table_entry *best_route) {
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// allocate an Ethernet header for the encapsulated IP packet
	struct ether_header *new_ether_hdr = calloc(1, sizeof(struct ether_header));

	if (best_route != NULL) {
		struct ether_header *ret_ether_header = NULL;
		// overwrite the received ip packet
		ret_ether_header = fill_ether_header(new_ether_hdr, IP_TYPE, best_route);

		if (ret_ether_header != NULL) {
			/* the ether header was filled successfully */

			// decrement TTL and compute new checksum
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, htons(ip_hdr->tot_len)));

			// combine the Ethernet header with the IP packet
			int send_buf_len = ntohs(ip_hdr->tot_len) + sizeof(struct ether_header);
			char* send_buf = calloc(1, send_buf_len);

			memcpy(send_buf, new_ether_hdr, sizeof(struct ether_header));
			memcpy(send_buf + sizeof(struct ether_header), ip_hdr, send_buf_len - sizeof(struct ether_header));

			// send the modified Ethernet frame
			send_to_link(best_route->interface, send_buf, send_buf_len);
			free(send_buf);
		} // else, the ether header cannot be filled because the destination address is NOT in the rtable, so the packet is dropped

		free(new_ether_hdr);
	} // else, there is no such an address in the rtable, so drop the packet
}

/* function that processes IP packets */
void process_ip(char* buf, size_t buf_len, int interface, struct TreeNode *trie) {
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// get the best route to the destination IP address
	struct route_table_entry *rtable_entry = get_best_route(ntohl(ip_hdr->daddr), trie);

	// check if destination IP is in the routing table
	if (rtable_entry != NULL) {
		// check if destination IP is in the ARP cache table
		if (get_arp_entry(rtable_entry->next_hop) != NULL) {
			/* check if the checksum of the IP packet is correct */
			uint16_t temp_checksum = ip_hdr->check;

			// set ip_hdr checksum to 0 to compute checksum
			ip_hdr->check = 0;

			// compute the checksum
			ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, buf_len - sizeof(struct ether_header)));

			if (temp_checksum == ip_hdr->check) {
				// checksum is correct

				// if TTL is higher than 1, do NOT drop the packet
				if (ip_hdr->ttl > 1) {
					if (router_contains_ip(ip_hdr->daddr)) {
						// check if protocol is ICMP
						if (ip_hdr->protocol == ICMP_PROTOCOL_CODE) {
							/* if destination ip address == one of this router's interfaces IP address,
							 * type == 8, code == 0, then it's an echo request; send a reply to source */
							struct icmphdr *icmp_header = (struct icmphdr *)(((char*)ip_hdr) + sizeof(struct iphdr));

							if (icmp_header->type == ICMP_REQUEST_TYPE &&
								icmp_header->code == ICMP_REPLY_CODE) {
								icmp_echo_reply(buf, interface, trie);
							}

						} // else, The packet is not of ICMP type, the packet is dropped
					} else {
						/* if destination ip address != all of this router's interfaces IP address,
						 * forward the ip packet to next hop */
						forward_ip_packet(buf, trie, rtable_entry);
					}
				} else {
					/* if TTL is 0 or 1, an ICMP packet with the message "Time exceeded" will be sent back to the sender */
					icmp_time_exceeded(buf, interface, trie);
				}
			} // else the checksum is incorrect, the packet was dropped
		} else {
			// if best_route is not in ARP table, put the packet in queue and send a broadcast ARP request
			struct queue_packet *q_packet = calloc(1, sizeof(struct queue_packet));

			q_packet->next_hop_ip = rtable_entry->next_hop;
			q_packet->original_packet_len = buf_len;

			q_packet->original_packet = calloc(1, buf_len);
			memcpy(q_packet->original_packet, buf, buf_len);

			queue_enq(waiting_queue, q_packet);
			arp_send_request(rtable_entry);
		}
	} else {
		// the next hop of the packet was NOT found in the rtable, send destination unreachable ICMP message
		icmp_dest_unreachable(buf, interface, trie);
	}
}

int main(int argc, char *argv[]) {

	char *buf = calloc(MAX_INPUT_BUF_LENGTH, sizeof(uint8_t));

	// Do not modify this line
	init(argc - 2, argv + 2);

	// allocate memory for routing table entries
	rtable = calloc(MAX_RTABLE_ENTRIES, sizeof(struct route_table_entry));
	DIE(rtable == NULL, "memory");

	// read the static routing table for this router
	rtable_len = read_rtable(argv[1], rtable);

	// initially allocate memory for one arp table entry
	arp_table = calloc(arp_table_len, sizeof(struct arp_table_entry));
	DIE(arp_table == NULL, "memory");

	/* create a binary tree (trie) and fill it with all "rtable" prefixes */
	struct TreeNode* trie = calloc(1, sizeof(struct TreeNode));
	initTree(&trie);

	for (size_t i = 0; i < rtable_len; i++) {
		struct TreeNode* ret = insert_prefix(trie, &rtable[i]);
		DIE(ret == NULL, "insert_prefix_in_trie");
	}

	waiting_queue = queue_create();

	while (1) {

		int interface;
		size_t buf_len;

		// check if the first packet in queue can be processed
		if (!queue_empty(waiting_queue)) {
			struct queue_packet *head_packet = (struct queue_packet *) get_queue_head(waiting_queue);
			// if the queue head next hop IP is in the ARP table, process queue head...
			if (get_arp_entry(head_packet->next_hop_ip) != NULL) {
				buf = head_packet->original_packet;
				buf_len = head_packet->original_packet_len;
				queue_deq(waiting_queue);
			} else {
				// queue head is not empty and is not a reply to the head of queue, waiting for a packet
				interface = recv_from_any_link(buf, &buf_len);
				DIE(interface < 0, "recv_from_any_links");
			}
		} else {
			// queue is empty, waiting for a packet
			interface = recv_from_any_link(buf, &buf_len);
			DIE(interface < 0, "recv_from_any_links");
		}

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		/* if the destination MAC is a broadcast MAC or one of this router's interfaces MAC */
		if (is_broadcast_mac(eth_hdr->ether_dhost) || router_contains_mac(eth_hdr->ether_dhost)) {

			/* if packet is of ARP type */
			if (ntohs(eth_hdr->ether_type) == ARP_TYPE) {
				process_arp(buf, buf_len, interface);
				continue;
			}
			/* if packet is of IP type */
			else if (ntohs(eth_hdr->ether_type) == IP_TYPE) {
				process_ip(buf, buf_len, interface, trie);
				continue;
			}
			// ether type is not ARP or IP, the packet is dropped
			continue;

		}
		// destination MAC is not broadcast or this router's MAC, the packet is dropped
		continue;
	}
}
