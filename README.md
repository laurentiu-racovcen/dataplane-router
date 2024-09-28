# **Dataplane Router**

>This project consists in implementing the dataplane of a router.
The router works with a static routing table, received in an input file.
The ARP table populates dynamically as the router receives packets.

**This router is only programmed to perform IP and ARP packet processing.**

The router can receive packets on any of its interfaces, and then must forward the packets onward, 
to a computer or to another directly connected router, depending on the rules in the routing table.



To realize the given requirements, there have been used certain data structures, declared in
`tree.h` and `queue.h` files and implemented in `tree.c` and `queue.c` files.
When the router does not have in the ARP table the MAC address corresponding to the
IP address of the next hop, it queues the corresponding packet (using the `"queue_packet"` structure) and sends
an broadcast `ARP Request` in order to find the MAC address of the next hop.
Given the routing table contains a lot of entries, the linear search for
`LPM (Longest Prefix Match)` in the table would be slow. Therefore, there is used a
`"trie"` data structure, which significantly reduces the `LPM` search time,
traversing a maximum of 32 nodes (an IP address being 32 bits long) for a prefix lookup.


## **Table of contents**

1. ["main" function](#main-function)
2. ["router.c" functions](#routerc-functions)
3. ["Trie" binary tree functions](#trie-binary-tree-functions)
4. [Queue functions](#queue-functions)

## **"main" function**

**1.** Allocate memory to buffer `buf` for storing incoming packets

**2.** Allocate memory for the routing table `rtable` for storing entries of type `"struct route_table_entry``

**3.** Initially, it dynamically allocates memory for a single entry in the `arp_table`, so as not to waste memory space

**4.** Initialize the `"trie"` binary tree and fill it with all the prefixes from the `rtable` table

**5.** Create a queue for packets whose MAC address of the next hop the router does not know

**6.** The router continuously receives packets. If the packet received by the router has MAC destination - router's MAC address or broadcast address, then the packet is processed by the router; if not - the router drops the packet.

**7.** If the packet received by the router is of IP or ARP type, the router processes the packet; if not - the router drops the packet

## **"router.c" functions**

Check functions:
- `"is_broadcast_mac"` - checks if a MAC address is of `broadcast` type
- `"router_contains_mac"` - checks if the router contains a particular MAC address
- `"router_contains_ip"` - checks if the router contains a particular IP address

ARP protocol functions:

- `"process_arp"` - processes `ARP` packets
- `"get_arp_entry"` - returns the ARP table entry for an IP address
- `"add_arp_entry"` - adds an ARP entry to the `ARP table`
- `"arp_send_reply"` - sends an `ARP Reply` packet
- `"arp_send_request"` - sends an broadcast `ARP Request` packet if the next hop is not in the `ARP table`

IP protocol functions:
- `"process_ip"` - processes `IP` packets
- `"fill_icmp_packet"` - fill the given `ICMP` header fields with the given parameter information
- `"fill_ip_header"` - fill the given `IP` header fields with the given parameter information
- `"fill_ether_header"` - fill the given `Ethernet` header fields with the given information as parameters
- `"icmp_echo_reply"` - creates and sends an `ICMP Echo Reply` packet to the interface corresponding to the `LPM` entry in the `rtable` of the original source IP address (back to the original source of the received packet, which has the `Echo Request` type)
- `"icmp_time_exceeded"` - creates and sends an `ICMP Time Exceeded` packet to the interface corresponding to the `LPM` entry in the `rtable` of the original source IP address (back to the original source of the received packet, whose TTL is expired)
- `"icmp_dest_unreachable"` - creates and sends an `ICMP Destination Unreachable` packet to the interface corresponding to the `LPM` entry in the `rtable` of the original source IP address (back to the original source of the received packet, because the router cannot find a path to the next hop in the `rtable`)
- `"forward_ip_packet"` - sends the received IP packet to the next hop to destination

## **"Trie" binary tree functions**

- `"initTree"` - initializes a `trie`
- `"insert_prefix"` - inserts a new prefix into the tree
- `"get_prefix_len"` - returns the length of a prefix
- `"get_best_route"` - returns the `rtable` entry with the Longest Prefix Match of a destination IP address
- `"freeTree"` - frees the dynamically allocated memory for the `trie` binary tree

## **Queue functions**

- `"queue_create"` - creates a queue
- `"queue_empty"` - determines whether the queue is empty or not
- `"queue_enq"` - inserts a new item into the queue
- `"queue_deq"` - extract an item from the queue
- `"get_queue_head"` - returns the value of the first item in the queue
