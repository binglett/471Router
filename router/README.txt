Spring CMPT471 
Project 4 - SR router

=============================
	Group Members
=============================
Bonnie Ng (301223584)
Ramin

=============================
	Work Division
=============================
Bonnie:
- ARP; the functions dealing with ARP request and reply handling, including 
	making and sending the required ARP packets.
- ARP; handle_arpreq; handling the case when router does not have the MAC
	address when forwarding, i.e. broadcasting ARP requests or sending ICMP
	host unreachable
- initial passing of received packet to either the ARP or IP flow

Ramin:
IP/ICMP

=============================
	Known Bugs
=============================


=============================
	Code Design
=============================
No additional data structures were defined to implement the router nor did we 
separate the ARP and IP/ICMP handling functions into their own files. Nearly 
all new code was added to router.c, but with a naming convention that can help 
us to identify which flow (ARP or IP/ICMP) the new functions belonged to. 
ARP helper functions begin with "ARP" and ICMP or IP start with "ICMP" or "IP"
respectively.

1. IP or ARP packet?
We approached the implementation of the router by starting at where the router 
first meets our router. The packet arrives and the ethernet header is inspected 
to determine if it should be handled as an ARP or IP packet.

2. Handling an ARP packet
After it is determined that the packet is an ARP packet, it is checked for if 
it is a request or reply by inspecting the ARP header this time. 
	If it is a request, the router only sends a reply if the IP address is one 
	of the router's address. A helper function to make an ARP packet and 
	another to send it was made to do this. 
	If it is a reply, we cache the reply using the provided insert to arpcache
	function, then we loops through the cache entries and check if any requests
	that were waiting for a response now has a reply that it can use to send its
	waiting packets.

3. Sending an ARP reply to a request:
The recieved ARP request packet is reused, meaning we modify just the few header
fields, like the sender and target MAC and IP address fields and send it right 
back to the sender. That way we don't have to allocate new memory. 

4. Recieving ARP replies and sending waiting packets:
Because of the way the cache is structured in sr_instance, to check and send all 
the packets waiting for a response, we just have to check if the requests in the
cache object against the cached new IP/MAC cache entries to see if they match; 
if the IP address of the request object matches with the new entry, we just iterate
over the linked list of packets attached to/waiting on that request. After sending 
the packets on a request, the request is destroyed using the provided function. 

5. IP packet is received
We first check whether the destination of the packet is one of the router's interfaces,
if is is, then it is checked whether it is an ICMP packet or TCP or UDP
	If ICMP, an ICMP echo is sent back to the sender
	If UDP or TCP, an ICMP port unreachable message is sent back
If the destination is not our router, we pass the packet along to our IP forwarding 
function.

*6. ICMP messages
We made separate ICMP messages for each of the ICMP messages that are to be sent 
by the router.

7. IP forwarding



