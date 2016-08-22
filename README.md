# DNSPoison

A DNS packet injection and DNS poisoning detection utility.

DNS Packet Injection:
dnsinject [-i interface] [-f hostnames] expression

-i  interface:
Listen on network device <interface> (e.g., eth0). If not specified, dnsinject will select a default interface to listen on. The same interface will be used for packet injection.

-f  hostnames:
Read a list of IP address and hostname pairs specifying the hostnames to be hijacked. If '-f' is not specified, dnsinject will forge replies for all observed requests with the local machine's IP address as an answer.

<expression> is a BPF filter that specifies a subset of the traffic to be
monitored.

DNS injection implemented in C for faster runtime and injection purposes.

DNS Poisoning Detection:
dnsdetect [-i interface] [-r tracefile] expression

-i  interface:
Listen on network device <interface> (e.g., eth0). If not specified, dnsdetect will select a default interface to listen on.

-r tracefile: Read packets from <tracefile> (tcpdump format).

<expression> is a BPF filter that specifies a subset of the traffic to be
monitored.

Once an attack is detected, dnsdetect will print to stdout a detailed alert
containing a printout of both the spoofed and legitimate responses.

