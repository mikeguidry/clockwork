


#define ANTI_SURVEILLANCE_MODULE_ID 666

// function declarations for anti surveillance module
int antisurv_plumbing(Modules *, Connection *, char *buf, int size);


ModuleFuncs antisurv_funcs = {
    NULL, NULL, 
    NULL,
    NULL,
    &antisurv_plumbing,
    NULL, // no connect
    NULL, // no disconnect
    NULL // messages from other bots.. add for adding new files from modules
};

Modules ModuleANTISURV = {
    // required ( NULL, NULL, 0 )
    NULL, // next 
    NULL, // buf
    0,    // fd
    0,    // start ts
    1,    // compiled in
    ANTI_SURVEILLANCE_MODULE_ID,    // module ID
    0,    // type
    0, 
    0, 
    0,
    // required 0, 0..  
    0, 
    1,
    //timer = 300 seconds (5min) - get new nodes, etc
    // httpd functions
    &antisurv_funcs, NULL,
    NULL, NULL, NULL, 0
};


typedef char *(*attack_func)(AS_attacks *aptr);


// one single dns record (response about a hostname, prepared to stay on record)
// it can be reused for preparing further attacks against the same sites, etc
// using different residential, or business ip addresses
typedef struct _dns_record {
    struct _dns_record *next;
    // raw response..
    unsigned char *response;
    int response_size;

    unsigned char type; // enums from before

    uint32_t ipv4;
    uint64_t ipv6;

    // ts of last lookup
    int ts;

    int country_id;
} DNSRecord;


typedef struct _lookup_queue {
    struct _lookup_queue *next;

    char *hostname;

    // spider would be for using different dns servers in different geos
    // it allows using geo ips which look more legit
    // one of the first responses to these attacks will be to filter the attacks out
    // using scenarios like this...
    struct _lookup_queue *spider;
    struct _lookup_queue *recursive;

    // is this queue complete? (it wouuld mean that all recursive/spider are completed as well)
    int complete;
    int ipv6;

    // how many responses? (different geos, etc)
    int count;
    int ts;

    DNSRecord **responses;
} DNSQueue;



// this is where the packet is held after the attack type's functin generates it.. so that function will be called only once
// per packetinfo depending on the count, and intervals...
// its possible to free the packet after from that structure after usage thus allowing it to get regenerated for continous use
// this allows threading by way of many different attack structures, thus seperate session structures
// wide scale manipulation of mass surveillance platforms ;)
typedef struct _pkt_info {
    struct _pkt_info *next;

    int type;

    // for future (wifi raw, etc)
    //int layer;

    char *buf;
    int size;

    // processed using functions to replace locally captured sessions
    // with other names
    int prepared; // macros, etc

    // this src/dst matters most only if the prior structure is using 0
    uint32_t source;
    uint32_t source_port;

    uint32_t destination;
    uint32_t destination_port;
} PacketInfo;


// research information is required for various aaspects of this...
// traceroute information, dns, 
typedef struct _research_info {
    struct _research_info *next;

    uint32_t addr;
    char *hostname;

    // we need to be able to compaare hops between different sources, and destinations
    int traceroute_hops;

    // dns records
    DNSRecord *dns;


} ResearchInfo;





// i decided to hold a virtual connecction  structure which could be used to perform long term sessions (such as falsifying telnet, 
// ssh, and many other things)
typedef struct _virtual_connection {
    struct _virtual_connection *next;
    
    struct _virtual_connection *client;
    struct _virtual_connection *server;

    // needs to be stored under the proper client/server arrangement (lists above)
    uint32_t ack;
    uint32_t seq;
    int operating_system;

    // this is meant for http (things with a way to send one request.. aand the server sends a responsse)
    // there must be other scenarios such as packet timestamps happening for other protocols..

    // GET / request
    char *client_body;
    int client_body_size;

    // server response
    char *server_body;
    int server_body_size;

} VirtualConnection;




// general attack structure...
// should support everything from syn packets, to virtual connections
typedef struct _as_attacks {
    struct _as_attacks *next;

    int id;

    // what kind of attack is this? syn only? spoofed full sessions..
    int type;

    // src / dest matters only if the box is expectinng to be handled on both sides of the tap
    // if its 0 then it will go along with the packet structures
    uint32_t src;
    uint32_t dst;

    // state / id of current packet
    int send_state;
    int recv_state;

    // packets being used for send states, or whatever other circumstances
    PacketInfo *packets;
    PacketInfo *current_packet;

    // do we repeat this attack again whenever its completed?
    int count;
    int repeat_interval;
    int ts;

    // if it has a count>0 then completed would get set whenever
    int completed;

    // function which sets up the attack
    // such as building packets (pushing to queue will done by a 'main loop' function)
    attack_func function;

    // lets hold information for all connections locally, and easily for use in packet building functions..
    // this will also allow easily expanding to do DNS, and other subsequent attacks to perform more like real clients
    // before submitting falsified web queries.. they aint ready
    VirtualConnection *connections;
} AS_attacks;



// this is the queue which shouldnt have anything to do with processing, or other functions.. its where
// all attacks go to get submitted directly to the wire.. 
typedef struct _attack_outgoing_queue {
    struct _attack_outgoing_queue *next;

    AS_attacks *attack_info;

    char *buf;
    int size;
} AttackOutgoingQueue;






#define PSEUDOTCPHSIZE	12
// base ip header size (without options)
#define IPHSIZE		20
// tcp header size (without options)
#define TCPHSIZE 20

// pseudo structure for calculating checksum
struct pseudo_tcp
{
	unsigned saddr, daddr;
	unsigned char mbz;
	unsigned char ptcl;
	unsigned short tcpl;
	struct tcphdr tcp;
};


// packet header.. options go after tcphdr.. i havent used iphdr so oh well
struct packethdr
{
	struct iphdr ip;
    struct tcphdr tcp;
};

/*
NS (1 bit): ECN-nonce - concealment protection (experimental: see RFC 3540).
CWR (1 bit): Congestion Window Reduced (CWR) flag is set by the sending host to indicate that it received a TCP
 segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
ECE (1 bit): ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
If the SYN flag is set (1), that the TCP peer is ECN capable.
If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11) in IP header was received
 during normal transmission (added to header by RFC 3168). This serves as an indication of network congestion
  (or impending congestion) to the TCP sender.
URG (1 bit): indicates that the Urgent pointer field is significant
ACK (1 bit): indicates that the Acknowledgment field is significant. 
All packets after the initial SYN packet sent by the client should have this flag set.
PSH (1 bit): Push function. Asks to push the buffered data to the receiving application.
RST (1 bit): Reset the connection
SYN (1 bit): Synchronize sequence numbers. 
Only the first packet sent from each end should have this flag set. Some other flags and fields change meaning based on this flag, and some are only valid for when it is set, and others when it is clear.
FIN (1 bit): Last packet from sender.
*/

// like this so we can use bitwise type scenarios even though its integer.. if & and flags |= FLAG_...
enum {
    TCP_WANT_CONNECT=1,
    TCP_CONNECT_OK=2,
    TCP_ESTABLISHED=4,
    TCP_TRANSFER=8,
    TCP_FLAG_NS=16,
    TCP_FLAG_CWR=32,
    TCP_FLAG_ECE=64,
    TCP_FLAG_URG=128,
    TCP_FLAG_ACK=256,
    TCP_FLAG_PSH=512,
    TCP_FLAG_RST=1024,
    TCP_FLAG_SYN=2048,
    TCP_FLAG_FIN=4096,
    TCP_OPTIONS_WINDOW=8192,
    TCP_OPTIONS_TIMESTAMP=16384
};



// allows preparing full session, and then building the packets immediately..
// resulting in this linked list going directly into a function for addition
// into the queue....
// i cannot think of any better way at the moment considering there are so many varibles
// and soon there will be functions being built around generalization of traffic statistics
// to ensure these connections cannot be singled out
// this is one method which allows expanding easily..
typedef struct _tcp_packet_instructions {
    struct _tcp_packet_instructions *next;

    int session_id;
    
    int ttl;
    

    uint32_t header_identifier;
    uint32_t source_ip;

    int source_port;

    uint32_t destination_ip;
    int destination_port;

    int flags;

    char *options;
    int options_size;

    int window_size;

    // data goes here.. but it'd be nice to have it as an array..
    // so a function can fragment it which would cause even further processing
    // by surveillance platforms.. even bit counts across thousands/millions
    // of connections per second, or minute
    char *data;
    int data_size;

    // final packet will get returned inside of the structure as well..
    char *packet;
    int packet_size;

    // we should have a decent way of swapping these?
    // either builder function can loop again after using daata size, and 
    // flags.. or it can keep track initially using pointers to set this information
    uint32_t ack;
    uint32_t seq;

    // if all is welll?... if not.. every instruction with the same session id
    // will get disqualified
    int ok;
} PacketBuildInstructions;



