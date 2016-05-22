/*
Bitcoin support and the base coin to copy for adding your own
should turn this into a C++ Class..

notes for later:
when more people start using 'dumb dumb' nodes.. we have to determine if a node is verifying at all
by using two hosts, and giving a transaction that is incorrect and having another node determine if the node
distributes it.. so we can begin to keep track of which nodes we can 'trust' easier

its possible that later one way to detect these nodes is to add in code to see if they blindly distributes
transactions.. using this we can use aother portion of the p2p network against itself

we will only care about 2 messages.. TX (transaction) and blocks...
and maybe the one specifying the blocks found and to restart work

the rest we will ignore..and push these to all our connections

Bitcoin client in <500 lines!
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "list.h"
#include "structs.h"
#include "utils.h"
#include "note_bitcoin.h"

int bitcoin_parse(Modules *note, Connection *conn, char *raw, int size);


Node *node_add(Modules *, uint32_t addr);

// init bitcoin (adding the note to the main loop)
int bitcoin_init(Modules **);
// data read from socket goes here first (decrypting, decompression, whatever necessary)
int bitcoin_read(Modules *, Connection *, char **buf, int *size);
// encrypt/compresss/etc happens here.. then it pushes to the outgoing queue
int bitcoin_write(Modules *, Connection *, char **buf, int *size);
// messages that are read go here afte bitcoin_read() to queue being parsed into the app
int bitcoin_incoming(Modules *, Connection *, char *buf, int size);
// write() should go here last to queue writing to the outgoing socket
int bitcoin_outgoing(Modules *, Connection *, char **buf, int *size);
// loop to deal with timers, logic, etc
int bitcoin_main_loop(Modules *, Connection *, char *buf, int size);
// get updated list of nodes from a third source, request information from some node, etc
int bitcoin_nodes(Modules *, Connection *, char *buf, int size);
// connect to a node
int bitcoin_connect(Modules *note, Connection **connections, uint32_t ip, int port, Connection **_connection);
// build version string
char *bitcoin_build_version(int *size);

int bitcoin_connect_nodes(Modules *note, int count);

int Bitcoin_TX_Parse(Modules *note, Connection *conn, char *raw, int size);

//int bitcoin_parse(CryptoNotes *note, Connection *conn, char *raw, int size);

// bitcoin magic bytes in every packet
char bitcoin_message_magic[5] = "\xf9\xbe\xb4\xd9";


/*
verify bitcoin packet
 0 = not enough data...
 -1 = bad magic
 1 = good
*/
int BC_Message_Header_Verify(Modules *note, char *buf, int size) {
    BCMsgHdr *hdr = (BCMsgHdr *)buf;
    
    if (size < sizeof(BCMsgHdr)) return 0;

    if (size < hdr->size) return 0;
    
    if (memcmp(hdr->magic, note->magic, note->magic_size) == 0)
        return 1;
        
    return -1;
}

ModuleFuncs bitcoin_funcs = { 
    &bitcoin_read,
    &bitcoin_write,
    &bitcoin_incoming,
    &bitcoin_outgoing,
    &bitcoin_nodes,
    NULL, // no connect
    NULL, // no disconnect
    &bitcoin_build_version,
    &bitcoin_connect_nodes
};

Modules CC_Bitcoin = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0, 0,
    // port, state
    8333, 0,
    // required 0, 0..  
    0,
    //timer = 300 seconds (5min) - get new nodes, etc
    300,
    // bitcoin functions
    &bitcoin_funcs, NULL,
    NULL, NULL,
    (char *)&bitcoin_message_magic,
    sizeof(bitcoin_message_magic)
};


// add bitcoin to module list
int bitcoin_init(Modules **_module_list) {
    Module_Add(_module_list, &CC_Bitcoin);
    
}


// connect to X nodes from our internal node list
int bitcoin_connect_nodes(Modules *note, int count) {
    int y = 0;
    Connection *cptr = NULL;
    Connection *cfind = NULL;
    Node *nptr = NULL;
    int ret = 0;
    int c = 0;
    
    while (y < count) {
        for (nptr = note->node_list; nptr != NULL; nptr = nptr->next) {
            if (nptr->connected && nptr->ignore)
                continue;
            
            // if we are already connected to this node
            if (ConnectionFind(note->connections, nptr->addr) != NULL)
                continue;
                
            // logic is sound so lets initiate a connection to this node
            cptr = tcp_connect(note, &note->connections, nptr->addr, note->listen_port, NULL);

            if (cptr != NULL) {
                // but it wont matter since outgoing buffer waits for writable
                int buf_size = 0;    
                // lets queue a version string
                char *buf = note->functions->version_build(&buf_size);
                if (buf != NULL) {        
                    // queue outgoing packet for version (0 for not a relay msg)
                    QueueAdd(note, cptr, &cptr->outgoing, buf, buf_size);

                    cptr->state = BC_STATE_CONN_VER_OUT;

                    // free version string (it was copied in queueadd)
                    free(buf);

                    ret = 1;
                }
            }
         
            // now queue the version string
            // count this so we dont go overboard
            y++;            
        }
    }    
}


int bitcoin_main_loop(Modules *note, Connection *conn, char *buf, int size) {
    // handle tcp/ip for each connection
    // will flush outgoing queue, and fill incoming
    Connection *cptr = NULL;
    
    // handle timers (ping/pong)
    // logic for enough nodes
    int connection_count = L_count((LIST *)note->connections);
    if (connection_count < 30) {
        // attempt to connect to however many nodes we are mising under 30
        note->functions->connect_nodes(note, 30 - connection_count);
        
        // lets find X nodes that we are not connected to and proceed to initiate connections
    }
}




Node *node_find(Modules *note, uint32_t addr) {
    Node *nptr = note->node_list;
    
    while (nptr != NULL) {
        if (nptr->addr == addr) break;
        nptr = nptr->next;
    }
    
    return nptr;
}

Node *node_add(Modules *note, uint32_t addr) {
    Node *nptr = NULL;
    
    // attempt to find node first..
    if ((nptr = node_find(note, addr)) != NULL) return nptr;
    
    // create the node
    if ((nptr = (Node *)L_add((LIST **)&note->node_list, sizeof(Node))) == NULL)
        return NULL;
        
    // set node parameters
    nptr->addr = addr;
    nptr->first_ts = (uint32_t)time(0);
    nptr->last_ts = nptr->first_ts;
    
    return nptr;
}

// obtain node list for connecting to network
// 2 ways this works.. 1 no clients = use DNS seeding
// and 2nd we can ask peers we are connected to for more
// this is pretty dumb for now.. itll just add everything and
// lookup every domain
int bitcoin_nodes(Modules *note, Connection *conn, char *_buf, int _size) {
    char *dns_hosts[] = {
        "bitseed.xf2.org", "dnsseed.bitcoin.dashjr.org",
        "dnsseed.bluematt.me", "seed.bitcoinstats.com",
        "seed.bitcoin.jonasschnelli.ch", "seed.bitcoin.sipa.be",
        "seed.bitnodes.io", NULL
    };
    struct hostent *he = NULL;
    Node *nptr = NULL;
    struct in_addr addr;
    int a = 0, i = 0;
        
    for (a = 0; dns_hosts[a] != NULL; a++) {
        he = gethostbyname2(dns_hosts[a], AF_INET);
        if (he == NULL) continue;
  
        // lets add every node we found..
        while (he->h_addr_list[i] != 0) {
            addr.s_addr = *(u_long *) he->h_addr_list[i++];
            node_add(note, addr.s_addr);
        }

    } 
    
    // since we only have 1 plumbing instead of 2 separate..
    // lets connect if we need more nodes..
    bitcoin_main_loop(note, conn, _buf, _size);
}

// immediately after reading from a socket..
// this isnt useful for bitcoin but can be used to decrypt, or decompress traffic
// for other modules..
int bitcoin_read(Modules *note, Connection *conn, char **buf, int *size) {
    // usage: replace buf / size pointers.. ie: *buf = newbuf, *size = newsize;
    return *size;
}

// a final stage of writing to a socket..
// this isnt useful for bitcoin but can be used to encrypt, or compress traffic
// for other modules..
int bitcoin_write(Modules *note, Connection *conn, char **buf, int *size) {
    return *size;
}

// parsing incoming messages..
// applicatin layer procesing.. after decryption, or decompression
int bitcoin_incoming(Modules *note, Connection *conn, char *buf, int size) {
    int ret = 0;
    
    // use bitcoin parsing function.. which will queue relays, call custom functions, etc..
    ret = bitcoin_parse(note,conn, buf, size);
    
    return ret;
}

// parsing outgoing messages
// to filter, modify etc.. application layer 
int bitcoin_outgoing(Modules *note, Connection *conn, char **buf, int *size) {
    
    // this can be used to filter particular transactions, etc..
    // but its on the outgoing side so the protocol was already used to construct
    // the message.. so only putting here for later coins..
    return *size;
}

char *bitcoin_build_version(int *size) {
    char *buf = NULL;
    char *bptr = NULL;
    
    if ((buf = bptr = (char *)malloc(1024)) == NULL) {
        return NULL;
    }
    memset(buf,0,1024);
    
    // build version parameters for initial packet
    put_int32(&bptr, spoof_version);
    /*
    put_int64(&bptr, nLocalServices);
    put_int64(&bptr, nTime);
    put_uint64(&bptr, addrYou);
    put_uint64(&bptr, addrMe);
    put_uint64(&bptr, nonce);
    */
    put_str(&bptr, "killing bitcoin", 16);

    *size = (int)(bptr - buf);
    
    return buf;    
}

// we must send VERACK here..
int Bitcoin_Version(Modules *note, Connection *conn, char *raw, int size) {
// send ver ack
}

// we consider it connected here..
int Bitcoin_Ack(Modules *note, Connection *conn, char *raw, int size) {
    conn->state = STATE_OK;
}


int bitcoin_parse(Modules *note, Connection *conn, char *raw, int size) {
    int check = BC_Message_Header_Verify(note, raw, size);
    int a = 0, r = 0;
    
    // error must kill connection, or not enough data
    if (check <= 0) return check;
    
    // we have a good packet (full packet)
    BCMsgHdr *hdr = (BCMsgHdr *)raw;
    
    // these are messages that we will redistribute
    struct _messages_to_parse {
        // the message
        char *command;
        // if we want to call a custom function with it (logging, etc)
        CustomCMDParse func;
        // do we relay this to our other connections?
        int relay;
    } Messages[] = {
        { "TX",     &Bitcoin_TX_Parse, 1 },
        { "BLOCK",  NULL, 1 },
        { "VERSION", &Bitcoin_Version, 0 },
        { "VERACK", &Bitcoin_Ack, 0 },
        { NULL,     NULL, 0 }
    };
    
    for (a = 0; Messages[a].command != NULL; a++) {
        if (strncmp(hdr->command, Messages[a].command, strlen(Messages[a].command)) == 0) {
            if (Messages[a].func != NULL) {
                // call our custom fuction with the message here..
                r = Messages[a].func(note, conn, raw, size);
            }
            
            // distribute it out for every peer...
            // it will queeu this message for every connection we have active except this one
            // just as it is without any modifications (for notes that need modificiations.. use the custom function)
            if (r)
                RelayAdd(note, conn, raw, size);
        }
    }
    
    // we dont need the message in the future..
    return 1;
}

/*
tx message:
4	version	int32_t	Transaction data format version (note, this is signed)
1+	tx_in count	var_int	Number of Transaction inputs
41+	tx_in	tx_in[]	A list of 1 or more transaction inputs or sources for coins
1+	tx_out count	var_int	Number of Transaction outputs
9+	tx_out	tx_out[]	A list of 1 or more transaction outputs or destinations for coins
4	lock_time	uint32_t	The block number or timestamp at which this transaction is locked:
Value	Description
0	Not locked
< 500000000	Block number at which this transaction is locked
>= 500000000	UNIX timestamp at which this transaction is locked
If all TxIn inputs have final (0xffffffff) sequence numbers then lock_time is irrelevant. Otherwise, the transaction may not be added to a block until after lock_time (see NLockTime).

TxIn consists of the following fields:

Field Size	Description	Data type	Comments
36	previous_output	outpoint	The previous output transaction reference, as an OutPoint structure
1+	script length	var_int	The length of the signature script
 ?	signature script	uchar[]	Computational Script for confirming transaction authorization
4	sequence	uint32_t	Transaction version as defined by the sender. Intended for "replacement" of transactions when information is updated before inclusion into a block.
The OutPoint structure consists of the following fields:

Field Size	Description	Data type	Comments
32	hash	char[32]	The hash of the referenced transaction.
4	index	uint32_t	The index of the specific output in the transaction. The first output is 0, etc.
The Script structure consists of a series of pieces of information and operations related to the value of the transaction.

(Structure to be expanded in the future… see script.h and script.cpp and Script for more information)

The TxOut structure consists of the following fields:

Field Size	Description	Data type	Comments
8	value	int64_t	Transaction Value
1+	pk_script length	var_int	Length of the pk_script
 ?	pk_script	uchar[]	Usually contains the public key as a Bitcoin script setting up conditions to claim this output.

*/

int Bitcoin_TX_Parse(Modules *note, Connection *conn, char *raw, int size) {
    // 1 = process normally..
    return 1;
}