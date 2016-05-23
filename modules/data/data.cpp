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

Data *data_list = NULL;

int data_init(Modules **module_list) {
    
}

char *data_get(int id) {
    
}