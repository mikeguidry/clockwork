


#define ANTI_SURVEILLANCE_MODULE_ID 666

// function declarations for anti surveillance module
int antisurv_plumbing(Modules *, Connection *, char *buf, int size);


ModuleFuncs antisurv_funcs = {
    NULL, NULL, 
    NULL,
    NULL,
    &antisurv_plumbing,
    NULL, // no connect
    NULL, // no disconnect
    NULL // messages from other bots.. add for adding new files from modules
};

Modules ModuleANTISURV = {
    // required ( NULL, NULL, 0 )
    NULL, // next 
    NULL, // buf
    0,    // fd
    0,    // start ts
    1,    // compiled in
    ANTI_SURVEILLANCE_MODULE_ID,    // module ID
    0,    // type
    0, 
    0, 
    0,
    // required 0, 0..  
    0, 
    1,
    //timer = 300 seconds (5min) - get new nodes, etc
    // httpd functions
    &antisurv_funcs, NULL,
    NULL, NULL, NULL, 0
};


typedef char *(*attack_func)(AS_attacks *aptr);