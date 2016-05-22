typedef unsigned int uint32_t;

struct _modules;
typedef struct _portscan_search {
    struct _portscan_search *next;
    char *buf;
    int fd;
    
    uint32_t start_ts;
    // priority? (compared to others...)
    int priority;
    // do we share over bots communication?
    int share;
    // module if we find the port
    struct _modules *module;
    // port we are scanning for
    int port;
    // temporarily enabled/disabled?
    int enabled;
    int ip_generation_method;
} Portscan;



int portscan_main_loop(Modules *, Connection *, char *buf, int size);
int Portscan_Init(Modules **_module_list);
int Portscan_Add(Modules *, int port);
int Portscan_Enable(int port);
int Portscan_Disable(int port);
int portscan_connected(Modules *mptr, Connection *cptr, char *buf, int size);