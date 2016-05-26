
typedef struct _attack {
    struct _attack *next;
    char *buf;
    int fd;
    uint32_t start_ts;
    
    int end_interval;
    uint32_t src;
    int src_port;
    uint32_t dst;
    int dst_port;
    int attack_type;
    int enabled;
} Attack;


int attack_syn_flood(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_fin_flood(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_connect_flood(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_udp(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_ddos_smurf(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_ddos_dns(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_ddos_ntp(Modules *mptr, Connection *cptr, char *buf, int size);
int attack_init(Modules **module_list);