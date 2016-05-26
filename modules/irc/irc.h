typedef struct _irc_connection {
    struct _irc_connection *next;
    char *buf;
    int fd;
    uint32_t start_ts;
    
    
    char *server;
    int port;
    
    char *nickname;
    
    
} IRC_Client_Connection;


int irc_client_init(Modules **);

int irc_client_main_loop(Modules *mptr, Connection *cptr, char *buf, int size);
int irc_client_connected(Modules *mptr, Connection *cptr, char *buf, int size);
int irc_client_incoming(Modules *mptr, Connection *cptr, char *buf, int size);
int irc_client_outgoing(Modules *mptr, Connection *cptr, char **buf, int *size);
