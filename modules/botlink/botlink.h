typedef struct CmdHdr {
    unsigned char cmd;
    unsigned short size;
} CMDHdr;


int botlink_init(Modules **);
int botlink_main_loop(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_write(Modules *mptr, Connection *cptr, char **buf, int *size);
int botlink_read(Modules *mptr, Connection *cptr, char **buf, int *size);
int botlink_incoming(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_outgoing(Modules *mptr, Connection *cptr, char **buf, int *size);
int botlink_connect(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_disconnect(Modules *mptr, Connection *cptr, char *buf, int size);

int botlink_handshake(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_keyexchange(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_message(Modules *mptr, Connection *cptr, char *buf, int size);