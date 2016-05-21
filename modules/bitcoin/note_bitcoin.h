int bitcoin_init(Modules **);


typedef struct _bitcoin_nodes {
    // first 3 are required in this order..
    struct _bitcoin_nodes *next;
    
    char *buf;
    
    int fd;
    
    uint32_t addr;
    
    int connected;
    
    // did we connect directly?
    int direct;
    // ignore ? is it dead, etc
    int ignore;
    // first seen
    uint32_t first_ts;
    // last seen
    uint32_t last_ts;
    
    int failures;
} BitcoinNode;


BitcoinNode *bitcoin_node_add(Modules *note, uint32_t addr);

int BC_Message_Header_Verify(char *buf, int size);



// states for bitcoin, connections, etc..
enum {
    // new connection outgoing.. sent VERSION
    // leaving NEW_OUT for other currencies, but bitcoin sends
    // version on connect.. so it goes to VER_ACK immediately
    // ok so this first one is a non blocking connection out
    BC_STATE_CONN_NEW_OUT,
    // and this is an established and sent VERSION
    BC_STATE_CONN_VER_OUT,
    
    
    // new connection incoming. waiting on version?
    BC_STATE_CONN_NEW_IN,
        
    // sent ACK for new clients version.. and sent our version
    BC_STATE_CONN_VER_ACK,
    
    // requesting nodes
    BC_STATE_NODE_REQ,
    
    // handshake OK.. connection is flowing normally..
    BC_STATE_CONN_NORMAL
};

// this is the bitcoin protocol format of every message
// if it doesnt match this then the connection is either broke
// or a bug exist
typedef struct _msg_header {
    char magic[4];
    char command[12];
    unsigned int size;
    char chk[4];
} BCMsgHdr;



// version of the protocol we will spoof
#define spoof_version 70012


int bitcoin_read(Modules *note, Connection *conn, char **buf, int *size);
int bitcoin_write(Modules *note, Connection *conn, char **buf, int *size);
int bitcoin_incoming(Modules *note, Connection *conn, char *buf, int size);
int bitcoin_outgoing(Modules *note, Connection *conn, char *buf, int size);
int bitcoin_main_loop(Modules *note, Connection *conn, char *buf, int size);
int bitcoin_connect_nodes(Modules *note, int count);
typedef int (*CustomCMDParse)(Modules *note, Connection *conn, char *raw, int size);
