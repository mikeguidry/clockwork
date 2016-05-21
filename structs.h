
#define STATE_OK 1024

typedef unsigned int uint32_t;
// queue for outgoing messages, or incoming parsing.. etc..
typedef struct _queue {
    struct _queue *next;
    
    // queue buffer
    char *buf;
    
    // fd goes here to auto close connections with L_del
    int empty;
    
    // queue size
    int size;
} Queue;

enum {
    // tcp connection
    TYPE_TCP,
    // udp socket (for sending)
    TYPE_UDP,
    // bound udp to a port
    TYPE_UDP_BIND,
    // bound tcp to a port
    TYPE_TCP_LISTEN,
    // raw socket
    TYPE_RAW,
    TCP_NEW,
    TCP_CONNECTED
};

typedef struct _connection {
    struct _connection *next;
 
     // buffer (if message parsing, etc requires)
    char *buf;

    // file descriptor/socket
    int fd;
    
    // list its on
    struct _connection **list;
    
    int buf_size;
       
    uint32_t addr;
    
    int type;
    
    
    // ip of connection
    uint32_t ip;
    // port we're connecting to
    unsigned short port;
    // time stamp
    uint32_t start_ts;
    
    // last ping / pong
    uint32_t ping_ts;
    
    // state of connection
    int connection_state;
    
    Queue *incoming;
    Queue *outgoing;
    
    // is it closed and should be recycled?
    int closed;
    
    int state;
    
    // function table
    // for write() func during outgoing flush
    void *func_table_ptr;
} Connection;

// function declaration for our notes..
struct _modules;
typedef int (*module_func)(struct _modules *, Connection *, char *, int);
typedef int (*module_func_ptr)(struct _modules *, Connection *, char **, int *);
// this next one is specifically for crypto currencies.. so we can use same code for bitcoin/litecoin/etc
typedef char *(*build_version_func)(int *);
typedef int (*connect_nodes_func)(struct _modules *note, int count);

// declaration for other modules
// such as: DHT, Spammer, IRC Bot, WORM,
// Port Scan, etc..

typedef struct _module_funcs {
    // read incoming data (in case encryption)
    // this needs a new func type with pointers to buf, size to replace them if need be
    module_func_ptr read_ptr;
    // writing outgoing data (in case encryption)
    module_func_ptr write_ptr;
    // incoming message parsing
    module_func incoming;
    // parsing outgoing messages (maybe filtering, etc)
    // needs function ponters like read..
    module_func_ptr outgoing;
    // obtain nodes for connection
    // all currency should do this immediately on startup, and every 15-20minutes
    module_func plumbing;
    // how do we find nodes to connect to?
    module_func main_loop;
    // build version for crypto currencies
    build_version_func version_build;
    
    connect_nodes_func connect_nodes;
} ModuleFuncs;

struct _bitcoin_nodes;

// current status of note
typedef struct _modules {
    struct _modules *next;
    
    // any buffer maybe required (itll get free'd on remove)
    char *buf;
    // fd has to be in place (if its not 0 itll get closed)
    int fd;
    
    // if we are attempting to listen
    int listen_port;
    // state of crypto currency (our connections, etc)
    int state;
    
    // timers for loops/logic/etc
    uint32_t start_ts;
    uint32_t timer_ts;
    int timer_interval;

    
    ModuleFuncs *functions;
    Connection *connections;
    
    struct _bitcoin_nodes *node_list;
    
    // any kind of custom data that has to be passed around
    void *custom_data;
    
    // magic bytes for crypto currencies
    char *magic;
    
    // size of magic bytes
    int magic_size;
} Modules;

Connection *Connection_find(Connection *list, uint32_t addr);
int RelayAdd(Modules *module, Connection *conn, char *buf, int size);
int QueueAdd(Modules *module, Connection *conn, Queue **queue, char *buf, int size);
int Module_Add(Modules **_module_list, Modules *newmodule);
int tcp_connect(Modules *note, Connection **connections, uint32_t ip, int port, Connection **_conn);