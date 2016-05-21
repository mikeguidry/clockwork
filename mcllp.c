/*
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
dogecoin,
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
allows new modules in easy fashion + quicker replicating and updating remotely
--

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include "structs.h"
#include "list.h"

#define MAX(a, b) ((a) > (b) ? ( a) : (b))

CryptoNotes *notes = NULL;
Modules *modules = NULL;

// prepare fd set / fd & max fds for select()
void setup_fd(fd_set *fdset, fd_set *fdset2, fd_set *fdset3, int *max_fd, int fd) {
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
    // can write now.. check outgoing queue
    // do we have an outgoing queue to deal with?
    if (cptr->outgoing != NULL) {
        // flush it!
        qptr = cptr->outgoing;
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
            }
        }
    }    
}

void ConnectionBad(Connection *cptr) {
    // close socket
    close(cptr->fd);
    // mark for deletion    
    cptr->closed = 1;
}

void ConnectionCleanup(Connection **conn_list) {
    Connection *cptr = NULL;
    for (cptr = *conn_list; cptr != NULL; ) {
        if (cptr->closed) {
            // remove the connection.. and get the next element from it
            L_del_next((LIST **)conn_list, (LIST *)cptr, (LIST **)&cptr);            
        } else {
            // if we didnt remove it.. the next is simple to iterate
            cptr = cptr->next;
        }
    }
}


// select & handle i/o of sockets
void tcp_socket_loop(CryptoNotes *notes) {
    CryptoNotes *nptr = NULL;
    Modules *mptr = NULL;
    Connection *cptr = NULL;
    Queue *qptr = cptr->outgoing;
    Queue *qnext = NULL;
    Connection *modcptr = NULL;
    int maxfd = 0;
    struct timeval ts;
    
    ts.tv_sec = 2;

    fd_set readfds;
    fd_set writefds;
    fd_set errorfds;
    
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&errorfds);
    
    for (nptr = notes; nptr != NULL; nptr = nptr->next) {
        for (cptr = notes->connections; cptr != NULL; cptr = cptr->next) {
            if (cptr->closed) continue;
            
            setup_fd(&readfds, &writefds, &errorfds, cptr->fd, &maxfd);
        }
    }
    
    // setup all possible module file descriptors for select
    for (mptr = modules; mptr != NULL; mptr = mptr->next) {
        // the module may have several Connection as well
        for (modcptr = mptr->connections; modcptr != NULL; modcptr = modcptr->next)
            setup_fd(&readfds, &writefds, &errorfds, modcptr->fd, &maxfd);    
    }
    
    if (select(maxfd, &readfds, &writefds, &errorfds, &ts) > 0) {

        // loop to check module file descriptors first
        for (mptr = modules; mptr != NULL; mptr = mptr->next) {
            // the module may have several Connection as well
            for (modcptr = mptr->connections; modcptr != NULL; modcptr = modcptr->next) {
                if (FD_ISSET(modcptr->fd, &readfds))
                    ConnectionRead(modcptr);
                    
                if (FD_ISSET(modcptr->fd,&writefds))
                    OutgoingFlush(cptr);

                if (FD_ISSET(modcptr->fd, &errorfds))
                    ConnectionBad(modcptr);

            }
            
            // cleanup stale Connection
            ConnectionCleanup(&mptr->connections);        
        }
   
        // now loop to check crypto currencies Connection
        for (nptr = notes; nptr != NULL; nptr = nptr->next) {            
            for (cptr = nptr->connections; cptr != NULL; cptr = cptr->next) {
                if (cptr->closed) continue;
                
                if (FD_ISSET(cptr->fd, &readfds))
                    // put through incoming (for decryption etc) and then into incoming queue
                    ConnectionRead(cptr);
                
                // we check our outgoing queue here if we can write to the socket
                if (FD_ISSET(cptr->fd, &writefds))
                    OutgoingFlush(cptr);
                
                if (FD_ISSET(cptr->fd, &errorfds))
                    ConnectionBad(cptr);
            }
            
            // cleanup stale Connection
            ConnectionCleanup(&nptr->connections);
        }
    }
}

Connection *Connection_find(Connection *list, uint32_t addr) {
    Connection *cptr = list;
    
    while (cptr != NULL) {
        if (cptr->addr == addr) break;
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
 //   ioctl(cptr->fd, FIONREAD, &waiting);
    if (!waiting) return;

    // lets add a little more just in case a fragment came in
    size = waiting + 1024;    
    buf = (char *)malloc(size + 1);
    if (buf == NULL) {
        // handle error..
        ConnectionBad(cptr);
        return;
    }
    
    // read X bytes from socket..
    r = read(cptr->fd, buf, size);
    // verify we read something.. if not its bad
    if (r <= 0) {
        ConnectionBad(cptr);
        return;
    }

    newqueue = (Queue *)l_add((LIST **)&cptr->incoming, sizeof(Queue));
    if (newqueue == NULL) {
        // error!
        ConnectionBad(cptr);
    }
    
    // all is well..
    newqueue->buf = buf;
    newqueue->size = size;
}

// handle basic TCP/IP (input/output)
void tcp_main_loop(CryptoNotes *notes) {
    Queue *qptr = NULL;
    CryptoNotes *nptr = NULL;
    Connection *cptr = NULL;
    // first handle all socket I/O...
    tcp_socket_loop(notes);
    
    // now we can handle crypto currency/application specific handling
    for (nptr = notes; nptr != NULL; nptr = nptr->next) {
        // loop for each note's Connection'
        for (cptr = nptr->connections; cptr != NULL; cptr = cptr->next) {
            // do we have an incoming queue to deal with?
            if (cptr->incoming != NULL) {
                
                // lets attempt to merge messages that may be fragmented in the queue
                QueueMerge(&cptr->incoming);  
                
                for (qptr = cptr->incoming; qptr != NULL; ) {
                    // first we hit our read function..maybe compressed, or encrypted
                    nptr->functions->read(nptr, cptr, qptr->buf, qptr->size);
                    
                    // parse data w specific note's parser
                    nptr->functions->incoming(nptr, cptr, qptr->buf, qptr->size);
                    
                    L_del_next((LIST **)&cptr->incoming, (LIST *)qptr, (LIST **)&qptr);                
                }
            }
            // outgoing gets handled in tcp_socket_loop() (yes i know it happens on the next loop)
        }
    }
}


// Queus data outgoing to the other p2p conenctins just as it is given..
// returns how many times its been queued
// relay = if its coming from another node for p2p..
// 0 means absolutely hit the specific connection
int QueueAdd(CryptoNotes *note, Connection *conn, Queue **queue, int relay, char *buf, int size) {
    int ret = -1;
    char *start_buf = buf;
    Connection *cptr = NULL;
    Queue *newqueue = NULL;
    char *newbuf = NULL;
    
    // does application layer processing (maybe filtering, modification)
    if (note->functions->outgoing(note, conn, &buf, &size)) {
        // now we have to call the ->write function to encrypt, or compress
        // needs pointers to buf/size to replace it if need be..
        if (note->functions->write(note, conn, &buf, &size)) {
            // loop for each connection in this note
            for (cptr = note->connections; cptr != NULL; cptr = cptr->next) {
                // if we are not relaying and its not our connection.. move on
                // if we ARE relaying and it is the same connection.. skip
                // *** rewrite this.. maybe separate into two functions
                if ((!relay && cptr != conn) || (relay && cptr == conn)) continue;
                
                newbuf = (char *)malloc(size + 1);
                if (newbuf == NULL) {
                    return -1;
                }
                
                memcpy(newbuf, buf, size);
                
                newqueue = (Queue *)l_add((LIST **)(queue ? queue : cptr->outgoing), sizeof(Queue));
                if (newqueue == NULL) {
                    // handle error here..
                    return -1;
                }
            
                newqueue->buf = newbuf;
                
                newqueue->size = size;
                
                ret = 1;
            }
        }
    }

    // free buf if it was modified during outgoing/write
    if (start_buf != buf) free(buf);
    
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
    if ((count = l_count(qptr)) < 2) return 0;
    
    // i'll start by merging only 1 at a time.. the msg just wont process if its too short..
    // another loop and it should be fine
    // speed is irrelevant for this operation
    if (count >= 2) {
        // get the next buffer waiting..
        qptr2 = qptr->next;
        // calculate size of both
        size = qptr->size + qptr2->size;
        
        if ((buf = malloc(size + 1)) == NULL)
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



// we will use a simple main in the beginning...
// i want this to be a library, or a very simple node
int main(int argc, char *argv[]) {
    
}