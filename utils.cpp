#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdarg.h>
#include "structs.h"

void put_int32(char **bptr, int32_t a) {
    int32_t *b = (int32_t *)*bptr;
    *b = a;
    *bptr += sizeof(int32_t);
}

void put_int64(char **bptr, int64_t a) {
    int64_t *b = (int64_t *)*bptr;
    *b = a;
    *bptr += sizeof(int64_t);
}

void put_uint64(char **bptr, uint64_t a) {
    uint64_t *b = (uint64_t *)*bptr;
    *b = a;
    *bptr += sizeof(uint64_t);
}

void put_str(char **bptr, char *str, int size) {
    char *dst = (char *)*bptr;
    memcpy(dst, str, size);
    *bptr += size;
}

int stateOK(Connection *cptr) {
    return (cptr->state & STATE_OK);
}

/*
  Chippy1337 and @packetprophet present:
  LizardStresser rekt
  is where i found these next functions
*/
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int got = 1, total = 0;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got == 0 ? NULL : buffer;
}

uint32_t getOurIPv4() {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == -1) return 0;

	struct sockaddr_in serv;
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr("8.8.8.8");
	serv.sin_port = htons(53);

	int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
	if(err == -1) return 0;

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);
	if(err == -1) return 0;

	//ourIP.s_addr = name.sin_addr.s_addr;
/*
	int cmdline = open("/proc/net/route", O_RDONLY);
    if (cmdline > 0) {
        char linebuf[4096];
        while(fdgets((unsigned char *)linebuf, 4096, cmdline) != NULL)
        {
            if(strstr(linebuf, "\t00000000\t") != NULL)
            {
                unsigned char *pos = (unsigned char *)linebuf;
                while(*pos != '\t') pos++;
                *pos = 0;
                break;
            }
            memset(linebuf, 0, 4096);
        }
        close(cmdline);
    }


	if(*linebuf)
	{
		int i;
		struct ifreq ifr;
		strcpy(ifr.ifr_name, linebuf);
		ioctl(sock, SIOCGIFHWADDR, &ifr);
		for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
	}
    */

	close(sock);
    
    return name.sin_addr.s_addr;
}



// just a google for 'vsnprintf' example
int sock_printf(Modules *mptr, Connection *cptr, char *fmt, ...) {
    va_list va;
    char buf[16384];
    int ret = 0;
    int len = 0;
    
    va_start(va, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, va);
    
    ret = QueueAdd(mptr, cptr, NULL, buf, len);
    
    va_end(va);
    
    return ret;
}
