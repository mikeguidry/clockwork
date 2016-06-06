/*
takes a trace output file (in raw uint32_t format), parses, and writes a unique file (thus shedding a massive amount of space)
this final file will be used in the actual compression part..

to start it'll feed UPX during compression to remove the unwanted areas
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

typedef struct _addr {
	struct _addr *next;
	uint64_t address;	
} Addr;

Addr *address_list = NULL;

int addr_check(uint64_t addr) {
  Addr *aptr = address_list;

  while (aptr != NULL) {
    if (aptr->address == addr)  {
	return 0;
    }

    aptr = aptr->next;
  }

  aptr = (Addr *)calloc(1,sizeof(Addr));
  if (aptr == NULL) {
    perror("malloc");
    exit(-1);
  }

  aptr->address = addr;

  aptr->next = address_list;
  address_list = aptr;

  return 1;
}


int main(int argc, char *argv[]) {
FILE *fd, *ofd;
char buf[1024];
int i = 0;
uint64_t raddr = 0;
int in = 0, out = 0;

fd = fopen(argv[1], "rb");
ofd = fopen(argv[2], "wb");
while (fread(&raddr, sizeof(uint64_t), 1, fd)) {
in++;
	if (addr_check(raddr)) {
		out++;
		fwrite(&raddr, sizeof(uint64_t),1, ofd);
	}
}

fclose(fd);
fclose(ofd);

printf("in: %d out: %d\n", in, out);

return -1;
}
