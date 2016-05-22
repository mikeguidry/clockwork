#include <stdint.h>
#include <string.h>
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