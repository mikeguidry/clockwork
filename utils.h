void put_int32(char **bptr, int32_t a);
void put_int64(char **bptr, int64_t a);
void put_uint64(char **bptr, uint64_t a);
void put_str(char **bptr, char *str, int size);
int32_t get_int32(char **bptr);
int64_t get_int64(char **bptr);
uint64_t get_uint64(char **bptr);

//int Note_Add(CryptoNotes *note);
int stateOK(Connection *cptr);
uint32_t getOurIPv4();



int sock_printf(Modules *mptr, Connection *cptr, char *fmt, ...);
void print_hex(char *buf, int size);