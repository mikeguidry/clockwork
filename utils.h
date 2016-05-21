void put_int32(char **bptr, int32_t a);
void put_int64(char **bptr, int64_t a);
void put_uint64(char **bptr, uint64_t a);
void put_str(char **bptr, char *str, int size);


//int Note_Add(CryptoNotes *note);
int stateOK(Connection *cptr);