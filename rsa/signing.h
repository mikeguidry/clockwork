int SignCreate(RSA *privkey, char *data, int dataLen, char *signature, int *signature_len);
int SignCheck(RSA *pubkey,  char *data, int dataLen, char *signature, int signature_len);
RSA *LoadPrivate(char *file);
RSA *LoadPublic(char *file);
char *FileContents(char *filename, int *ret_size);
int FileWrite(char *filename, char *data, int size);
