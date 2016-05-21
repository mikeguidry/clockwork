
int telnet_main_loop(Modules *, Connection *, char *buf, int size);
int telnet_init(Modules **_module_list);
int telnet_disconnect(Modules *mptr, Connection *cptr, char *buf, int size);