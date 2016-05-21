
int telnet_read(Modules *, Connection *, char **buf, int *size);
int telnet_write(Modules *, Connection *, char **buf, int *size);
int telnet_incoming(Modules *, Connection *, char *buf, int size);
int telnet_outgoing(Modules *, Connection *, char *buf, int size);
int telnet_main_loop(Modules *, Connection *, char *buf, int size);
int telnet_nodes(Modules *, Connection *, char *buf, int size);
int telnet_connect(Modules *, Connection **, uint32_t ip, int port);
int telnet_init(Modules **_module_list);