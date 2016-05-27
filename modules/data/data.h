typedef struct _data_entry {
    struct _data_entry *next;
    char *name;
    char *buf;
    int size;
} Data;


int data_init(Modules **module_list);
char *data_get(int id);