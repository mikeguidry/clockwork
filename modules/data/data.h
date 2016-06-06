typedef struct _data_entry {
    struct _data_entry *next;
    char *name;
    char *buf;
    uint32_t start_ts;
    
    int size;
    // type? loaded from /tmp? etc?
    int type;
    // do we share this object?
    int share;
    // is the local copy complete?
    int local;
} Data;


int data_init(Modules **module_list);
char *data_get(int id);