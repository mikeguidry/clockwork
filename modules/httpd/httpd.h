
typedef struct _offered_files {
    struct _offered_files *next;
    char *filename;
    char *data;
    int data_size;
    int type; // static file, or real directory
} Content;


// init httpd (adding the note to the main loop)
int httpd_init(Modules **);
