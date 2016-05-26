
typedef struct _offered_files {
    struct _offered_files *next;
    char *filename;
    char *uri;
    char *data;
    char *content_type;
    int data_size;
    int temporary;
    int type; // static file, or real directory
} Content;


// init httpd (adding the note to the main loop)
int httpd_init(Modules **);

Content *ContentAddStatic(char *filename, char *data, int size, int type, char *content_type);
int ContentAddFile(char *filename, char *uri, char *ctype);
int httpd_unlisten(int port);
int httpd_listen(int port);
