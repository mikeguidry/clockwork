
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

enum {
    // new is brand new connection
    HTTP_STATE_NEW,
    // headers is waiting for headers.. (after GET, etc)
    HTTP_STATE_HEADERS,
    // when a file is queued to them.. set to this..
    HTTP_STATE_DOWNLOADING,
    // complete = state OK, or done.. we can time out after 15... or close before
    HTTP_STATE_COMPLETE=1024,
    TYPE_STATIC,
    TYPE_DIRECTORY,
};


// init httpd (adding the note to the main loop)
int httpd_init(Modules **);

Content *ContentAddStatic(char *filename, char *data, int size, int type, char *content_type);
int ContentAddFile(char *filename, char *uri, char *ctype);
int httpd_unlisten(int port);
int httpd_listen(int port);
int ContentDelete(char *uri);
Content *ContentFindByName(char *filename);
Content *ContentAdd(char *filename, char *uri, char *data, int size, int type, char *content_type);