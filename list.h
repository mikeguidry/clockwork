typedef struct _link { struct _link *next; } LINK;


LINK *l_last(LINK *);
LINK *l_add(LINK **, int);
void l_del(LINK **, LINK *);
int l_count(LINK *);

// new type of list which will free a buffer automatically while deleting
// will start using after expanding to multiple buffers
typedef struct _list { struct _list *next; void *buf; int fd; } LIST;

LIST *L_last(LIST *);
LIST *L_add(LIST **, int);
void L_del(LIST **, LIST *);
int L_count(LIST *);
// same as other except for use in loops.. gives the next for the loops
// to block requiring a secondary parameters
void L_del_next(LIST **, LIST *, LIST **);