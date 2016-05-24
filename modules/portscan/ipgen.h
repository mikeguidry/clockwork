// unless we wanna add in custom seed code..
// we need to keep the current number so we can
// skip to it and bring the seed back to the state
// ill make this a linked list so various states may exist..
typedef struct _gen_config {
    struct _gen_config *next;
    char *buf;
    int fd;
    uint32_t start_ts;
    
    int id;
    uint32_t current;
    uint32_t seed;
    int current_count;   
    int x[4]; 
} IPGeneratorConfig;

uint32_t IPGenerateAlgo(int seed);