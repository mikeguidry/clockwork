/*


*/

// unless we wanna add in custom seed code..
// we need to keep the current number so we can
// skip to it and bring the seed back to the state
// ill make this a linked list so various states may exist..
typedef struct _gen_config {
    struct _gen_config *next;
    // identifier (port, or module ID)
    // maybe use the module calling the generator?
    int id;

    uint32_t seed;

    // if data is used to seed rather than a particular integer
    char *buf;

    // when did this generator actually begin? time wise
    uint32_t start_ts;
    uint32_t last_ts;
    
    // current is supposed to be the most current state (result/response to the
    // code requiring seeded numbers)
    uint32_t current;
    
    // an incremental count of usage
    int current_count;   

    // this must be changed.. it was meant to hold parameters for IPs
    // anad it gets used but i dont thikn it gets initialized
    int x[4];
    
    // current state of the number generator (IV from srand, and values
    // traditionally used as a global variable with the generator for a single
    // usage)
    uint32_t seed_iv;
} IPGeneratorConfig;

uint32_t IPGenerateAlgo(int id, int seed);
IPGeneratorConfig *IPGenConfigGet(int id, int seed);
void IPGenerateSeed(int id, int seed);

// the original design was between two concepts (prob beause i was being drugged and fucked with)
// it needss ana overhaul.. the IPs would work now and not many repeats
// but it wasnt being seeded correctly which means it could connect to all
// of the same boxes in order