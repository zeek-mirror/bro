#ifndef FUZZYVAL_H
#define FUZZYVAL_H

#include "OpaqueVal.h"
#include <fuzzy.h>

#define ROLLING_WINDOW 7
#define NUM_BLOCKHASHES 31
struct blockhash_context
{
    unsigned int dindex;
    char digest [SPAMSUM_LENGTH];
    char halfdigest;
    char h;
    char halfh;
};

struct roll_state 
{
    unsigned char window [ROLLING_WINDOW];
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t n;
};

struct fz_st 
{
    uint_least64_t total_size;    
    uint_least64_t fixed_size;
    uint_least64_t reduce_border;
    unsigned int bhstart;
    unsigned int bhend;
    unsigned int bhendlimit;
    unsigned int flags;
    uint32_t rollmask;
    struct blockhash_context bh [NUM_BLOCKHASHES];
    struct roll_state roll;
    unsigned char lasth;
};


class FUZZYVal : public HashVal {
public:
    static void digest(val_list & vlist, u_char result[FUZZY_MAX_RESULT]);
    
    FUZZYVal();
protected:
    friend class Val;
    
    virtual bool DoInit() override;
    virtual bool DoFeed(const void *data, size_t size) override;
    virtual StringVal *DoGet() override;
    
    DECLARE_SERIAL(FUZZYVal);

    ~FUZZYVal() 
    {
        if (ctx)
            fuzzy_free((struct fuzzy_state *)ctx);        
    }
    
private:
    struct fz_st *ctx = NULL;
};
#endif








