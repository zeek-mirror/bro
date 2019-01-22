
#include "Fuzzy.h"
#include "NetVar.h"
#include "Serializer.h"
#include "Reporter.h"


inline const char *fuzzy_digest_print(const u_char digest[FUZZY_MAX_RESULT])
{
    return digest_print(digest, FUZZY_MAX_RESULT);
}

FUZZYVal::FUZZYVal() : HashVal(fuzzy_type)
{

}

void FUZZYVal::digest(val_list& vlist, u_char result[FUZZY_MAX_RESULT])
{

    struct fuzzy_state *h;

    h = fuzzy_new();
    if ( h == NULL) {
        reporter->Error("Failed to init fuzzy hash context");
        return;
    }

    loop_over_list(vlist, i)
    {
        Val *v = vlist[i];
        if ( v->Type()->Tag() == TYPE_STRING) {
            const BroString *str = v->AsString();
            if (fuzzy_update(h, str->Bytes(), str->Len())){
                reporter->Error("Failed to update fuzzy hash");
                goto error;
            }
        } else {
            ODesc d(DESC_BINARY);
            v->Describe(&d);
            if (fuzzy_update(h, (const u_char *)d.Bytes(), d.Len())) {
                reporter->Error("Failed to update fuxzy hash");
                goto error;
            }
        }
    }

    if (fuzzy_digest((const struct fuzzy_state *)h, (char *)result, FUZZY_FLAG_ELIMSEQ)) {
        reporter->Error("Failed to collect digest");
    }
    fuzzy_free(h);
    return;
error:
    fuzzy_free(h);
    assert(1);
    return;
}

bool FUZZYVal::DoInit()
{

    assert(! IsValid());
    if (ctx) fuzzy_free((struct fuzzy_state *)ctx);
    ctx = (struct fz_st *)fuzzy_new();
    return ctx ? true:false;
}

bool FUZZYVal::DoFeed(const void *data, size_t size)
{
    if ( ! IsValid()) {
        reporter->Error("%s-%d inivalid fuzzy hash object found",
                        __FUNCTION__, __LINE__);
        return false;
    }


    if (fuzzy_update((struct fuzzy_state *)ctx, (const u_char *)data, size))
    {
        reporter->Error("%s-%d Failed to update fuzzy hash",
                        __FUNCTION__, __LINE__);
        return false;
    }
    return true;
}


StringVal *FUZZYVal::DoGet()
{
    if (! IsValid())
        return new StringVal("");
    char digest[FUZZY_MAX_RESULT];

    fuzzy_digest((struct fuzzy_state *)ctx, digest, FUZZY_FLAG_ELIMSEQ);
    return new StringVal((char *)digest);
}


IMPLEMENT_SERIAL(FUZZYVal, SER_FUZZY_VAL);

bool FUZZYVal::DoSerialize(SerialInfo *info) const
{
    int i, j;

    DO_SERIALIZE(SER_FUZZY_VAL, HashVal);

    if (! IsValid() )
        return true;

    if ( ! (SERIALIZE(ctx->total_size) &&
            SERIALIZE(ctx->fixed_size) &&
            SERIALIZE(ctx->reduce_border) &&
            SERIALIZE(ctx->bhstart) &&
            SERIALIZE(ctx->bhend) &&
            SERIALIZE(ctx->bhendlimit) &&
            SERIALIZE(ctx->flags)))
        return false;

    for (i = 0; i < NUM_BLOCKHASHES; i++) {
        if ( ! SERIALIZE(ctx->bh[i].dindex))
            return false;

        for (j = 0; j < SPAMSUM_LENGTH; j ++) {
            if (! SERIALIZE(ctx->bh[i].digest[j]))
                return false;
        }
        if (! SERIALIZE(ctx->bh[i].halfdigest)) {
            return false;
        }

        if (! SERIALIZE(ctx->bh[i].h)) return false;

        if (! SERIALIZE(ctx->bh[i].halfh)) return false;
    }

    for (i = 0; i < ROLLING_WINDOW; i++) {
        if (! SERIALIZE(ctx->roll.window[i])) return false;
    }

    if (! SERIALIZE(ctx->roll.h1)) return false;

    if (! SERIALIZE(ctx->roll.h2)) return false;

    if (! SERIALIZE(ctx->roll.h3)) return false;

    if (! SERIALIZE(ctx->roll.n)) return false;

    if (! SERIALIZE(ctx->lasth)) return false;

    return true;

}

bool FUZZYVal::DoUnserialize(UnserialInfo* info)
{
    int i, j;

    DO_UNSERIALIZE(HashVal);

    if (! IsValid()) return true;

    if ( ! (UNSERIALIZE(&ctx->total_size) &&
            UNSERIALIZE(&ctx->fixed_size) &&
            UNSERIALIZE(&ctx->reduce_border) &&
            UNSERIALIZE(&ctx->bhstart) &&
            UNSERIALIZE(&ctx->bhend) &&
            UNSERIALIZE(&ctx->bhendlimit) &&
            UNSERIALIZE(&ctx->flags)))
        return false;

    for (i = 0; i < NUM_BLOCKHASHES; i++) {
        if ( ! UNSERIALIZE(&ctx->bh[i].dindex))
            return false;

        for (j = 0; j < SPAMSUM_LENGTH; j ++) {
            if (! UNSERIALIZE(&ctx->bh[i].digest[j]))
                return false;
        }
        if (! UNSERIALIZE(&ctx->bh[i].halfdigest)) {
            return false;
        }

        if (! UNSERIALIZE(&ctx->bh[i].h)) return false;

        if (! UNSERIALIZE(&ctx->bh[i].halfh)) return false;
    }

    for (i = 0; i < ROLLING_WINDOW; i++) {
        if (! UNSERIALIZE((char *)(&ctx->roll.window[i]))) return false;
    }

    if (! UNSERIALIZE(&ctx->roll.h1)) return false;

    if (! UNSERIALIZE(&ctx->roll.h2)) return false;

    if (! UNSERIALIZE(&ctx->roll.h3)) return false;

    if (! UNSERIALIZE(&ctx->roll.n)) return false;

    if (! UNSERIALIZE((char *)(&ctx->lasth))) return false;

    return true;
}
