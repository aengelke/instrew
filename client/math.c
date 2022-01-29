
#include <stdint.h>

#define I32_AS_F32(vi) ((union { int32_t i; float f; }) { .i = vi }.f)
#define I64_AS_F64(vi) ((union { int64_t i; double d; }) { .i = vi }.d)
#define F32_AS_I32(v) ((union { int32_t i; float f; }) { .f = v }.i)
#define F64_AS_I64(v) ((union { int64_t i; double d; }) { .d = v }.i)
#define EXP_F32(vi) ((((vi) >> 23) & 0xff) - 0x7f)
#define EXP_F64(vi) ((((vi) >> 52) & 0x7ff) - 0x3ff)

float
floorf(float v) {
    int32_t vi = F32_AS_I32(v);
    int exp = EXP_F32(vi);
    if (exp < 0) { // less than one
        // < 0 -> -1, else sign(v) * 0
        return vi == INT32_MIN ? -0.0f : vi < 0 ? -1.0f : 0.0f;
    } else if (exp < 23) {
        int32_t msk = 0x7fffff >> exp;
        return I32_AS_F32((vi + (vi < 0 ? msk : 0)) & ~msk);
    } else { // integral, Inf, or NaN
        return v;
    }
}

double
floor(double v) {
    int64_t vi = F64_AS_I64(v);
    int exp = EXP_F64(vi);
    if (exp < 0) { // less than one
        // < 0 -> -1, else sign(v) * 0
        return vi == INT64_MIN ? -0.0 : vi < 0 ? -1.0 : 0.0;
    } else if (exp < 52) {
        int64_t msk = 0xfffffffffffff >> exp;
        return I64_AS_F64((vi + (vi < 0 ? msk : 0)) & ~msk);
    } else { // integral, Inf, or NaN
        return v;
    }
}

float
ceilf(float v) {
    int32_t vi = F32_AS_I32(v);
    int exp = EXP_F32(vi);
    if (exp < 0) { // less than one
        // <= 0 -> sign(v) * 0, else 1
        return vi < 0 ? -0.0f : vi == 0 ? 0.0f : 1.0f;
    } else if (exp < 23) {
        int32_t msk = 0x7fffff >> exp;
        return I32_AS_F32((vi + (vi >= 0 ? msk : 0)) & ~msk);
    } else { // integral, Inf, or NaN
        return v;
    }
}

double
ceil(double v) {
    int64_t vi = F64_AS_I64(v);
    int exp = EXP_F64(vi);
    if (exp < 0) { // less than one
        // <= 0 -> sign(v) * 0, else 1
        return vi < 0 ? -0.0 : vi == 0 ? 0.0 : 1.0;
    } else if (exp < 52) {
        int64_t msk = 0xfffffffffffff >> exp;
        return I64_AS_F64((vi + (vi >= 0 ? msk : 0)) & ~msk);
    } else { // integral, Inf, or NaN
        return v;
    }
}

float
roundf(float v) {
    int32_t vi = F32_AS_I32(v);
    int exp = EXP_F32(vi);
    if (exp < -1) { // less than 0.5
        return I32_AS_F32(vi & 0x80000000);
    } else if (exp == -1) { // between 0.5 and 1
        return vi < 0 ? -1.0f : 1.0f;
    } else if (exp < 23) {
        int32_t msk = 0x7fffff >> exp;
        if (vi & msk) // v is not integral
            return I32_AS_F32((vi + (1 + (msk >> 1))) & ~msk);
        return v;
    } else { // integral, Inf, or NaN
        return v;
    }
}

double
round(double v) {
    int64_t vi = F64_AS_I64(v);
    int exp = EXP_F64(vi);
    if (exp < -1) { // less than 0.5
        return I64_AS_F64(vi & 0x8000000000000000);
    } else if (exp == -1) { // between 0.5 and 1
        return vi < 0 ? -1.0 : 1.0;
    } else if (exp < 52) {
        int64_t msk = 0xfffffffffffff >> exp;
        if (vi & msk) // v is not integral
            return I64_AS_F64((vi + (1 + (msk >> 1))) & ~msk);
        return v;
    } else { // integral, Inf, or NaN
        return v;
    }
}

float
truncf(float v) {
    int32_t vi = F32_AS_I32(v);
    int exp = EXP_F32(vi);
    if (exp < 0) { // less than one
        // < 0 -> -1, else sign(v) * 0
        return vi < 0 ? -0.0f : 0.0f;
    } else if (exp < 23) {
        int32_t msk = 0x7fffff >> exp;
        return I32_AS_F32(vi & ~msk);
    } else { // integral, Inf, or NaN
        return v;
    }
}

double
trunc(double v) {
    int64_t vi = F64_AS_I64(v);
    int exp = EXP_F64(vi);
    if (exp < 0) { // less than one
        // < 0 -> -1, else sign(v) * 0
        return vi < 0 ? -0.0 : 0.0;
    } else if (exp < 52) {
        int64_t msk = 0xfffffffffffff >> exp;
        return I64_AS_F64(vi & ~msk);
    } else { // integral, Inf, or NaN
        return v;
    }
}

float
fmaf(float x, float y, float z) {
    return (x * y) + z; // TODO: actually perform fused multiply-add
}

double
fma(double x, double y, double z) {
    return (x * y) + z; // TODO: actually perform fused multiply-add
}

#ifdef TEST
#include <inttypes.h>
#include <stdio.h>

int
main(void) {
    unsigned count = 0;
    unsigned failed = 0;
#define CASE(FLOAT_TY, F_AS_I, PRIxN, a, b) do { \
        count++; \
        FLOAT_TY _a = (a), _b = (b); \
        unsigned ok = F_AS_I(_a) == F_AS_I(_b); \
        printf("%s %d - " #a " == " #b "\n", &"not ok"[4*ok], count); \
        if (!ok) { \
            printf("# %lf (%"PRIxN") != %lf (%"PRIxN")\n", \
                   _a, F_AS_I(_a), _b, F_AS_I(_b)); \
            failed++; \
        } \
    } while (0)
#define CASE_F32(a, b) CASE(float, F32_AS_I32, PRIx32, a, b)
#define CASE_F64(a, b) CASE(double, F64_AS_I64, PRIx64, a, b)

    CASE_F32(floorf(+0.0f), +0.0f);
    CASE_F32(floorf(-0.0f), -0.0f);
    CASE_F32(floorf(-0.5f), -1.0f);
    CASE_F32(floorf(+0.1f), +0.0f);
    CASE_F32(floorf(-1.0f), -1.0f);
    CASE_F32(floorf(+1.125f), +1.0f);
    CASE_F32(floorf(-1.125f), -2.0f);
    CASE_F32(floorf(+63.0f), +63.0f);
    CASE_F32(floorf(-63.0f), -63.0f);
    CASE_F32(floorf(+63.5f), +63.0f);
    CASE_F32(floorf(-63.5f), -64.0f);
    CASE_F32(floorf((int32_t) 1 << 24), (int32_t) 1 << 24);
    CASE_F32(floorf(((int32_t) 1 << 24) + 2), ((int32_t) 1 << 24) + 2);

    CASE_F64(floor(+0.0), +0.0);
    CASE_F64(floor(-0.0), -0.0);
    CASE_F64(floor(-0.5), -1.0);
    CASE_F64(floor(+0.1), +0.0);
    CASE_F64(floor(-1.0), -1.0);
    CASE_F64(floor(+1.125), +1.0);
    CASE_F64(floor(-1.125), -2.0);
    CASE_F64(floor(+63.0), +63.0);
    CASE_F64(floor(-63.0), -63.0);
    CASE_F64(floor(+63.5), +63.0);
    CASE_F64(floor(-63.5), -64.0);
    CASE_F64(floor((int64_t) 1 << 53), (int64_t) 1 << 53);
    CASE_F64(floor(((int64_t) 1 << 53) + 2), ((int64_t) 1 << 53) + 2);

    CASE_F32(ceilf(+0.0f), +0.0f);
    CASE_F32(ceilf(-0.0f), -0.0f);
    CASE_F32(ceilf(-0.5f), -0.0f);
    CASE_F32(ceilf(+0.1f), +1.0f);
    CASE_F32(ceilf(-1.0f), -1.0f);
    CASE_F32(ceilf(+1.125f), +2.0f);
    CASE_F32(ceilf(-1.125f), -1.0f);
    CASE_F32(ceilf(+63.0f), +63.0f);
    CASE_F32(ceilf(-63.0f), -63.0f);
    CASE_F32(ceilf(+63.5f), +64.0f);
    CASE_F32(ceilf(-63.5f), -63.0f);
    CASE_F32(ceilf((int32_t) 1 << 24), (int32_t) 1 << 24);
    CASE_F32(ceilf(((int32_t) 1 << 24) + 2), ((int32_t) 1 << 24) + 2);

    CASE_F64(ceil(+0.0), +0.0);
    CASE_F64(ceil(-0.0), -0.0);
    CASE_F64(ceil(-0.5), -0.0);
    CASE_F64(ceil(+0.1), +1.0);
    CASE_F64(ceil(-1.0), -1.0);
    CASE_F64(ceil(+1.125), +2.0);
    CASE_F64(ceil(-1.125), -1.0);
    CASE_F64(ceil(+63.0), +63.0);
    CASE_F64(ceil(-63.0), -63.0);
    CASE_F64(ceil(+63.5), +64.0);
    CASE_F64(ceil(-63.5), -63.0);
    CASE_F64(ceil((int64_t) 1 << 53), (int64_t) 1 << 53);
    CASE_F64(ceil(((int64_t) 1 << 53) + 2), ((int64_t) 1 << 53) + 2);

    CASE_F32(roundf(+0.0f), +0.0f);
    CASE_F32(roundf(-0.0f), -0.0f);
    CASE_F32(roundf(+0.25f), +0.0f);
    CASE_F32(roundf(-0.25f), -0.0f);
    CASE_F32(roundf(+0.5f), +1.0f);
    CASE_F32(roundf(-0.5f), -1.0f);
    CASE_F32(roundf(+1.0f), +1.0f);
    CASE_F32(roundf(-1.0f), -1.0f);
    CASE_F32(roundf(+1.125f), +1.0f);
    CASE_F32(roundf(-1.125f), -1.0f);
    CASE_F32(roundf(+1.5f), +2.0f);
    CASE_F32(roundf(-1.5f), -2.0f);
    CASE_F32(roundf(+1.625f), +2.0f);
    CASE_F32(roundf(-1.625f), -2.0f);
    CASE_F32(roundf(+63.0f), +63.0f);
    CASE_F32(roundf(-63.0f), -63.0f);
    CASE_F32(roundf(+63.5f), +64.0f);
    CASE_F32(roundf(-63.5f), -64.0f);
    CASE_F32(roundf((int32_t) 1 << 24), (int32_t) 1 << 24);
    CASE_F32(roundf(((int32_t) 1 << 24) + 2), ((int32_t) 1 << 24) + 2);

    CASE_F64(round(+0.0), +0.0);
    CASE_F64(round(-0.0), -0.0);
    CASE_F64(round(+0.25), +0.0);
    CASE_F64(round(-0.25), -0.0);
    CASE_F64(round(+0.5), +1.0);
    CASE_F64(round(-0.5), -1.0);
    CASE_F64(round(+1.0), +1.0);
    CASE_F64(round(-1.0), -1.0);
    CASE_F64(round(+1.125), +1.0);
    CASE_F64(round(-1.125), -1.0);
    CASE_F64(round(+1.5), +2.0);
    CASE_F64(round(-1.5), -2.0);
    CASE_F64(round(+1.625), +2.0);
    CASE_F64(round(-1.625), -2.0);
    CASE_F64(round(+63.0), +63.0);
    CASE_F64(round(-63.0), -63.0);
    CASE_F64(round(+63.5), +64.0);
    CASE_F64(round(-63.5), -64.0);
    CASE_F64(round((int64_t) 1 << 53), (int64_t) 1 << 53);
    CASE_F64(round(((int64_t) 1 << 53) + 2), ((int64_t) 1 << 53) + 2);

    CASE_F32(truncf(+0.0f), +0.0f);
    CASE_F32(truncf(-0.0f), -0.0f);
    CASE_F32(truncf(+0.25f), +0.0f);
    CASE_F32(truncf(-0.25f), -0.0f);
    CASE_F32(truncf(+0.5f), +0.0f);
    CASE_F32(truncf(-0.5f), -0.0f);
    CASE_F32(truncf(+1.0f), +1.0f);
    CASE_F32(truncf(-1.0f), -1.0f);
    CASE_F32(truncf(+1.125f), +1.0f);
    CASE_F32(truncf(-1.125f), -1.0f);
    CASE_F32(truncf(+1.5f), +1.0f);
    CASE_F32(truncf(-1.5f), -1.0f);
    CASE_F32(truncf(+1.625f), +1.0f);
    CASE_F32(truncf(-1.625f), -1.0f);
    CASE_F32(truncf(+63.0f), +63.0f);
    CASE_F32(truncf(-63.0f), -63.0f);
    CASE_F32(truncf(+63.5f), +63.0f);
    CASE_F32(truncf(-63.5f), -63.0f);
    CASE_F32(truncf((int32_t) 1 << 24), (int32_t) 1 << 24);
    CASE_F32(truncf(((int32_t) 1 << 24) + 2), ((int32_t) 1 << 24) + 2);

    CASE_F64(trunc(+0.0), +0.0);
    CASE_F64(trunc(-0.0), -0.0);
    CASE_F64(trunc(+0.25), +0.0);
    CASE_F64(trunc(-0.25), -0.0);
    CASE_F64(trunc(+0.5), +0.0);
    CASE_F64(trunc(-0.5), -0.0);
    CASE_F64(trunc(+1.0), +1.0);
    CASE_F64(trunc(-1.0), -1.0);
    CASE_F64(trunc(+1.125), +1.0);
    CASE_F64(trunc(-1.125), -1.0);
    CASE_F64(trunc(+1.5), +1.0);
    CASE_F64(trunc(-1.5), -1.0);
    CASE_F64(trunc(+1.625), +1.0);
    CASE_F64(trunc(-1.625), -1.0);
    CASE_F64(trunc(+63.0), +63.0);
    CASE_F64(trunc(-63.0), -63.0);
    CASE_F64(trunc(+63.5), +63.0);
    CASE_F64(trunc(-63.5), -63.0);
    CASE_F64(trunc((int64_t) 1 << 53), (int64_t) 1 << 53);
    CASE_F64(trunc(((int64_t) 1 << 53) + 2), ((int64_t) 1 << 53) + 2);

    printf("1..%u\n", count);
    return failed != 0;
}
#endif
