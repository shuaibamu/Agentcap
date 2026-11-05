#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
typedef struct { uint32_t s[8]; uint8_t buf[64]; uint32_t n; uint64_t len; } sha256_ctx;
typedef struct { sha256_ctx in; uint8_t okey[64]; } hmac_ctx;
extern unsigned long sha256_compressions;
void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c,const uint8_t *d,uint32_t l);
void sha256_final(sha256_ctx *c,uint8_t out[32]);
void sha256(const uint8_t *d,uint32_t l,uint8_t out[32]);
void hmac_init(hmac_ctx *h,const uint8_t *key,uint32_t kl);
void hmac_update(hmac_ctx *h,const uint8_t *d,uint32_t l);
void hmac_final(hmac_ctx *h,uint8_t out[32]);
void hmac_sha256(const uint8_t *key,uint32_t kl,const uint8_t *d,uint32_t l,uint8_t out[32]);
#endif
#ifndef SHA256_MID
#define SHA256_MID
typedef struct { uint32_t is[8]; uint32_t os[8]; } hmac_mid;
void hmac_mid_from_key(hmac_mid *m, const uint8_t *key, uint32_t kl);
void hmac_mid_init(const hmac_mid *m, hmac_ctx *h);   /* start a MAC from midstate */
void hmac_mid_final(const hmac_mid *m, hmac_ctx *h, uint8_t out[32]);
#endif
