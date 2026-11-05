#ifndef VERIF_H
#define VERIF_H
#include <stdint.h>

#define MAXB 16
#define RATE_SLOTS 16

/* error codes */
#define E_OK 0
#define E_FMT -1
#define E_AUTH -2
#define E_CAV -3
#define E_REV -4
#define E_NONCE -5
#define E_RATE -6
#define E_DEPTH -7
#define E_ATT -8

/* caveat types */
#define C_DEV 0x01
#define C_CAPS 0x02
#define C_RANGE 0x03
#define C_TIME 0x04
#define C_RATE 0x05
#define C_DEPTH 0x06
#define C_BIND 0x07
#define C_INTENT 0x08
#define C_STATE 0x09
#define C_REQATT 0x0B
#define C_ACT 0x0C
#define C_CNF 0x0D

typedef struct {
    uint32_t dev_id;
    uint32_t now;
    int16_t state[8];
    const uint8_t *rev; uint32_t nrev;      /* sorted 8-byte revoked chain ids */
    uint8_t nonce[8]; uint8_t nonce_valid;  /* outstanding device challenge     */
    uint8_t rate_id[RATE_SLOTS][8]; uint16_t rate_cnt[RATE_SLOTS]; uint32_t nrate;
    uint8_t key[32];                        /* AgentCap / macaroon root key K_d */
    uint8_t owner_pk[32];                   /* UCAN-like: owner Ed25519 key     */
    uint8_t as_pk[64];                      /* OAuth: AS P-256 public key       */
} vctx;

int v_agentcap(vctx *c, const uint8_t *p, uint32_t len);
int v_macaroon(vctx *c, const uint8_t *p, uint32_t len);
int v_ucan(vctx *c, const uint8_t *p, uint32_t len);
int v_jwt(vctx *c, const uint8_t *p, uint32_t len);
int v_tedpop(vctx *c, const uint8_t *p, uint32_t len);
int v_acesym(vctx *c, const uint8_t *p, uint32_t len);
int v_agentcap_opt(vctx *c, const uint8_t *p, uint32_t len);
void ac_boot(vctx *c);
void ac_challenge(vctx *c, const uint8_t rnd[8]);
int ac_set_epoch(vctx *c, uint32_t e, const uint8_t *rl, uint32_t nrev, const uint8_t tag[16]);
uint32_t ac_epoch(void);
int ac_verify(vctx *c, const uint8_t *p, uint32_t len);
extern unsigned long g_cache_hits;
#endif
