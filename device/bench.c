#include <stddef.h>
#include "verif.h"
#include "sha256.h"
_Static_assert(offsetof(vctx,rev)==24,"rev");_Static_assert(offsetof(vctx,nonce)==32,"n");
_Static_assert(offsetof(vctx,rate_cnt)==170,"rc");_Static_assert(offsetof(vctx,nrate)==204,"nr");
_Static_assert(offsetof(vctx,key)==208,"k");_Static_assert(offsetof(vctx,as_pk)==272,"as");_Static_assert(sizeof(vctx)==336,"sz");
volatile unsigned long g_comp;
int bench(vctx *c, const uint8_t *p, uint32_t len){
    sha256_compressions=0; int r = SCHEME(c,p,len); g_comp=sha256_compressions; return r; }
void bench_boot(vctx *c){
#ifdef OPT
    ac_boot(c);
#else
    (void)c;
#endif
}
