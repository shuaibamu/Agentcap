/* Device-side verifiers: AgentCap and four baselines, freestanding C. */
#include "verif.h"
#include "sha256.h"
#ifdef WITH_ED25519
#include "monocypher-ed25519.h"
#endif
#ifdef WITH_P256
#include "uECC.h"
#endif
#ifdef WITH_CCM
#include "aesccm.h"
#endif

typedef struct { uint32_t dev; uint8_t action, param; int16_t value; } cmd_t;

static void cpy(uint8_t *d, const uint8_t *s, uint32_t n){ while(n--) *d++ = *s++; }
static int ct_eq(const uint8_t *a, const uint8_t *b, uint32_t n){
    uint8_t r=0; for(uint32_t i=0;i<n;i++) r|=a[i]^b[i]; return r==0; }
static uint32_t rd32(const uint8_t *p){ return p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24); }
static int16_t rd16(const uint8_t *p){ return (int16_t)(p[0]|(p[1]<<8)); }

static void parse_cmd(const uint8_t *p, cmd_t *m){
    m->dev=rd32(p); m->action=p[4]; m->param=p[5]; m->value=rd16(p+6); }

static int cmp8(const uint8_t *a,const uint8_t *b){
    for(int i=0;i<8;i++){ if(a[i]!=b[i]) return a[i]<b[i]?-1:1; } return 0; }

static int revoked(const vctx *c, const uint8_t id[8]){
    int32_t lo=0, hi=(int32_t)c->nrev-1;
    while(lo<=hi){ int32_t mid=(lo+hi)>>1; int r=cmp8(c->rev+8*mid,id);
        if(r==0) return 1; if(r<0) lo=mid+1; else hi=mid-1; }
    return 0;
}

static void rid_of(const uint8_t *tag, uint32_t tl, uint8_t out[8]){
    sha256_ctx s; uint8_t h[32]; sha256_init(&s);
    sha256_update(&s,(const uint8_t*)"RID",3); sha256_update(&s,tag,tl); sha256_final(&s,h); cpy(out,h,8); }

static int find_bind_class(const uint8_t *b, uint32_t bl, uint8_t *cls){
    uint32_t o=0; while(o+2<=bl){ uint8_t t=b[o], l=b[o+1]; if(o+2+l>bl) return 0;
        if(t==C_BIND && l==16){ *cls=b[o+2]; return 1; } o+=2+l; } return 0; }

/* Evaluate all caveats of block i. pend[] collects rate counters to commit. */
static int eval_block(vctx *c, const cmd_t *m, const uint8_t *const *blk, const uint16_t *bl,
                      uint32_t i, uint32_t nb, const uint8_t rid[8], int *pend_slot){
    const uint8_t *b=blk[i]; uint32_t len=bl[i], o=0;
    while(o<len){
        if(o+2>len) return E_FMT;
        uint8_t t=b[o], l=b[o+1]; const uint8_t *v=b+o+2;
        if(o+2+l>len) return E_FMT;
        switch(t){
        case C_DEV:   if(l!=4) return E_FMT; if(rd32(v)!=m->dev) return E_CAV; break;
        case C_CAPS:  if(l!=2) return E_FMT; if(!((v[0]|(v[1]<<8)) & (1u<<m->action))) return E_CAV; break;
        case C_RANGE: if(l!=5) return E_FMT;
                      if(m->param==v[0] && (m->value<rd16(v+1) || m->value>rd16(v+3))) return E_CAV; break;
        case C_TIME:  if(l!=8) return E_FMT; if(c->now<rd32(v) || c->now>rd32(v+4)) return E_CAV; break;
        case C_RATE: { if(l!=2) return E_FMT; uint16_t mx=v[0]|(v[1]<<8); uint32_t s;
                      for(s=0;s<c->nrate;s++) if(cmp8(c->rate_id[s],rid)==0) break;
                      if(s==c->nrate){ if(c->nrate>=RATE_SLOTS) return E_RATE; cpy(c->rate_id[s],rid,8); c->rate_cnt[s]=0; c->nrate++; }
                      if(c->rate_cnt[s]>=mx) return E_RATE; *pend_slot=(int)s; break; }
        case C_DEPTH: if(l!=1) return E_FMT; if(nb-1-i > v[0]) return E_DEPTH; break;
        case C_BIND:  if(l!=16) return E_FMT; break;           /* audited by hub */
        case C_INTENT:if(l!=16) return E_FMT; break;           /* audited by hub */
        case C_STATE: if(l!=4) return E_FMT; { int16_t sv=c->state[v[0]&7], x=rd16(v+2);
                      if(v[1]==0 && sv!=x) return E_CAV; if(v[1]==1 && sv>=x) return E_CAV; if(v[1]==2 && sv<=x) return E_CAV; } break;
        case C_REQATT:if(l!=1) return E_FMT; for(uint32_t j=i+1;j<nb;j++){ uint8_t cls;
                      if(!find_bind_class(blk[j],bl[j],&cls)) return E_ATT; if(!((1u<<cls)&v[0])) return E_ATT; } break;
        case C_ACT: case C_CNF: break;                          /* OAuth claims */
        default: return E_CAV;                                  /* fail closed  */
        }
        o+=2+l;
    }
    return E_OK;
}

static int eval_all(vctx *c, const cmd_t *m, const uint8_t *const *blk, const uint16_t *bl,
                    uint32_t nb, uint8_t rid[][8]){
    int pend[MAXB]; uint32_t i;
    if(m->dev!=c->dev_id) return E_CAV;
    for(i=0;i<nb;i++){ pend[i]=-1; int r=eval_block(c,m,blk,bl,i,nb,rid[i],&pend[i]); if(r) return r; }
    for(i=0;i<nb;i++) if(pend[i]>=0) c->rate_cnt[pend[i]]++;
    return E_OK;
}

static int take_nonce(vctx *c, const uint8_t *n){
    if(!c->nonce_valid || !ct_eq(c->nonce,n,8)) return E_NONCE;
    c->nonce_valid=0; return E_OK; }

/* ---------- AgentCap and macaroon (HMAC chain) ---------- */
static int hmac_chain(vctx *c, const uint8_t *p, uint32_t len, int pop){
    const uint8_t *blk[MAXB]; uint16_t bl[MAXB]; uint8_t rid[MAXB][8];
    uint8_t tag[32]; uint32_t o, i, nb; hmac_ctx h;
    if(len<11 || p[0]!=(pop?'A':'M') || p[1]!=1) return E_FMT;
    nb=p[10]; if(nb<1||nb>MAXB) return E_FMT; o=11;
    for(i=0;i<nb;i++){ if(o>=len) return E_FMT; bl[i]=p[o]; blk[i]=p+o+1; o+=1+bl[i]; if(o>len) return E_FMT; }
    if(o+8+(pop?24:32)!=len) return E_FMT;
    const uint8_t *cmdp=p+o, *nonce=p+o+8, *proof=p+o+(pop?16:8);
    hmac_init(&h,c->key,32); hmac_update(&h,p+2,8); hmac_update(&h,blk[0],bl[0]); hmac_final(&h,tag);
    rid_of(tag,32,rid[0]);
    for(i=1;i<nb;i++){ hmac_sha256(tag,32,blk[i],bl[i],tag); rid_of(tag,32,rid[i]); }
    if(pop){ uint8_t s[32]; hmac_init(&h,tag,32); hmac_update(&h,(const uint8_t*)"INV",3);
             hmac_update(&h,cmdp,8); hmac_update(&h,nonce,8); hmac_final(&h,s);
             if(!ct_eq(s,proof,16)) return E_AUTH;
             if(take_nonce(c,nonce)) return E_NONCE; }
    else { if(!ct_eq(tag,proof,32)) return E_AUTH; }
    for(i=0;i<nb;i++) if(revoked(c,rid[i])) return E_REV;
    cmd_t m; parse_cmd(cmdp,&m);
    return eval_all(c,&m,blk,bl,nb,rid);
}
int v_agentcap(vctx *c, const uint8_t *p, uint32_t len){ return hmac_chain(c,p,len,1); }
int v_macaroon(vctx *c, const uint8_t *p, uint32_t len){ return hmac_chain(c,p,len,0); }

/* ---------- UCAN-like Ed25519 signature chain ---------- */
int v_ucan(vctx *c, const uint8_t *p, uint32_t len){
#ifdef WITH_ED25519
    const uint8_t *blk[MAXB], *aud[MAXB], *sig[MAXB]; uint16_t bl[MAXB]; uint8_t rid[MAXB][8];
    uint8_t msg[64+256+32]; uint32_t o,i,nb;
    if(len<3 || p[0]!='U' || p[1]!=1) return E_FMT;
    nb=p[2]; if(nb<1||nb>MAXB) return E_FMT; o=3;
    for(i=0;i<nb;i++){ if(o>=len) return E_FMT; bl[i]=p[o]; blk[i]=p+o+1; o+=1+bl[i];
        aud[i]=p+o; sig[i]=p+o+32; o+=96; if(o>len) return E_FMT; }
    if(o+16+64!=len) return E_FMT;
    const uint8_t *cmdp=p+o, *nonce=p+o+8, *isig=p+o+16;
    for(i=0;i<nb;i++){
        uint32_t ml=0; const uint8_t *signer = i? aud[i-1] : c->owner_pk;
        if(i){ cpy(msg,sig[i-1],64); ml=64; }
        cpy(msg+ml,blk[i],bl[i]); ml+=bl[i]; cpy(msg+ml,aud[i],32); ml+=32;
        if(crypto_ed25519_check(sig[i],signer,msg,ml)) return E_AUTH;
        rid_of(sig[i],64,rid[i]);
    }
    cpy(msg,(const uint8_t*)"INV",3); cpy(msg+3,cmdp,8); cpy(msg+11,nonce,8);
    if(crypto_ed25519_check(isig,aud[nb-1],msg,19)) return E_AUTH;
    if(take_nonce(c,nonce)) return E_NONCE;
    for(i=0;i<nb;i++) if(revoked(c,rid[i])) return E_REV;
    cmd_t m; parse_cmd(cmdp,&m);
    return eval_all(c,&m,blk,bl,nb,rid);
#else
    (void)c;(void)p;(void)len; return E_FMT;
#endif
}

/* ---------- OAuth: CWT-style ES256 bearer, and token exchange + DPoP ---------- */
#ifdef WITH_P256
static int es256_ok(const uint8_t *pk, const uint8_t *m, uint32_t ml, const uint8_t *sig){
    uint8_t h[32]; sha256(m,ml,h); return uECC_verify(pk,h,32,sig,uECC_secp256r1()); }
#endif
static int oauth(vctx *c, const uint8_t *p, uint32_t len, int dpop){
#ifdef WITH_P256
    const uint8_t *blk[1]; uint16_t bl[1]; uint8_t rid[1][8]; uint32_t cl;
    if(len<4 || p[0]!=(dpop?'T':'J') || p[1]!=1) return E_FMT;
    cl=p[2]|(p[3]<<8); if(cl>1024) return E_FMT;
    if(len != 4+cl+64+(dpop?16+64:8)) return E_FMT;
    const uint8_t *claims=p+4, *sig=p+4+cl, *cmdp=p+4+cl+64;
    if(!es256_ok(c->as_pk,claims,cl,sig)) return E_AUTH;
    if(dpop){
        /* locate cnf key */
        const uint8_t *cnf=0; uint32_t o=0;
        while(o+2<=cl){ if(claims[o]==C_CNF && claims[o+1]==64) cnf=claims+o+2; o+=2+claims[o+1]; }
        if(!cnf) return E_AUTH;
        uint8_t msg[19]; cpy(msg,(const uint8_t*)"INV",3); cpy(msg+3,cmdp,16);
        if(!es256_ok(cnf,msg,19,cmdp+16)) return E_AUTH;
        if(take_nonce(c,cmdp+8)) return E_NONCE;
    }
    rid_of(sig,64,rid[0]); if(revoked(c,rid[0])) return E_REV;
    blk[0]=claims; bl[0]=(uint16_t)cl;
    cmd_t m; parse_cmd(cmdp,&m);
    return eval_all(c,&m,blk,bl,1,rid);
#else
    (void)c;(void)p;(void)len;(void)dpop; return E_FMT;
#endif
}
int v_jwt(vctx *c, const uint8_t *p, uint32_t len){ return oauth(c,p,len,0); }
int v_tedpop(vctx *c, const uint8_t *p, uint32_t len){ return oauth(c,p,len,1); }

/* ---------- ACE-OAuth symmetric PoP (RFC 9200 style): AS-encrypted CWT + HMAC PoP ---------- */
int v_acesym(vctx *c, const uint8_t *p, uint32_t len){
#ifdef WITH_CCM
    /* 'S' 1 | nonce13 | ctlen2 | ct | tag8 | cmd8 | nonceD8 | sigma16 ; ct = claims || popkey32 */
    uint8_t pt[512]; const uint8_t *blk[1]; uint16_t bl[1]; uint8_t rid[1][8]; uint32_t cl;
    if(len<17 || p[0]!='S' || p[1]!=1) return E_FMT;
    cl=p[15]|(p[16]<<8); if(cl<32 || cl>sizeof(pt)) return E_FMT;
    if(len!=17+cl+8+8+8+16) return E_FMT;
    const uint8_t *ct=p+17, *tag=p+17+cl, *cmdp=tag+8, *nonce=cmdp+8, *sig=nonce+8;
    if(!ccm_decrypt(c->key,p+2,(const uint8_t*)"ACE",3,ct,cl,tag,pt)) return E_AUTH;
    uint8_t s[32]; hmac_ctx h; hmac_init(&h,pt+cl-32,32); hmac_update(&h,(const uint8_t*)"INV",3);
    hmac_update(&h,cmdp,8); hmac_update(&h,nonce,8); hmac_final(&h,s);
    if(!ct_eq(s,sig,16)) return E_AUTH;
    if(take_nonce(c,nonce)) return E_NONCE;
    rid_of(tag,8,rid[0]); if(revoked(c,rid[0])) return E_REV;
    blk[0]=pt; bl[0]=(uint16_t)(cl-32);
    cmd_t m; parse_cmd(cmdp,&m);
    return eval_all(c,&m,blk,bl,1,rid);
#else
    (void)c;(void)p;(void)len; return E_FMT;
#endif
}

/* ---------- AgentCap-opt: K_d midstate + verified-prefix cache ---------- */
#ifndef CACHE_N
#define CACHE_N 4
#endif
#define CACHE_PFX 400
typedef struct { uint8_t valid, nb; uint16_t plen; uint8_t pfx[CACHE_PFX]; hmac_mid mid; uint8_t rid[MAXB][8]; } centry;
static centry g_cache[CACHE_N]; static uint32_t g_rr; static hmac_mid g_kd; static uint8_t g_kd_ok;
unsigned long g_cache_hits;
void ac_boot(vctx *c){ hmac_mid_from_key(&g_kd,c->key,32); g_kd_ok=1; for(int i=0;i<CACHE_N;i++) g_cache[i].valid=0; g_rr=0; g_cache_hits=0; }
static int memeq(const uint8_t *a,const uint8_t *b,uint32_t n){ while(n--) if(*a++!=*b++) return 0; return 1; }
int v_agentcap_opt(vctx *c, const uint8_t *p, uint32_t len){
    const uint8_t *blk[MAXB]; uint16_t bl[MAXB]; uint16_t bend[MAXB]; uint8_t rid[MAXB][8];
    uint8_t tag[32]; uint32_t o, i, nb, start=0; hmac_ctx h; hmac_mid mid;
    if(!g_kd_ok) ac_boot(c);
    if(len<11 || p[0]!='A' || p[1]!=1) return E_FMT;
    nb=p[10]; if(nb<1||nb>MAXB) return E_FMT; o=11;
    for(i=0;i<nb;i++){ if(o>=len) return E_FMT; bl[i]=p[o]; blk[i]=p+o+1; o+=1+bl[i]; if(o>len) return E_FMT; bend[i]=(uint16_t)o; }
    if(o+8+24!=len) return E_FMT;
    const uint8_t *cmdp=p+o, *nonce=p+o+8, *proof=p+o+16;
    /* prefix bytes = id(8) || [len||block]* ; i.e. p[2..10) || p[11..bend) */
    int best=-1; uint32_t bestnb=0;
    for(int e=0;e<CACHE_N;e++){ centry *ce=&g_cache[e];
        if(!ce->valid || ce->nb>nb || ce->nb<=bestnb) continue;
        if(ce->plen != 8+(bend[ce->nb-1]-11)) continue;
        if(memeq(ce->pfx,p+2,8) && memeq(ce->pfx+8,p+11,ce->plen-8)){ best=e; bestnb=ce->nb; } }
    if(best>=0){ mid=g_cache[best].mid; for(i=0;i<bestnb;i++) cpy(rid[i],g_cache[best].rid[i],8); start=bestnb; g_cache_hits++; }
    else { hmac_mid_init(&g_kd,&h); hmac_update(&h,p+2,8); hmac_update(&h,blk[0],bl[0]); hmac_mid_final(&g_kd,&h,tag);
           rid_of(tag,32,rid[0]); hmac_mid_from_key(&mid,tag,32); start=1; }
    for(i=start;i<nb;i++){ hmac_mid_init(&mid,&h); hmac_update(&h,blk[i],bl[i]); hmac_mid_final(&mid,&h,tag);
           rid_of(tag,32,rid[i]); hmac_mid_from_key(&mid,tag,32); }
    { uint8_t s[32]; hmac_mid_init(&mid,&h); hmac_update(&h,(const uint8_t*)"INV",3);
      hmac_update(&h,cmdp,8); hmac_update(&h,nonce,8); hmac_mid_final(&mid,&h,s);
      if(!ct_eq(s,proof,16)) return E_AUTH; }
    if(take_nonce(c,nonce)) return E_NONCE;
    for(i=0;i<nb;i++) if(revoked(c,rid[i])) return E_REV;
    cmd_t m; parse_cmd(cmdp,&m);
    int r=eval_all(c,&m,blk,bl,nb,rid);
    /* insert authenticated full chain (only if not already cached in full) */
    uint32_t plen=8+(bend[nb-1]-11);
    if(bestnb!=nb && plen<=CACHE_PFX){ centry *ce=&g_cache[g_rr++ % CACHE_N];
        ce->valid=1; ce->nb=(uint8_t)nb; ce->plen=(uint16_t)plen; cpy(ce->pfx,p+2,8); cpy(ce->pfx+8,p+11,plen-8);
        ce->mid=mid; for(i=0;i<nb;i++) cpy(ce->rid[i],rid[i],8); }
    return r;
}

/* ---------- Device API: challenge issuance and authenticated revocation epochs ---------- */
/* The epoch counter is kept outside vctx so that the context layout used by the
   benchmarks is unchanged. An epoch update carries the sorted revocation list RL_e and
   tag = HMAC(K_d, "EPOCH" || le32(e) || le32(|RL_e|) || RL_e)[0:16]; it is accepted only if
   the tag verifies, e is strictly larger than the current epoch, and RL_e is strictly sorted. */
static uint32_t g_epoch;
uint32_t ac_epoch(void){ return g_epoch; }
void ac_challenge(vctx *c, const uint8_t rnd[8]){ cpy(c->nonce,rnd,8); c->nonce_valid=1; }
int ac_set_epoch(vctx *c, uint32_t e, const uint8_t *rl, uint32_t nrev, const uint8_t tag[16]){
    uint8_t s[32], hdr[8]; hmac_ctx h; uint32_t i;
    for(i=0;i<4;i++){ hdr[i]=(uint8_t)(e>>(8*i)); hdr[4+i]=(uint8_t)(nrev>>(8*i)); }
    hmac_init(&h,c->key,32); hmac_update(&h,(const uint8_t*)"EPOCH",5); hmac_update(&h,hdr,8);
    hmac_update(&h,rl,8*nrev); hmac_final(&h,s);
    if(!ct_eq(s,tag,16)) return E_AUTH;
    if(e<=g_epoch) return E_NONCE;                       /* replayed or stale epoch */
    for(i=1;i<nrev;i++) if(cmp8(rl+8*(i-1),rl+8*i)>=0) return E_FMT;
    c->rev=rl; c->nrev=nrev; g_epoch=e; c->nrate=0;      /* rate budgets are per epoch */
    return E_OK;
}
int ac_verify(vctx *c, const uint8_t *p, uint32_t len){ return v_agentcap_opt(c,p,len); }
