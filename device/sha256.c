/* Minimal SHA-256 and HMAC-SHA256 (FIPS 180-4, RFC 2104), freestanding. */
#include "sha256.h"

static const uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

unsigned long sha256_compressions = 0;

static void compress(uint32_t s[8], const uint8_t b[64]) {
    uint32_t w[64], a,bb,c,d,e,f,g,h,t1,t2; int i;
    sha256_compressions++;
    for (i=0;i<16;i++) w[i]=((uint32_t)b[4*i]<<24)|((uint32_t)b[4*i+1]<<16)|((uint32_t)b[4*i+2]<<8)|b[4*i+3];
    for (i=16;i<64;i++){uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1;}
    a=s[0];bb=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for (i=0;i<64;i++){t1=h+(ROR(e,6)^ROR(e,11)^ROR(e,25))+((e&f)^(~e&g))+K[i]+w[i];
        t2=(ROR(a,2)^ROR(a,13)^ROR(a,22))+((a&bb)^(a&c)^(bb&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;}
    s[0]+=a;s[1]+=bb;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

void sha256_init(sha256_ctx *c){
    static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for(int i=0;i<8;i++)c->s[i]=iv[i]; c->n=0; c->len=0;
}
void sha256_update(sha256_ctx *c,const uint8_t *d,uint32_t l){
    while(l--){c->buf[c->n++]=*d++; c->len++; if(c->n==64){compress(c->s,c->buf);c->n=0;}}
}
void sha256_final(sha256_ctx *c,uint8_t out[32]){
    uint64_t bits=c->len*8; uint8_t z=0x80; sha256_update(c,&z,1); z=0;
    while(c->n!=56) sha256_update(c,&z,1);
    for(int i=7;i>=0;i--){uint8_t b=(uint8_t)(bits>>(8*i)); c->buf[c->n++]=b;}
    compress(c->s,c->buf); c->n=0;
    for(int i=0;i<8;i++){out[4*i]=c->s[i]>>24;out[4*i+1]=c->s[i]>>16;out[4*i+2]=c->s[i]>>8;out[4*i+3]=c->s[i];}
}
void sha256(const uint8_t *d,uint32_t l,uint8_t out[32]){sha256_ctx c;sha256_init(&c);sha256_update(&c,d,l);sha256_final(&c,out);}

void hmac_init(hmac_ctx *h,const uint8_t *key,uint32_t kl){
    uint8_t k[64]; uint32_t i;
    for(i=0;i<64;i++)k[i]=0;
    if(kl>64){sha256(key,kl,k);} else {for(i=0;i<kl;i++)k[i]=key[i];}
    for(i=0;i<64;i++){h->okey[i]=k[i]^0x5c; k[i]^=0x36;}
    sha256_init(&h->in); sha256_update(&h->in,k,64);
}
void hmac_update(hmac_ctx *h,const uint8_t *d,uint32_t l){sha256_update(&h->in,d,l);}
void hmac_final(hmac_ctx *h,uint8_t out[32]){
    uint8_t ih[32]; sha256_ctx o; sha256_final(&h->in,ih);
    sha256_init(&o); sha256_update(&o,h->okey,64); sha256_update(&o,ih,32); sha256_final(&o,out);
}
void hmac_sha256(const uint8_t *key,uint32_t kl,const uint8_t *d,uint32_t l,uint8_t out[32]){
    hmac_ctx h; hmac_init(&h,key,kl); hmac_update(&h,d,l); hmac_final(&h,out);
}

/* HMAC with precomputed inner/outer midstates (saves 2 compressions per MAC) */
void hmac_mid_from_key(hmac_mid *m, const uint8_t *key, uint32_t kl){
    hmac_ctx h; hmac_init(&h,key,kl);
    for(int i=0;i<8;i++) m->is[i]=h.in.s[i];
    sha256_ctx o; sha256_init(&o); sha256_update(&o,h.okey,64);
    for(int i=0;i<8;i++) m->os[i]=o.s[i];
}
void hmac_mid_init(const hmac_mid *m, hmac_ctx *h){
    for(int i=0;i<8;i++) h->in.s[i]=m->is[i]; h->in.n=0; h->in.len=64;
}
void hmac_mid_final(const hmac_mid *m, hmac_ctx *h, uint8_t out[32]){
    uint8_t ih[32]; sha256_ctx o; sha256_final(&h->in,ih);
    for(int i=0;i<8;i++) o.s[i]=m->os[i]; o.n=0; o.len=64;
    sha256_update(&o,ih,32); sha256_final(&o,out);
}
