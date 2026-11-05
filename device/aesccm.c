/* AES-128-CCM (RFC 3610), L=2, M=8, 13-byte nonce: COSE AES-CCM-16-64-128 */
#define ECB 1
#define CBC 0
#define CTR 0
#include "aes.h"
#include "aesccm.h"
static void xorb(uint8_t *a,const uint8_t *b,uint32_t n){while(n--)*a++^=*b++;}
int ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *ad, uint32_t adl,
                const uint8_t *ct, uint32_t cl, const uint8_t tag[8], uint8_t *pt){
    struct AES_ctx c; AES_init_ctx(&c,key);
    uint8_t a[16], s[16], x[16]; uint32_t i,j;
    /* CTR decrypt */
    for(i=0;i<cl;i+=16){ a[0]=1; for(j=0;j<13;j++)a[1+j]=nonce[j]; uint32_t ctr=i/16+1; a[14]=ctr>>8; a[15]=ctr;
        for(j=0;j<16;j++)s[j]=a[j]; AES_ECB_encrypt(&c,s); for(j=0;j<16&&i+j<cl;j++)pt[i+j]=ct[i+j]^s[j]; }
    /* CBC-MAC over B0 || len(ad)||ad || pt */
    x[0]=(adl?0x40:0)|(((8-2)/2)<<3)|(2-1); for(j=0;j<13;j++)x[1+j]=nonce[j]; x[14]=cl>>8; x[15]=cl;
    AES_ECB_encrypt(&c,x);
    if(adl){ uint8_t b[16]; uint32_t o=0; int first=1;
        while(o<adl){ j=0; if(first){ b[0]=adl>>8; b[1]=adl; j=2; first=0; }
            while(j<16 && o<adl) b[j++]=ad[o++]; while(j<16) b[j++]=0;
            xorb(x,b,16); AES_ECB_encrypt(&c,x); } }
    for(i=0;i<cl;i+=16){ uint8_t b[16]; for(j=0;j<16;j++) b[j]= (i+j<cl)? pt[i+j]:0; xorb(x,b,16); AES_ECB_encrypt(&c,x); }
    a[0]=1; for(j=0;j<13;j++)a[1+j]=nonce[j]; a[14]=0; a[15]=0; for(j=0;j<16;j++)s[j]=a[j]; AES_ECB_encrypt(&c,s);
    uint8_t d=0; for(j=0;j<8;j++) d|=(uint8_t)((x[j]^s[j])^tag[j]);
    return d==0;
}
