#include <stddef.h>
#include <stdint.h>
void *memcpy(void *d,const void *s,size_t n){uint8_t*a=d;const uint8_t*b=s;while(n--)*a++=*b++;return d;}
void *memmove(void *d,const void *s,size_t n){uint8_t*a=d;const uint8_t*b=s;if(a<b){while(n--)*a++=*b++;}else{a+=n;b+=n;while(n--)*--a=*--b;}return d;}
void *memset(void *d,int c,size_t n){uint8_t*a=d;while(n--)*a++=(uint8_t)c;return d;}
int memcmp(const void *x,const void *y,size_t n){const uint8_t*a=x,*b=y;for(;n;n--,a++,b++)if(*a!=*b)return *a-*b;return 0;}
void __aeabi_memcpy(void*d,const void*s,size_t n){memcpy(d,s,n);} void __aeabi_memcpy4(void*d,const void*s,size_t n){memcpy(d,s,n);}
void __aeabi_memcpy8(void*d,const void*s,size_t n){memcpy(d,s,n);}
void __aeabi_memset(void*d,size_t n,int c){memset(d,c,n);} void __aeabi_memset4(void*d,size_t n,int c){memset(d,c,n);}
void __aeabi_memclr(void*d,size_t n){memset(d,0,n);} void __aeabi_memclr4(void*d,size_t n){memset(d,0,n);} void __aeabi_memclr8(void*d,size_t n){memset(d,0,n);}
/* 64-bit helpers for cores/ABIs without native support (ARMv6-M); written with 32-bit ops only */
typedef unsigned long long u64; typedef long long s64; typedef unsigned int u32;
static u64 mul32x32(u32 a, u32 b){ u32 al=a&0xFFFF, ah=a>>16, bl=b&0xFFFF, bh=b>>16;
    u32 ll=al*bl, lh=al*bh, hl=ah*bl, hh=ah*bh; u32 mid=(ll>>16)+(lh&0xFFFF)+(hl&0xFFFF);
    u32 lo=(ll&0xFFFF)|(mid<<16); u32 hi=hh+(lh>>16)+(hl>>16)+(mid>>16); return ((u64)hi<<32)|lo; }
#if defined(__arm__)
u64 __aeabi_lmul(u64 a, u64 b){ u32 al=(u32)a, ah=(u32)(a>>32), bl=(u32)b, bh=(u32)(b>>32);
    u64 r=mul32x32(al,bl); u32 hi=(u32)(r>>32)+al*bh+ah*bl; return ((u64)hi<<32)|(u32)r; }
u64 __aeabi_llsl(u64 x, int n){ u32 lo=(u32)x, hi=(u32)(x>>32); if(n>=32){ hi=lo<<(n-32); lo=0; } else if(n){ hi=(hi<<n)|(lo>>(32-n)); lo<<=n; } return ((u64)hi<<32)|lo; }
u64 __aeabi_llsr(u64 x, int n){ u32 lo=(u32)x, hi=(u32)(x>>32); if(n>=32){ lo=hi>>(n-32); hi=0; } else if(n){ lo=(lo>>n)|(hi<<(32-n)); hi>>=n; } return ((u64)hi<<32)|lo; }
s64 __aeabi_lasr(s64 x, int n){ u32 lo=(u32)x; int hi=(int)(x>>32); if(n>=32){ lo=(u32)(hi>>(n-32)); hi=hi>>31; } else if(n){ lo=(lo>>n)|((u32)hi<<(32-n)); hi>>=n; } return (s64)(((u64)(u32)hi<<32)|lo); }
#endif
