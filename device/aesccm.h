#include <stdint.h>
int ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *ad, uint32_t adl,
                const uint8_t *ct, uint32_t cl, const uint8_t tag[8], uint8_t *pt);
