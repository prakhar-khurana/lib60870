/*
 * Copyright 2024
 *
 * This file is part of lib60870-C
 *
 * lib60870-C is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * lib60870-C is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lib60870-C.  If not, see <http://www.gnu.org/licenses/>.
 */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include "aprofile_internal.h"
#include "cs104_frame.h"
#include "lib_memory.h"
#include "cs101_asdu_internal.h"
#include "cs101_information_objects.h"
#include "information_objects_internal.h"
#include <stdio.h>
#include <string.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>

#if (CONFIG_CS104_APROFILE == 1)

AProfileContext
AProfile_create(void* connection, AProfile_SendAsduCallback sendAsduCallback)
{
    AProfileContext self = (AProfileContext) GLOBAL_CALLOC(1, sizeof(struct sAProfileContext));

    if (self == NULL)
        return NULL;

    self->connection = connection;
    self->sendAsdu = sendAsduCallback;

    mbedtls_gcm_init(&self->gcm_encrypt);
    mbedtls_ecdh_init(&self->ecdh);
    mbedtls_ctr_drbg_init(&self->ctr_drbg);
    mbedtls_entropy_init(&self->entropy);
    mbedtls_gcm_init(&self->gcm_decrypt);

    /* Seed the random number generator */
    const char* pers = "lib60870";
    int ret = mbedtls_ctr_drbg_seed(&self->ctr_drbg, mbedtls_entropy_func, &self->entropy,
                           (const unsigned char*) pers, strlen(pers));

    if (ret != 0) {
        printf("APROFILE: Failed to seed random number generator\n");
        AProfile_destroy(self);
        return NULL;
    }

    self->keyExchangeState = KEY_EXCHANGE_IDLE;
    self->security_active = false;
    self->local_sequence_number = 0;
    self->remote_sequence_number = 0;

    return self;
}

void
AProfile_destroy(AProfileContext self)
{
    if (self) {
        mbedtls_ecdh_free(&self->ecdh);
        mbedtls_ctr_drbg_free(&self->ctr_drbg);
        mbedtls_entropy_free(&self->entropy);
        mbedtls_gcm_free(&self->gcm_encrypt);
        mbedtls_gcm_free(&self->gcm_decrypt);
        GLOBAL_FREEMEM(self);
    }
}

#else /* CONFIG_CS104_APROFILE == 0 */

AProfileContext
AProfile_create(void* connection, void* sendAsduCallback)
{
    AProfileContext self = (AProfileContext) GLOBAL_CALLOC(1, sizeof(struct sAProfileContext));
    if (self) {
        self->security_active = false;
    }
    return self;
}

void
AProfile_destroy(AProfileContext self)
{
    GLOBAL_FREEMEM(self);
    (void)self; /* avoid unused parameter warning */
}

#endif /* CONFIG_CS104_APROFILE */


bool
AProfile_onStartDT(AProfileContext self)
{
#if (CONFIG_CS104_APROFILE == 1)
    int ret;

    printf("APROFILE: StartDT received, initiating key exchange\n");

    ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("APROFILE: Failed to setup ECP group\n");
        mbedtls_ecdh_free(&self->ecdh);
        return false;
    }

    size_t olen = 0;
    ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q, mbedtls_ctr_drbg_random, &self->ctr_drbg);
    if (ret != 0) {
        printf("APROFILE: Failed to generate public key\n");
        mbedtls_ecdh_free(&self->ecdh);
        return false;
    }

    ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, self->localPublicKey, sizeof(self->localPublicKey));
    if (ret != 0) {
        printf("APROFILE: Failed to write public key\n");
        mbedtls_ecdh_free(&self->ecdh);
        return false;
    }

    self->localPublicKeyLen = (int)olen;

    /* Create and send key exchange ASDU with the public key */
    CS101_ASDU asdu = CS101_ASDU_create(NULL, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;

    CS101_ASDU_setTypeID(asdu, S_RP_NA_1);

    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, self->localPublicKeyLen, self->localPublicKey);
    if (!spk) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    SecurityPublicKey_destroy(spk);

    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }

    self->keyExchangeState = KEY_EXCHANGE_AWAIT_REPLY;

    return true; /* We are not ready yet, but the process has started */
#else
    return true;
#endif
}

bool
AProfile_ready(AProfileContext self)
{
#if (CONFIG_CS104_APROFILE == 1)
    return self->security_active;
#else
    return false;
#endif
}

bool
AProfile_wrapOutAsdu(AProfileContext self, T104Frame frame)
{
#if (CONFIG_CS104_APROFILE == 1)
    if (!self->security_active || !AProfile_ready(self)) {
        return true; /* Do nothing if security is not active */
    }

    uint8_t* asdu_buffer = T104Frame_getBuffer((Frame)frame) + 6;
    int asdu_len = T104Frame_getMsgSize((Frame)frame) - 6;

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t* ciphertext = (uint8_t*)GLOBAL_MALLOC(asdu_len);
    if (!ciphertext) return false;

    /* Generate nonce */
    mbedtls_ctr_drbg_random(&self->ctr_drbg, nonce, 12);

    /* Encrypt */
    int ret = mbedtls_gcm_crypt_and_tag(&self->gcm_encrypt, MBEDTLS_GCM_ENCRYPT, asdu_len, nonce, 12, NULL, 0, asdu_buffer, ciphertext, 16, tag);
    if (ret != 0) {
        printf("APROFILE: Failed to encrypt ASDU\n");
        GLOBAL_FREEMEM(ciphertext);
        return false;
    }

    /* Create new ASDU with encrypted data */
    T104Frame_resetFrame((Frame)frame);
    T104Frame_setNextByte((Frame)frame, S_SE_NA_1); /* Type ID for secure ASDU */
    T104Frame_setNextByte((Frame)frame, 1); /* VSQ */
    T104Frame_setNextByte((Frame)frame, CS101_COT_SPONTANEOUS); /* COT */
    T104Frame_setNextByte((Frame)frame, 0); /* OA */
    T104Frame_setNextByte((Frame)frame, 0); /* CA LSB */
    T104Frame_setNextByte((Frame)frame, 0); /* CA MSB */

    SecurityEncryptedData sed = SecurityEncryptedData_create(NULL, 0, nonce, tag, asdu_len, ciphertext);
    if (!sed) {
        GLOBAL_FREEMEM(ciphertext);
        return false;
    }

    InformationObject_encode((InformationObject)sed, (Frame)frame, NULL, false);

    SecurityEncryptedData_destroy(sed);
    GLOBAL_FREEMEM(ciphertext);

    return true;
#else
    return true;
#endif
}

AProfileKind
AProfile_handleInPdu(AProfileContext self, const uint8_t* in, int inSize, const uint8_t** out, int* outSize)
{
#if (CONFIG_CS104_APROFILE == 1)
    if (self->keyExchangeState == KEY_EXCHANGE_AWAIT_REPLY) {
        struct sCS101_ASDU _asdu;
        CS101_ASDU asdu = CS101_ASDU_createFromBufferEx(&_asdu, NULL, (uint8_t*)in, inSize);

        if (asdu && CS101_ASDU_getTypeID(asdu) == S_RP_NA_1) {
            printf("APROFILE: Received security ASDU (S_RP_NA_1)\n");

            int ret;
            for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
                union uInformationObject _io;
                SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, i);
                if (spk && InformationObject_getObjectAddress((InformationObject)spk) == 65535) {
                    printf("APROFILE: Found public key IO\n");

                    /* Extract public key and perform key exchange */
                    const uint8_t* peer_key = SecurityPublicKey_getKeyValue(spk);
                    int peer_key_len = SecurityPublicKey_getKeyLength(spk);

                    // Use MBEDTLS_PRIVATE for lvalue access
                    ret = mbedtls_ecdh_read_public(&self->ecdh, peer_key, peer_key_len);
                    if (ret != 0) {
                        printf("APROFILE: Failed to read peer public key\n");
                        mbedtls_ecdh_free(&self->ecdh);
                        break;
                    }
                    uint8_t shared_secret[32];
                    size_t shared_secret_len;
                    ret = mbedtls_ecdh_calc_secret(&self->ecdh, &shared_secret_len, shared_secret, sizeof(shared_secret), mbedtls_ctr_drbg_random, &self->ctr_drbg);
                    if (ret != 0) {
                        printf("APROFILE: Failed to calculate shared secret\n");
                        mbedtls_ecdh_free(&self->ecdh);
                        break;
                    }

                    uint8_t session_key[16];
                    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                      shared_secret, shared_secret_len,
                                      (const unsigned char*)"IEC62351-5", 11,
                                      session_key, sizeof(session_key));
                    if (ret != 0) {
                        printf("APROFILE: Failed to derive session key\n");
                        mbedtls_ecdh_free(&self->ecdh);
                        break;
                    }

                    mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                    mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);

                    self->security_active = true;
                    self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                    printf("APROFILE: Key exchange complete, security is active\n");

                    break;
                }
            }

            return APROFILE_CTRL_MSG;
        }
    }

    if (!self->security_active || CS101_ASDU_getTypeID(CS101_ASDU_createFromBufferEx(NULL, NULL, (uint8_t*)in, inSize)) != S_SE_NA_1) {
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

    /* Check if the incoming message is a secure ASDU */
    if (inSize < 1 || in[0] != S_SE_NA_1) {
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

    SecurityEncryptedData sed = SecurityEncryptedData_getFromBuffer(NULL, NULL, (uint8_t*)in + 6, inSize - 6, 0, false);
    if (!sed) return APROFILE_PLAINTEXT;

    *outSize = SecurityEncryptedData_getCiphertextLength(sed);
    *out = (const uint8_t*)GLOBAL_MALLOC(*outSize);

    int ret = mbedtls_gcm_auth_decrypt(&self->gcm_decrypt, *outSize, SecurityEncryptedData_getNonce(sed), 12, NULL, 0, SecurityEncryptedData_getTag(sed), 16, SecurityEncryptedData_getCiphertext(sed), (uint8_t*)*out);
    SecurityEncryptedData_destroy(sed);

    if (ret != 0) {
        printf("APROFILE: Failed to decrypt or authenticate ASDU\n");
        GLOBAL_FREEMEM((void*)*out);
        *out = NULL;
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }

    return APROFILE_SECURE_DATA;
#else
    *out = in;
    *outSize = inSize;
    return APROFILE_PLAINTEXT;
#endif
}