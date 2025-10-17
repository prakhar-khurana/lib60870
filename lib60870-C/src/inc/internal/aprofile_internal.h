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

#ifndef APROFILE_INTERNAL_H_
#define APROFILE_INTERNAL_H_

#include "aprofile_context.h"

#if (CONFIG_CS104_APROFILE == 1)

#include "mbedtls/gcm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/entropy.h"

#include "iec60870_common.h"

typedef bool (*AProfile_SendAsduCallback)(void* connection, CS101_ASDU asdu);

typedef enum {
    KEY_EXCHANGE_IDLE,
    KEY_EXCHANGE_AWAIT_REPLY,
    KEY_EXCHANGE_COMPLETE
} KeyExchangeState;

/* Placeholder for security state */
struct sAProfileContext
{
    bool security_active;
    bool isClient; /* true for client (CS104_Connection), false for server (MasterConnection) */
    uint32_t local_sequence_number;
    uint32_t remote_sequence_number;

    void* connection; /* Reference to the CS104_Connection or MasterConnection */
    AProfile_SendAsduCallback sendAsdu;
    CS101_AppLayerParameters parameters; /* Application layer parameters for ASDU creation */

    KeyExchangeState keyExchangeState;

    mbedtls_ecdh_context ecdh;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_gcm_context gcm_encrypt;
    mbedtls_gcm_context gcm_decrypt;

    uint8_t localPublicKey[65];
    int localPublicKeyLen;
};

#else

/* This is a dummy struct for when A-profile is disabled */
struct sAProfileContext
{
    bool security_active;
};

#endif /* CONFIG_CS104_APROFILE */

#endif /* APROFILE_INTERNAL_H_ */