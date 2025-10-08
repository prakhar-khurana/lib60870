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

#ifndef CS104_SECURITY_H_
#define CS104_SECURITY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct sCS104_Connection* CS104_Connection;
typedef struct sCS104_Slave* CS104_Slave;

typedef struct {
    uint32_t sessionKeyChangeInterval;
    uint32_t challengeResponseTimeout;
} CS104_SecurityConfig;

typedef struct {
    const char* privateKeyFile;
    const char* ownCertificateFile;
    const char* caCertificateFile;
} CS104_CertConfig;

typedef struct {
    int roleId;
    int permissions;
} CS104_RoleConfig;

typedef enum
{
    CS104_SECURITY_EVENT_NONE = 0
} CS104_SecurityEvent;

typedef struct
{
    int dummy;
} CS104_SecurityStats;

typedef void (*CS104_SecurityEventHandler)(void* parameter, CS104_SecurityEvent event,
                                           const CS104_SecurityStats* stats);

void CS104_Connection_setSecurityConfig(CS104_Connection connection,
                                        const CS104_SecurityConfig* sec,
                                        const CS104_CertConfig* cert,
                                        const CS104_RoleConfig* role);

void CS104_Connection_setSecurityEventHandler(CS104_Connection connection,
                                              CS104_SecurityEventHandler handler,
                                              void* parameter);

void CS104_Slave_setSecurityConfig(CS104_Slave slave,
                                   const CS104_SecurityConfig* sec,
                                   const CS104_CertConfig* cert,
                                   const CS104_RoleConfig* role);

#ifdef __cplusplus
}
#endif

#endif /* CS104_SECURITY_H_ */
