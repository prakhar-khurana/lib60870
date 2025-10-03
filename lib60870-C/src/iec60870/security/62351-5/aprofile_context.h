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

#ifndef APROFILE_CONTEXT_H_
#define APROFILE_CONTEXT_H_

#include <stdbool.h>
#include <stdint.h>

#include "cs104_frame.h" /* For T104Frame */

typedef struct sAProfileContext* AProfileContext;

typedef enum
{
    APROFILE_PLAINTEXT = 0,
    APROFILE_SECURE_DATA,
    APROFILE_CTRL_MSG
} AProfileKind;

AProfileContext
AProfile_create(void);

void
AProfile_destroy(AProfileContext ctx);

bool
AProfile_onStartDT(AProfileContext ctx);

bool
AProfile_ready(AProfileContext ctx);

bool
AProfile_wrapOutAsdu(AProfileContext ctx, T104Frame frame);

AProfileKind
AProfile_handleInPdu(AProfileContext ctx, const uint8_t* in, int inSize, const uint8_t** out, int* outSize);

#endif /* APROFILE_CONTEXT_H_ */