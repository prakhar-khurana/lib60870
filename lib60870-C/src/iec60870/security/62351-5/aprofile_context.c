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

#include "../../inc/internal/aprofile_internal.h"
#include "lib_memory.h"
#include "cs104_frame.h"

struct sAProfileContext {
    int dummy;
};

AProfileContext
AProfile_create(void)
{
#if (CONFIG_CS104_APROFILE == 1)
    return (AProfileContext)GLOBAL_CALLOC(1, sizeof(struct sAProfileContext));
#else
    return NULL;
#endif
}

void
AProfile_destroy(AProfileContext ctx)
{
    if (ctx)
        GLOBAL_FREEMEM(ctx);
}

bool
AProfile_onStartDT(AProfileContext ctx)
{
    (void)ctx;
    return true;
}

bool
AProfile_ready(AProfileContext ctx)
{
#if (CONFIG_CS104_APROFILE == 1)
    return (ctx != NULL);
#else
    return false;
#endif
}

bool
AProfile_wrapOutAsdu(AProfileContext ctx, T104Frame frame)
{
    (void)ctx;
    (void)frame;
    return false;
}

AProfileKind
AProfile_handleInPdu(AProfileContext ctx, const uint8_t* in, int inSize,
                     const uint8_t** out, int* outSize)
{
    (void)ctx;
    *out = in;
    *outSize = inSize;
    return APROFILE_PLAINTEXT;
}

