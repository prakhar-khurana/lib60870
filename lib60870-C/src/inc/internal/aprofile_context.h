#ifndef APROFILE_CONTEXT_H_
#define APROFILE_CONTEXT_H_

#include "iec60870_common.h"

typedef struct sAProfileContext* AProfileContext;

typedef enum {
    APROFILE_CTRL_MSG,
    APROFILE_PLAINTEXT,
    APROFILE_SECURE_DATA
} AProfileKind;

struct sCS101_ASDU;
struct sT104Frame;

AProfileContext
AProfile_create(void* connection, bool (*sendAsduCallback)(void*, struct sCS101_ASDU*), CS101_AppLayerParameters parameters, bool isClient);

void
AProfile_destroy(AProfileContext self);

bool
AProfile_onStartDT(AProfileContext self);

bool
AProfile_ready(AProfileContext self);

bool
AProfile_wrapOutAsdu(AProfileContext self, struct sT104Frame* frame);

AProfileKind
AProfile_handleInPdu(AProfileContext self, const uint8_t* in, int inSize, const uint8_t** out, int* outSize);

#endif /* APROFILE_CONTEXT_H_ */