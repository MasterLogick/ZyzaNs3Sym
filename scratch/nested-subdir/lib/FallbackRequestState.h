#ifndef ZYZZYVA_A_FALLBACKREQUESTSTATE_H
#define ZYZZYVA_A_FALLBACKREQUESTSTATE_H

#include "capnp/message.h"

#include <memory>

namespace zyza
{
struct FallbackRequestState
{
    capnp::MallocMessageBuilder request;
    capnp::MallocMessageBuilder response;
    bool responseIsDrop = false;
    bool hasResponse = false;
};
} // namespace zyza

#endif // ZYZZYVA_A_FALLBACKREQUESTSTATE_H
