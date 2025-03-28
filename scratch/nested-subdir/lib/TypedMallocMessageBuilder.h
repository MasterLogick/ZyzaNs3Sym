#ifndef NS3_TYPEDMALLOCMESSAGEBUILDER_H
#define NS3_TYPEDMALLOCMESSAGEBUILDER_H

#include <capnp/message.h>
namespace zyza {

template <typename T> class TypedMallocMessageBuilder {
public:
  TypedMallocMessageBuilder() { reset(); };

  TypedMallocMessageBuilder(const TypedMallocMessageBuilder<T> &) = delete;

  TypedMallocMessageBuilder(TypedMallocMessageBuilder<T> &&a)
      : messageBuilder(std::move(a.messageBuilder)) {};

  void setTypedRoot(T::Reader &&reader) { messageBuilder->setRoot(reader); }

  void setTypedRoot(const T::Reader &reader) {
    messageBuilder->setRoot(reader);
  }

  T::Builder getTyped() const { return messageBuilder->getRoot<T>(); }

  void reset() {
    messageBuilder = std::make_unique<capnp::MallocMessageBuilder>();
  }

private:
  std::unique_ptr<capnp::MallocMessageBuilder> messageBuilder;
};

} // namespace zyza

#endif // NS3_TYPEDMALLOCMESSAGEBUILDER_H
