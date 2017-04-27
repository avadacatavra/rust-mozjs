/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#define __STDC_LIMIT_MACROS
#include <stdint.h>

#include "js-config.h"

#ifdef JS_DEBUG
// A hack for MFBT. Guard objects need this to work.
#define DEBUG 1
#endif

#include "jsapi.h"
#include "jsfriendapi.h"
#include "js/Proxy.h"
#include "js/Class.h"
#include "jswrapper.h"
#include "js/MemoryMetrics.h"
#include "js/Principals.h"
#include "assert.h"

struct ProxyTraps {
    bool (*enter)(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                  js::BaseProxyHandler::Action action, bool *bp);

    bool (*getOwnPropertyDescriptor)(JSContext *cx, JS::HandleObject proxy,
                                     JS::HandleId id,
                                     JS::MutableHandle<JS::PropertyDescriptor> desc);
    bool (*defineProperty)(JSContext *cx, JS::HandleObject proxy,
                           JS::HandleId id,
                           JS::Handle<JS::PropertyDescriptor> desc,
                           JS::ObjectOpResult &result);
    bool (*ownPropertyKeys)(JSContext *cx, JS::HandleObject proxy,
                            JS::AutoIdVector &props);
    bool (*delete_)(JSContext *cx, JS::HandleObject proxy,
                    JS::HandleId id, JS::ObjectOpResult &result);

    bool (*enumerate)(JSContext *cx, JS::HandleObject proxy,
                      JS::MutableHandleObject objp);

    bool (*getPrototypeIfOrdinary)(JSContext *cx, JS::HandleObject proxy,
                                   bool *isOrdinary, JS::MutableHandleObject protop);
    // getPrototype
    // setPrototype
    // setImmutablePrototype

    bool (*preventExtensions)(JSContext *cx, JS::HandleObject proxy,
                              JS::ObjectOpResult &result);

    bool (*isExtensible)(JSContext *cx, JS::HandleObject proxy, bool *succeeded);

    bool (*has)(JSContext *cx, JS::HandleObject proxy,
                JS::HandleId id, bool *bp);
    bool (*get)(JSContext *cx, JS::HandleObject proxy, JS::HandleValue receiver,
                JS::HandleId id, JS::MutableHandleValue vp);
    bool (*set)(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                JS::HandleValue v, JS::HandleValue receiver,
                JS::ObjectOpResult &result);

    bool (*call)(JSContext *cx, JS::HandleObject proxy,
                 const JS::CallArgs &args);
    bool (*construct)(JSContext *cx, JS::HandleObject proxy,
                      const JS::CallArgs &args);

    bool (*getPropertyDescriptor)(JSContext *cx, JS::HandleObject proxy,
                                  JS::HandleId id,
                                  JS::MutableHandle<JS::PropertyDescriptor> desc);
    bool (*hasOwn)(JSContext *cx, JS::HandleObject proxy,
                   JS::HandleId id, bool *bp);
    bool (*getOwnEnumerablePropertyKeys)(JSContext *cx, JS::HandleObject proxy,
                                         JS::AutoIdVector &props);
    bool (*nativeCall)(JSContext *cx, JS::IsAcceptableThis test,
                       JS::NativeImpl impl, JS::CallArgs args);
    bool (*hasInstance)(JSContext *cx, JS::HandleObject proxy,
                        JS::MutableHandleValue v, bool *bp);
    bool (*objectClassIs)(JS::HandleObject obj, js::ESClass classValue,
                          JSContext *cx);
    const char *(*className)(JSContext *cx, JS::HandleObject proxy);
    JSString *(*fun_toString)(JSContext *cx, JS::HandleObject proxy,
                              unsigned indent);
    //bool (*regexp_toShared)(JSContext *cx, JS::HandleObject proxy, RegExpGuard *g);
    bool (*boxedValue_unbox)(JSContext *cx, JS::HandleObject proxy,
                             JS::MutableHandleValue vp);
    bool (*defaultValue)(JSContext *cx, JS::HandleObject obj, JSType hint, JS::MutableHandleValue vp);
    void (*trace)(JSTracer *trc, JSObject *proxy);
    void (*finalize)(JSFreeOp *fop, JSObject *proxy);
    void (*objectMoved)(JSObject *proxy, const JSObject *old);

    bool (*isCallable)(JSObject *obj);
    bool (*isConstructor)(JSObject *obj);

    // watch
    // unwatch
    // getElements

    // weakmapKeyDelegate
    // isScripted
};

static int HandlerFamily;

#define DEFER_TO_TRAP_OR_BASE_CLASS(_base)                                      \
                                                                                \
    virtual bool enter(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,  \
                       _base::Action action, bool *bp) const override           \
    {                                                                           \
        return mTraps.enter                                                     \
               ? mTraps.enter(cx, proxy, id, action, bp)                        \
               : _base::enter(cx, proxy, id, action, bp);                       \
    }                                                                           \
                                                                                \
    /* Standard internal methods. */                                            \
    virtual bool enumerate(JSContext *cx, JS::HandleObject proxy,               \
                           JS::MutableHandleObject objp) const override         \
    {                                                                           \
        return mTraps.enumerate                                                 \
               ? mTraps.enumerate(cx, proxy, objp)                              \
               : _base::enumerate(cx, proxy, objp);                             \
    }                                                                           \
                                                                                \
    virtual bool has(JSContext* cx, JS::HandleObject proxy,                     \
                     JS::HandleId id, bool *bp) const override                  \
    {                                                                           \
        return mTraps.has                                                       \
               ? mTraps.has(cx, proxy, id, bp)                                  \
               : _base::has(cx, proxy, id, bp);                                 \
    }                                                                           \
                                                                                \
    virtual bool get(JSContext* cx, JS::HandleObject proxy,                     \
                     JS::HandleValue receiver,                                 \
                     JS::HandleId id, JS::MutableHandleValue vp) const override \
    {                                                                           \
        return mTraps.get                                                       \
               ? mTraps.get(cx, proxy, receiver, id, vp)                        \
               : _base::get(cx, proxy, receiver, id, vp);                       \
    }                                                                           \
                                                                                \
    virtual bool set(JSContext* cx, JS::HandleObject proxy,                     \
                     JS::HandleId id, JS::HandleValue v,                        \
                     JS::HandleValue receiver,                                  \
                     JS::ObjectOpResult &result) const override                 \
    {                                                                           \
        return mTraps.set                                                       \
               ? mTraps.set(cx, proxy, id, v, receiver, result)                 \
               : _base::set(cx, proxy, id, v, receiver, result);                \
    }                                                                           \
                                                                                \
    virtual bool call(JSContext* cx, JS::HandleObject proxy,                    \
                      const JS::CallArgs &args) const override                  \
    {                                                                           \
        return mTraps.call                                                      \
               ? mTraps.call(cx, proxy, args)                                   \
               : _base::call(cx, proxy, args);                                  \
    }                                                                           \
                                                                                \
    virtual bool construct(JSContext* cx, JS::HandleObject proxy,               \
                           const JS::CallArgs &args) const override             \
    {                                                                           \
        return mTraps.construct                                                 \
               ? mTraps.construct(cx, proxy, args)                              \
               : _base::construct(cx, proxy, args);                             \
    }                                                                           \
                                                                                \
    /* Spidermonkey extensions. */                                              \
    virtual bool hasOwn(JSContext* cx, JS::HandleObject proxy, JS::HandleId id, \
                        bool* bp) const override                                \
    {                                                                           \
        return mTraps.hasOwn                                                    \
               ? mTraps.hasOwn(cx, proxy, id, bp)                               \
               : _base::hasOwn(cx, proxy, id, bp);                              \
    }                                                                           \
                                                                                \
    virtual bool getOwnEnumerablePropertyKeys(JSContext* cx,                    \
                                              JS::HandleObject proxy,           \
                                              JS::AutoIdVector &props) const override \
    {                                                                           \
        return mTraps.getOwnEnumerablePropertyKeys                              \
               ? mTraps.getOwnEnumerablePropertyKeys(cx, proxy, props)          \
               : _base::getOwnEnumerablePropertyKeys(cx, proxy, props);         \
    }                                                                           \
                                                                                \
    virtual bool nativeCall(JSContext* cx, JS::IsAcceptableThis test,           \
                            JS::NativeImpl impl,                                \
                            const JS::CallArgs& args) const override            \
    {                                                                           \
        return mTraps.nativeCall                                                \
               ? mTraps.nativeCall(cx, test, impl, args)                        \
               : _base::nativeCall(cx, test, impl, args);                       \
    }                                                                           \
                                                                                \
    virtual bool hasInstance(JSContext* cx, JS::HandleObject proxy,             \
                             JS::MutableHandleValue v, bool* bp) const override \
    {                                                                           \
        return mTraps.hasInstance                                               \
               ? mTraps.hasInstance(cx, proxy, v, bp)                           \
               : _base::hasInstance(cx, proxy, v, bp);                          \
    }                                                                           \
                                                                                \
    virtual const char *className(JSContext *cx, JS::HandleObject proxy) const override\
    {                                                                           \
        return mTraps.className                                                 \
               ? mTraps.className(cx, proxy)                                    \
               : _base::className(cx, proxy);                                   \
    }                                                                           \
                                                                                \
    virtual JSString* fun_toString(JSContext* cx, JS::HandleObject proxy,       \
                                   unsigned indent) const override              \
    {                                                                           \
        return mTraps.fun_toString                                              \
               ? mTraps.fun_toString(cx, proxy, indent)                         \
               : _base::fun_toString(cx, proxy, indent);                        \
    }                                                                           \
                                                                                \
    virtual bool boxedValue_unbox(JSContext* cx, JS::HandleObject proxy,        \
                                  JS::MutableHandleValue vp) const override     \
    {                                                                           \
        return mTraps.boxedValue_unbox                                          \
               ? mTraps.boxedValue_unbox(cx, proxy, vp)                         \
               : _base::boxedValue_unbox(cx, proxy, vp);                        \
    }                                                                           \
                                                                                \
    virtual void trace(JSTracer* trc, JSObject* proxy) const override           \
    {                                                                           \
        mTraps.trace                                                            \
        ? mTraps.trace(trc, proxy)                                              \
        : _base::trace(trc, proxy);                                             \
    }                                                                           \
                                                                                \
    virtual void finalize(JSFreeOp* fop, JSObject* proxy) const override        \
    {                                                                           \
        mTraps.finalize                                                         \
        ? mTraps.finalize(fop, proxy)                                           \
        : _base::finalize(fop, proxy);                                          \
    }                                                                           \
                                                                                \
    virtual void objectMoved(JSObject* proxy,                                   \
                             const JSObject *old) const override                \
    {                                                                           \
        mTraps.objectMoved                                                      \
        ? mTraps.objectMoved(proxy, old)                                        \
        : _base::objectMoved(proxy, old);                                       \
    }                                                                           \
                                                                                \
    virtual bool isCallable(JSObject* obj) const override                       \
    {                                                                           \
        return mTraps.isCallable                                                \
               ? mTraps.isCallable(obj)                                         \
               : _base::isCallable(obj);                                        \
    }                                                                           \
                                                                                \
    virtual bool isConstructor(JSObject* obj) const override                    \
    {                                                                           \
        return mTraps.isConstructor                                             \
               ? mTraps.isConstructor(obj)                                      \
               : _base::isConstructor(obj);                                     \
    }

class WrapperProxyHandler : public js::Wrapper
{
    ProxyTraps mTraps;
  public:
    WrapperProxyHandler(const ProxyTraps& aTraps)
    : js::Wrapper(0), mTraps(aTraps) {}

    virtual bool finalizeInBackground(JS::Value priv) const override
    {
        return false;
    }

    DEFER_TO_TRAP_OR_BASE_CLASS(js::Wrapper)

    virtual bool getOwnPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                          JS::HandleId id,
                                          JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
        return mTraps.getOwnPropertyDescriptor
               ? mTraps.getOwnPropertyDescriptor(cx, proxy, id, desc)
               : js::Wrapper::getOwnPropertyDescriptor(cx, proxy, id, desc);
    }

    virtual bool defineProperty(JSContext *cx,
                                JS::HandleObject proxy, JS::HandleId id,
                                JS::Handle<JS::PropertyDescriptor> desc,
                                JS::ObjectOpResult &result) const override
    {
        return mTraps.defineProperty
               ? mTraps.defineProperty(cx, proxy, id, desc, result)
               : js::Wrapper::defineProperty(cx, proxy, id, desc, result);
    }

    virtual bool ownPropertyKeys(JSContext *cx, JS::HandleObject proxy,
                                 JS::AutoIdVector &props) const override
    {
        return mTraps.ownPropertyKeys
               ? mTraps.ownPropertyKeys(cx, proxy, props)
               : js::Wrapper::ownPropertyKeys(cx, proxy, props);
    }

    virtual bool delete_(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                         JS::ObjectOpResult &result) const override
    {
        return mTraps.delete_
               ? mTraps.delete_(cx, proxy, id, result)
               : js::Wrapper::delete_(cx, proxy, id, result);
    }

    virtual bool preventExtensions(JSContext *cx, JS::HandleObject proxy,
                                   JS::ObjectOpResult &result) const override
    {
        return mTraps.preventExtensions
               ? mTraps.preventExtensions(cx, proxy, result)
               : js::Wrapper::preventExtensions(cx, proxy, result);
    }

    virtual bool isExtensible(JSContext *cx, JS::HandleObject proxy,
                              bool *succeeded) const override
    {
        return mTraps.isExtensible
               ? mTraps.isExtensible(cx, proxy, succeeded)
               : js::Wrapper::isExtensible(cx, proxy, succeeded);
    }

    virtual bool getPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                       JS::HandleId id,
                                       JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
        return mTraps.getPropertyDescriptor
               ? mTraps.getPropertyDescriptor(cx, proxy, id, desc)
               : js::Wrapper::getPropertyDescriptor(cx, proxy, id, desc);
    }
};

class RustJSPrincipal : public JSPrincipals
{
    const void* origin; //box with origin in it
    void (*destroyCallback)(JSPrincipals *principal);
    bool (*writeCallback)(JSContext* cx, JSStructuredCloneWriter* writer);

  public:
    RustJSPrincipal(const void* origin, 
                     void (*destroy)(JSPrincipals *principal),
                     bool (*write)(JSContext* cx, JSStructuredCloneWriter* writer))
    : JSPrincipals(), origin(origin), destroyCallback(destroy), writeCallback(write) {}

    virtual const void* getOrigin() {
      return origin;
    }

    virtual void destroy() {
      if(this->destroyCallback)
        this->destroyCallback(this);
    }

    bool write(JSContext* cx, JSStructuredCloneWriter* writer) {
      return this->writeCallback
             ? this->writeCallback(cx, writer)
             : false;
    }
};

class OpaqueWrapper: js::CrossCompartmentSecurityWrapper {

  public:
    OpaqueWrapper(): js::CrossCompartmentSecurityWrapper(0) {}

     bool getOwnPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                       JS::HandleId id,
                                       JS::MutableHandle<JS::PropertyDescriptor> desc)
    {
      desc.value().setUndefined();
      return false;
    }

     bool getPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                       JS::HandleId id,
                                       JS::MutableHandle<JS::PropertyDescriptor> desc)
    {
      desc.value().setUndefined();
      return false;
    }

     bool defineProperty(JSContext *cx,
                                JS::HandleObject proxy, JS::HandleId id,
                                JS::Handle<JS::PropertyDescriptor> desc,
                                JS::ObjectOpResult &result)
    {
      return false;
    }

     bool delete_(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                         JS::ObjectOpResult &result)
    {
      return false;
    }

     bool enter(JSContext* cx, JS::Handle<JSObject*> wrapper, JS::Handle<jsid> id,
                       js::Wrapper::Action act, bool mayThrow, bool* bp)
    {
      return false;
    }

     bool ownPropertyKeys(JSContext* cx, JS::Handle<JSObject*> wrapper,
                                 JS::AutoIdVector& props)
    {
      return false;
    }

     bool getOwnEnumerablePropertyKeys(JSContext* cx, JS::Handle<JSObject*> wrapper,
                                              JS::AutoIdVector& props)
    {
      return false;
    }
     bool enumerate(JSContext* cx, JS::Handle<JSObject*> wrapper,
                           JS::MutableHandle<JSObject*> objp)
    {
      //return js::BaseProxyHandler::enumerate(cx, wrapper, objp);
      return false;
    }

     bool getPrototype(JSContext* cx, JS::HandleObject wrapper,
                              JS::MutableHandleObject protop)
    {
      // Filtering wrappers do not allow access to the prototype.
      protop.set(nullptr);
      return true;
    }

};

//TODO DOM SecurityError call (https://dxr.mozilla.org/mozilla-central/source/js/xpconnect/wrappers/AccessCheck.cpp?q=%2Bfunction%3A%22xpc%3A%3AAccessCheck%3A%3AisCrossOriginAccessPermitted%28JSContext+%2A%2C+JS%3A%3AHandleObject%2C+JS%3A%3AHandleId%2C+js%3A%3AWrapper%3A%3AAction%29%22&redirect_type=single#291)
//

// Hardcoded policy for cross origin property access. See the HTML5 Spec.
static bool
IsPermitted(JSFlatString* prop, bool set)
{
    return true;
}

typedef uint32_t Action;
enum {
    NONE      = 0x00,
    GET       = 0x01,
    SET       = 0x02,
    CALL      = 0x04,
    ENUMERATE = 0x08,
    GET_PROPERTY_DESCRIPTOR = 0x10
};

bool isCrossOriginAccessPermitted(JSContext* cx, JS::HandleObject wrapper, JS::HandleId id, Action act) {
  if (act == CALL)
        return false;

    if (act == ENUMERATE)
        return true;

    // For the case of getting a property descriptor, we allow if either GET or SET
    // is allowed, and rely on FilteringWrapper to filter out any disallowed accessors.
    if (act == GET_PROPERTY_DESCRIPTOR) {
        return isCrossOriginAccessPermitted(cx, wrapper, id, GET) ||
               isCrossOriginAccessPermitted(cx, wrapper, id, SET);
    }

    JS::RootedObject obj(cx, js::UncheckedUnwrap(wrapper, /*stopAtWindowProxy = */ false));
    if (JSID_IS_STRING(id)) {
      if (IsPermitted(JSID_TO_FLAT_STRING(id), act == SET))
        return true;
    }
    // TODO XOW type -- currently defined in utils.rs

    if (act != GET) 
      return false;

    return false;
}

static JS::SymbolCode sCrossOriginWhitelistedSymbolCodes[] = {
    JS::SymbolCode::toStringTag,
    JS::SymbolCode::hasInstance,
    JS::SymbolCode::isConcatSpreadable
};

bool
IsCrossOriginWhitelistedSymbol(JSContext* cx, JS::HandleId id)
{
    if (!JSID_IS_SYMBOL(id)) {
        return false;
    }

    JS::Symbol* symbol = JSID_TO_SYMBOL(id);
    for (auto code : sCrossOriginWhitelistedSymbolCodes) {
        if (symbol == JS::GetWellKnownSymbol(cx, code)) {
            return true;
        }
    }

    return false;
}

class CrossOriginWrapper: js::CrossCompartmentSecurityWrapper {
  //i guess we can store the type in here? since it's computed in utils.rs
  
  public:
     CrossOriginWrapper(): js::CrossCompartmentSecurityWrapper(0) {}

     bool getPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                       JS::HandleId id,
                                       JS::MutableHandle<JS::PropertyDescriptor> desc)
    {
      if (!SecurityXrayDOM::getPropertyDescriptor(cx, wrapper, id, desc))
        return false;
      if (desc.object()) {
        // Cross-origin DOM objects do not have symbol-named properties apart
        // from the ones we add ourselves here.
        MOZ_ASSERT(!JSID_IS_SYMBOL(id),
                   "What's this symbol-named property that appeared on a "
                   "Window or Location instance?");

        // All properties on cross-origin DOM objects are |own|.
        desc.object().set(wrapper);

        // All properties on cross-origin DOM objects are non-enumerable and
        // "configurable". Any value attributes are read-only.
        desc.attributesRef() &= ~JSPROP_ENUMERATE;
        desc.attributesRef() &= ~JSPROP_PERMANENT;
        if (!desc.getter() && !desc.setter())
            desc.attributesRef() |= JSPROP_READONLY;
      } else if (IsCrossOriginWhitelistedSymbol(cx, id)) {
        // Spec says to return PropertyDescriptor {
        //   [[Value]]: undefined, [[Writable]]: false, [[Enumerable]]: false,
        //   [[Configurable]]: true
        // }.
        //
        desc.setDataDescriptor(JS::UndefinedHandleValue, JSPROP_READONLY);
        desc.object().set(wrapper);
      }

      return true;

    }

    bool ownPropertyKeys(JSContext *cx, JS::HandleObject wrapper, AutoIdVector& props)
    {
      // All properties on cross-origin objects are supposed |own|, despite what
      // the underlying native object may report. Override the inherited trap to
      // avoid passing JSITER_OWNONLY as a flag.
      if (!SecurityXrayDOM::getPropertyKeys(cx, wrapper, JSITER_HIDDEN, props)) {
        return false;
      }

      if (!props.reserve(props.length() +
                       ArrayLength(sCrossOriginWhitelistedSymbolCodes))) {
          return false;
      }

      for (auto code : sCrossOriginWhitelistedSymbolCodes) {
        props.infallibleAppend(SYMBOL_TO_JSID(JS::GetWellKnownSymbol(cx, code)));
      }

      return true;
    }

    bool getOwnPropertyDescriptor(JSContext* cx,
                                                 JS::Handle<JSObject*> wrapper,
                                                 JS::Handle<jsid> id,
                                                 JS::MutableHandle<JS::PropertyDescriptor> desc)
    {
      // All properties on cross-origin DOM objects are |own|
      return getPropertyDescriptor(cx, wrapper, id, desc);
    }

    //Not allowed
     bool defineProperty(JSContext *cx,
                                JS::HandleObject proxy, JS::HandleId id,
                                JS::Handle<JS::PropertyDescriptor> desc,
                                JS::ObjectOpResult &result)
    {
      return false;
    }

    // Not allowed
     bool delete_(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                         JS::ObjectOpResult &result)
    {
      return false;
    }
};

class ForwardingProxyHandler : public js::BaseProxyHandler
{
    ProxyTraps mTraps;
    const void* mExtra;
  public:
    ForwardingProxyHandler(const ProxyTraps& aTraps, const void* aExtra)
    : js::BaseProxyHandler(&HandlerFamily), mTraps(aTraps), mExtra(aExtra) {}

    const void* getExtra() const {
        return mExtra;
    }

    virtual bool finalizeInBackground(JS::Value priv)
    {
        return false;
    }

    DEFER_TO_TRAP_OR_BASE_CLASS(BaseProxyHandler)

    virtual bool getOwnPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                          JS::HandleId id,
                                          JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
        return mTraps.getOwnPropertyDescriptor(cx, proxy, id, desc);
    }

    virtual bool defineProperty(JSContext *cx,
                                JS::HandleObject proxy, JS::HandleId id,
                                JS::Handle<JS::PropertyDescriptor> desc,
                                JS::ObjectOpResult &result) const override
    {
        return mTraps.defineProperty(cx, proxy, id, desc, result);
    }

    virtual bool ownPropertyKeys(JSContext *cx, JS::HandleObject proxy,
                                 JS::AutoIdVector &props) const override
    {
        return mTraps.ownPropertyKeys(cx, proxy, props);
    }

    virtual bool delete_(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                         JS::ObjectOpResult &result) const override
    {
        return mTraps.delete_(cx, proxy, id, result);
    }

    virtual bool getPrototypeIfOrdinary(JSContext* cx, JS::HandleObject proxy,
                                        bool* isOrdinary,
                                        JS::MutableHandleObject protop) const override
    {
        return mTraps.getPrototypeIfOrdinary(cx, proxy, isOrdinary, protop);
    }

    virtual bool preventExtensions(JSContext *cx, JS::HandleObject proxy,
                                   JS::ObjectOpResult &result) const override
    {
        return mTraps.preventExtensions(cx, proxy, result);
    }

    virtual bool isExtensible(JSContext *cx, JS::HandleObject proxy,
                              bool *succeeded) const override
    {
        return mTraps.isExtensible(cx, proxy, succeeded);
    }

    virtual bool getPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                       JS::HandleId id,
                                       JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
        return mTraps.getPropertyDescriptor(cx, proxy, id, desc);
    }
};

extern "C" {

JSPrincipals*
CreateRustJSPrincipal(const void* origin,
                       void (*destroy)(JSPrincipals *principal),
                       bool (*write)(JSContext* cx, JSStructuredCloneWriter *writer)){
  return new RustJSPrincipal(origin, destroy, write);
}

const void*
GetPrincipalOrigin(JSPrincipals* principal) {
  return static_cast<RustJSPrincipal*>(principal)->getOrigin();
}

bool
InvokeGetOwnPropertyDescriptor(
        const void *handler,
        JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
        JS::MutableHandle<JS::PropertyDescriptor> desc)
{
    return static_cast<const ForwardingProxyHandler*>(handler)->
        getOwnPropertyDescriptor(cx, proxy, id, desc);
}

bool
InvokeHasOwn(
       const void *handler,
       JSContext *cx, JS::HandleObject proxy,
       JS::HandleId id, bool *bp)
{
    return static_cast<const js::BaseProxyHandler*>(handler)->
        hasOwn(cx, proxy, id, bp);
}

JS::Value
RUST_JS_NumberValue(double d)
{
    return JS_NumberValue(d);
}

const JSJitInfo*
RUST_FUNCTION_VALUE_TO_JITINFO(JS::Value v)
{
    return FUNCTION_VALUE_TO_JITINFO(v);
}

JS::CallArgs
CreateCallArgsFromVp(unsigned argc, JS::Value* vp)
{
    return JS::CallArgsFromVp(argc, vp);
}

bool
CallJitGetterOp(const JSJitInfo* info, JSContext* cx,
                JS::HandleObject thisObj, void* specializedThis,
                unsigned argc, JS::Value* vp)
{
    JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
    return info->getter(cx, thisObj, specializedThis, JSJitGetterCallArgs(args));
}

bool
CallJitSetterOp(const JSJitInfo* info, JSContext* cx,
                JS::HandleObject thisObj, void* specializedThis,
                unsigned argc, JS::Value* vp)
{
    JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
    return info->setter(cx, thisObj, specializedThis, JSJitSetterCallArgs(args));
}

bool
CallJitMethodOp(const JSJitInfo* info, JSContext* cx,
                JS::HandleObject thisObj, void* specializedThis,
                uint32_t argc, JS::Value* vp)
{
    JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
    return info->method(cx, thisObj, specializedThis, JSJitMethodCallArgs(args));
}

const void*
CreateProxyHandler(const ProxyTraps* aTraps, const void* aExtra)
{
    return new ForwardingProxyHandler(*aTraps, aExtra);
}

const void*
CreateWrapperProxyHandler(const ProxyTraps* aTraps)
{
    return new WrapperProxyHandler(*aTraps);
}

const void*
GetCrossCompartmentWrapper()
{
    return &js::CrossCompartmentWrapper::singleton;
}

const void*
GetSecurityWrapper()
{
  return &js::CrossCompartmentSecurityWrapper::singleton;
}

const void*
GetOpaqueWrapper()
{
  return new OpaqueWrapper();
}

const void*
CreateCrossOriginWrapper(const JS::HandleObject* obj)
{
  return new CrossOriginWrapper();//*obj);
}

JS::ReadOnlyCompileOptions*
NewCompileOptions(JSContext* aCx, const char* aFile, unsigned aLine)
{
    JS::OwningCompileOptions *opts = new JS::OwningCompileOptions(aCx);
    opts->setFileAndLine(aCx, aFile, aLine);
    opts->setVersion(JSVERSION_DEFAULT);
    return opts;
}

void
DeleteCompileOptions(JS::ReadOnlyCompileOptions *aOpts)
{
    delete static_cast<JS::OwningCompileOptions *>(aOpts);
}

JSObject*
NewProxyObject(JSContext* aCx, const void* aHandler, JS::HandleValue aPriv,
               JSObject* proto, JSObject* parent, JSObject* call,
               JSObject* construct)
{
    js::ProxyOptions options;
    return js::NewProxyObject(aCx, (js::BaseProxyHandler*)aHandler, aPriv, proto,
                              options);
}

JSObject*
WrapperNew(JSContext* aCx, JS::HandleObject aObj, const void* aHandler,
           const JSClass* aClass, bool aSingleton)
{
    js::WrapperOptions options;
    if (aClass) {
        options.setClass(js::Valueify(aClass));
    }
    options.setSingleton(aSingleton);
    return js::Wrapper::New(aCx, aObj, (const js::Wrapper*)aHandler, options);
}

void WindowProxyObjectMoved(JSObject*, const JSObject*)
{
    abort();
}

static const js::ClassExtension WindowProxyClassExtension = PROXY_MAKE_EXT(
    WindowProxyObjectMoved
);

const js::Class WindowProxyClass = PROXY_CLASS_WITH_EXT(
    "Proxy",
    0, /* additional class flags */
    &WindowProxyClassExtension);

const js::Class*
GetWindowProxyClass()
{
    return &WindowProxyClass;
}

JSObject*
NewWindowProxy(JSContext* aCx, JS::HandleObject aObj, const void* aHandler)
{
    return WrapperNew(aCx, aObj, aHandler, Jsvalify(&WindowProxyClass), true);
}

JS::Value
GetProxyExtra(JSObject* obj, uint32_t slot)
{
    return js::GetProxyExtra(obj, slot);
}

JS::Value
GetProxyPrivate(JSObject* obj)
{
    return js::GetProxyPrivate(obj);
}

void
SetProxyExtra(JSObject* obj, uint32_t slot, const JS::Value& val)
{
    js::SetProxyExtra(obj, slot, val);
}

bool
RUST_JSID_IS_INT(JS::HandleId id)
{
    return JSID_IS_INT(id);
}

jsid
int_to_jsid(int32_t i)
{
    return INT_TO_JSID(i);
}

int32_t
RUST_JSID_TO_INT(JS::HandleId id)
{
    return JSID_TO_INT(id);
}

bool
RUST_JSID_IS_STRING(JS::HandleId id)
{
    return JSID_IS_STRING(id);
}

JSString*
RUST_JSID_TO_STRING(JS::HandleId id)
{
    return JSID_TO_STRING(id);
}

jsid
RUST_SYMBOL_TO_JSID(JS::Symbol* sym)
{
    return SYMBOL_TO_JSID(sym);
}

void
RUST_SET_JITINFO(JSFunction* func, const JSJitInfo* info) {
    SET_JITINFO(func, info);
}

jsid
RUST_INTERNED_STRING_TO_JSID(JSContext* cx, JSString* str) {
    return INTERNED_STRING_TO_JSID(cx, str);
}

const JSErrorFormatString*
RUST_js_GetErrorMessage(void* userRef, uint32_t errorNumber)
{
    return js::GetErrorMessage(userRef, errorNumber);
}

bool
IsProxyHandlerFamily(JSObject* obj)
{
    return js::GetProxyHandler(obj)->family() == &HandlerFamily;
}

const void*
GetProxyHandlerFamily()
{
    return &HandlerFamily;
}

const void*
GetProxyHandlerExtra(JSObject* obj)
{
    const js::BaseProxyHandler* handler = js::GetProxyHandler(obj);
    assert(handler->family() == &HandlerFamily);
    return static_cast<const ForwardingProxyHandler*>(handler)->getExtra();
}

const void*
GetProxyHandler(JSObject* obj)
{
    const js::BaseProxyHandler* handler = js::GetProxyHandler(obj);
    assert(handler->family() == &HandlerFamily);
    return handler;
}

void
ReportError(JSContext* aCx, const char* aError)
{
#ifdef DEBUG
    for (const char* p = aError; *p; ++p) {
        assert(*p != '%');
    }
#endif
    JS_ReportError(aCx, aError);
}

bool
IsWrapper(JSObject* obj)
{
    return js::IsWrapper(obj);
}

JSObject*
UnwrapObject(JSObject* obj, bool stopAtOuter)
{
    return js::CheckedUnwrap(obj, stopAtOuter);
}

JSObject*
UncheckedUnwrapObject(JSObject* obj, bool stopAtOuter)
{
    return js::UncheckedUnwrap(obj, stopAtOuter);
}

JS::AutoIdVector*
CreateAutoIdVector(JSContext* cx)
{
    return new JS::AutoIdVector(cx);
}

bool
AppendToAutoIdVector(JS::AutoIdVector* v, jsid id)
{
    return v->append(id);
}

const jsid*
SliceAutoIdVector(const JS::AutoIdVector* v, size_t* length)
{
    *length = v->length();
    return v->begin();
}

void
DestroyAutoIdVector(JS::AutoIdVector* v)
{
    delete v;
}

JS::AutoObjectVector*
CreateAutoObjectVector(JSContext* aCx)
{
    JS::AutoObjectVector* vec = new JS::AutoObjectVector(aCx);
    return vec;
}

bool
AppendToAutoObjectVector(JS::AutoObjectVector* v, JSObject* obj)
{
    return v->append(obj);
}

void
DeleteAutoObjectVector(JS::AutoObjectVector* v)
{
    delete v;
}

#if defined(__linux__)
 #include <malloc.h>
#elif defined(__APPLE__)
 #include <malloc/malloc.h>
#elif defined(__MINGW32__) || defined(__MINGW64__)
 // nothing needed here
#elif defined(_MSC_VER)
 // nothing needed here
#else
 #error "unsupported platform"
#endif

// SpiderMonkey-in-Rust currently uses system malloc, not jemalloc.
static size_t MallocSizeOf(const void* aPtr)
{
#if defined(__linux__)
    return malloc_usable_size((void*)aPtr);
#elif defined(__APPLE__)
    return malloc_size((void*)aPtr);
#elif defined(__MINGW32__) || defined(__MINGW64__)
    return _msize((void*)aPtr);
#elif defined(_MSC_VER)
    return _msize((void*)aPtr);
#else
    #error "unsupported platform"
#endif
}

bool
CollectServoSizes(JSRuntime *rt, JS::ServoSizes *sizes)
{
    mozilla::PodZero(sizes);
    return JS::AddServoSizeOf(rt, MallocSizeOf,
                              /* ObjectPrivateVisitor = */ nullptr, sizes);
}

void
CallValueTracer(JSTracer* trc, JS::Heap<JS::Value>* valuep, const char* name)
{
    JS::TraceEdge(trc, valuep, name);
}

void
CallIdTracer(JSTracer* trc, JS::Heap<jsid>* idp, const char* name)
{
    JS::TraceEdge(trc, idp, name);
}

void
CallObjectTracer(JSTracer* trc, JS::Heap<JSObject*>* objp, const char* name)
{
    JS::TraceEdge(trc, objp, name);
}

void
CallStringTracer(JSTracer* trc, JS::Heap<JSString*>* strp, const char* name)
{
    JS::TraceEdge(trc, strp, name);
}

void
CallScriptTracer(JSTracer* trc, JS::Heap<JSScript*>* scriptp, const char* name)
{
    JS::TraceEdge(trc, scriptp, name);
}

void
CallFunctionTracer(JSTracer* trc, JS::Heap<JSFunction*>* funp, const char* name)
{
    JS::TraceEdge(trc, funp, name);
}

void
CallUnbarrieredObjectTracer(JSTracer* trc, JSObject** objp, const char* name)
{
    js::UnsafeTraceManuallyBarrieredEdge(trc, objp, name);
}

#define JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Type, type)                         \
    void                                                                       \
    Get ## Type ## ArrayLengthAndData(JSObject* obj, uint32_t* length,         \
                                      bool* isSharedMemory, type** data)       \
    {                                                                          \
        js::Get ## Type ## ArrayLengthAndData(obj, length, isSharedMemory,     \
                                              data);                           \
    }

JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Int8, int8_t)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Uint8, uint8_t)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Uint8Clamped, uint8_t)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Int16, int16_t)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Uint16, uint16_t)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Int32, int32_t)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Uint32, uint32_t)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Float32, float)
JS_DEFINE_DATA_AND_LENGTH_ACCESSOR(Float64, double)

#undef JS_DEFINE_DATA_AND_LENGTH_ACCESSOR

} // extern "C"
