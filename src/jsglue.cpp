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
#include <iostream>

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
                                       JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
      desc.value().setUndefined();
      return false;
    }

     bool getPropertyDescriptor(JSContext *cx, JS::HandleObject proxy,
                                       JS::HandleId id,
                                       JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
      desc.value().setUndefined();
      return false;
    }

     bool defineProperty(JSContext *cx,
                                JS::HandleObject proxy, JS::HandleId id,
                                JS::Handle<JS::PropertyDescriptor> desc,
                                JS::ObjectOpResult &result) const override
    {
      return false;
    }

     bool delete_(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                         JS::ObjectOpResult &result) const override
    {
      return false;
    }

     bool ownPropertyKeys(JSContext* cx, JS::Handle<JSObject*> wrapper,
                                 JS::AutoIdVector& props) const override
    {
      return false;
    }

     bool getOwnEnumerablePropertyKeys(JSContext* cx, JS::Handle<JSObject*> wrapper,
                                              JS::AutoIdVector& props) const override
    {
      return false;
    }
     bool enumerate(JSContext* cx, JS::Handle<JSObject*> wrapper,
                           JS::MutableHandle<JSObject*> objp) const override
    {
      //return js::BaseProxyHandler::enumerate(cx, wrapper, objp);
      return false;
    }

     bool getPrototype(JSContext* cx, JS::HandleObject wrapper,
                              JS::MutableHandleObject protop) const override
    {
      // Filtering wrappers do not allow access to the prototype.
      protop.set(nullptr);
      return true;
    }

};


typedef void (*throw_dom_exception_callback)(JSContext *cx);
throw_dom_exception_callback throw_dom_exception_fn;
void set_throw_dom_exception_callback(void (*throw_dom_exception_callback_fn)(JSContext *cx)) {
  throw_dom_exception_fn = throw_dom_exception_callback_fn;
}
typedef bool (*is_frame_id_callback)(JSContext* cx, JSObject* obj, jsid idArg);
is_frame_id_callback is_frame_id_fn;
static void set_is_frame_id_callback(bool (*is_frame_id_callback_fn)(JSContext* cx, JSObject* obj, jsid idArg)) {
  is_frame_id_fn = is_frame_id_callback_fn;
}

static bool IsFrameId(JSContext* cx, JSObject* obj, jsid idArg) {
  return is_frame_id_fn(cx, obj, idArg);
}

bool deny_access(JSContext* cx) {
  throw_dom_exception_fn
    ? throw_dom_exception_fn(cx)
    : JS_ReportError(cx, "Access Denied");
    return false;
}


/*typedef uint32_t Action;
enum {
    NONE      = 0x00,
    GET       = 0x01,
    SET       = 0x02,
    CALL      = 0x04,
    ENUMERATE = 0x08,
    GET_PROPERTY_DESCRIPTOR = 0x10
};*/

enum CrossOriginObjectType {
    CrossOriginWindow,
    CrossOriginLocation,
    CrossOriginOpaque
};

// TODO make this less awful?
  inline bool IsPermittedWindow(JSFlatString* prop, char16_t propFirstChar, bool set)
  {
    switch (propFirstChar) {
      case 'b': {
        if (!set && JS_FlatStringEqualsAscii(prop, "blur")) {
          return true;
        }
        break;
      }
      case 'c': {
        if (!set && JS_FlatStringEqualsAscii(prop, "close")) {
          return true;
        }
        if (!set && JS_FlatStringEqualsAscii(prop, "closed")) {
          return true;
        }
        break;
      }
      case 'f': {
        if (!set && JS_FlatStringEqualsAscii(prop, "focus")) {
          return true;
        }
        if (!set && JS_FlatStringEqualsAscii(prop, "frames")) {
          return true;
        }
        break;
      }
      case 'l': {
        if (!set && JS_FlatStringEqualsAscii(prop, "length")) {
          return true;
        }
        if (JS_FlatStringEqualsAscii(prop, "location")) {
          return true;
        }
        break;
      }
      case 'o': {
        if (!set && JS_FlatStringEqualsAscii(prop, "opener")) {
          return true;
        }
        break;
      }
      case 'p': {
        if (!set && JS_FlatStringEqualsAscii(prop, "parent")) {
          return true;
        }
        if (!set && JS_FlatStringEqualsAscii(prop, "postMessage")) {
          return true;
        }
        break;
      }
      case 's': {
        if (!set && JS_FlatStringEqualsAscii(prop, "self")) {
          return true;
        }
        break;
      }
      case 't': {
        if (!set && JS_FlatStringEqualsAscii(prop, "top")) {
          return true;
        }
        break;
      }
      case 'w': {
        if (!set && JS_FlatStringEqualsAscii(prop, "window")) {
          return true;
        }
        break;
      }
    }

    return false;
  }

  inline bool IsPermittedLocation(JSFlatString* prop, char16_t propFirstChar, bool set)
  {
    switch (propFirstChar) {
      case 'h': {
        if (set && JS_FlatStringEqualsAscii(prop, "href")) {
          return true;
        }
        break;
      }
      case 'r': {
        if (!set && JS_FlatStringEqualsAscii(prop, "replace")) {
          return true;
        }
        break;
      }
    }

    return false;
  }

// Hardcoded policy for cross origin property access. See the HTML5 Spec.
static bool
IsPermitted(CrossOriginObjectType type, JSFlatString* prop, bool set)
{
    size_t propLength = JS_GetStringLength(JS_FORGET_STRING_FLATNESS(prop));
    if (!propLength)
        return false;

    char16_t propChar0 = JS_GetFlatStringCharAt(prop, 0);
    if (type == CrossOriginLocation)
        return IsPermittedLocation(prop, propChar0, set);
    if (type == CrossOriginWindow)
        return IsPermittedWindow(prop, propChar0, set);

    return false;
}

CrossOriginObjectType
IdentifyCrossOriginObject(JSObject* obj)
{
    obj = js::UncheckedUnwrap(obj, /* stopAtWindowProxy = */ false);
    const js::Class* clasp = js::GetObjectClass(obj);

    if (clasp->name[0] == 'L' && !strcmp(clasp->name, "Location"))
        return CrossOriginLocation;
    if (clasp->name[0] == 'W' && !strcmp(clasp->name, "Window"))
        return CrossOriginWindow;

    return CrossOriginOpaque;
}

static JS::SymbolCode sCrossOriginWhitelistedSymbolCodes[] = {
    //FIXME requires mozjs update
    //JS::SymbolCode::toStringTag,
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

bool isCrossOriginAccessPermitted(JSContext* cx, JS::HandleObject wrapper, JS::HandleId id, js::BaseProxyHandler::Action act) {
  if (act == js::BaseProxyHandler::CALL)
        return false;

    if (act == js::BaseProxyHandler::ENUMERATE)
        return true;

    // For the case of getting a property descriptor, we allow if either GET or SET
    // is allowed, and rely on FilteringWrapper to filter out any disallowed accessors.
    if (act == js::BaseProxyHandler::GET_PROPERTY_DESCRIPTOR) {
        return isCrossOriginAccessPermitted(cx, wrapper, id, js::BaseProxyHandler::GET) ||
               isCrossOriginAccessPermitted(cx, wrapper, id, js::BaseProxyHandler::SET);
    }

    JS::RootedObject obj(cx, js::UncheckedUnwrap(wrapper, /* stopAtWindowProxy = */ false));
    CrossOriginObjectType type = IdentifyCrossOriginObject(obj);
    if (JSID_IS_STRING(id)) {
        if (IsPermitted(type, JSID_TO_FLAT_STRING(id), act == js::BaseProxyHandler::SET)){
            std::cout << "checking permissions: true" << std::endl;
            return true;
          }
    } else if (type != CrossOriginOpaque &&
               IsCrossOriginWhitelistedSymbol(cx, id)) {
        // We always allow access to @@toStringTag, @@hasInstance, and
        // @@isConcatSpreadable.  But then we nerf them to be a value descriptor
        // with value undefined in CrossOriginXrayWrapper.
        std::cout << "checking permissions- true" << std::endl;
        return true;
    }

    if (act != js::BaseProxyHandler::GET) 
      return false;

    // Check for frame IDs. If we're resolving named frames, make sure to only
    // resolve ones that don't shadow native properties. See bug 860494.
    if (type == CrossOriginWindow) {
      // std::cout << "calling is frame id" << std::endl;
        return IsFrameId(cx, obj, id);
    }

    return false;
}

//FIXME figure out maythrow
struct CrossOriginPolicy {
  static bool check(JSContext* cx, JS::HandleObject wrapper, JS::HandleId id, js::BaseProxyHandler::Action act) {
    std::cout << isCrossOriginAccessPermitted(cx, wrapper, id, act) <<std::endl;
    return isCrossOriginAccessPermitted(cx, wrapper, id, act);
  }

  static bool deny(JSContext* cx, js::BaseProxyHandler::Action act, JS::HandleId id) {//, bool mayThrow) {
    //fail silently
    if (act == js::BaseProxyHandler::ENUMERATE)
      return true;
    //if (mayThrow)
    deny_access(cx);
    return false;
  }
};

class CrossOriginWrapper: js::CrossCompartmentSecurityWrapper {
  
  public:
     CrossOriginWrapper(): 
      js::CrossCompartmentSecurityWrapper(HandlerFamily) {}

     bool getPropertyDescriptor(JSContext *cx, JS::HandleObject wrapper,
                                       JS::HandleId id,
                                       JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
      assertEnteredPolicy(cx, wrapper, id, js::BaseProxyHandler::GET | js::BaseProxyHandler::SET |
                                           js::BaseProxyHandler::GET_PROPERTY_DESCRIPTOR);

      if (!js::CrossCompartmentSecurityWrapper::getPropertyDescriptor(cx, wrapper, id, desc)) // this is leading to the failed assertion
        return false;

      bool getAllowed = CrossOriginPolicy::check(cx, wrapper, id, js::BaseProxyHandler::GET);
      if (JS_IsExceptionPending(cx))
        return false;
      bool setAllowed = CrossOriginPolicy::check(cx, wrapper, id, js::BaseProxyHandler::SET);
      if (JS_IsExceptionPending(cx))
        return false;

      if (!(getAllowed || setAllowed))
        return false;

      if (!desc.hasGetterOrSetter()) {
        // Handle value properties.
        if (!getAllowed)
            desc.value().setUndefined();
    } else {
        // Handle accessor properties.
        //MOZ_ASSERT(desc.value().isUndefined());
        if (!getAllowed)
            desc.setGetter(nullptr);
        if (!setAllowed)
            desc.setSetter(nullptr);
    }

    return true;

    }

    //need to xray through this
    /*bool get(JSContext* cx, JS::HandleObject wrapper,
             JS::HandleValue receiver, JS::HandleId id,
             JS::MutableHandleValue vp) const override
    {
          JS::Rooted<JS::PropertyDescriptor> desc(cx);
          //will probably need to meake a new function for this that accesses the window object
          if (!xrayGetPropertyDescriptor(cx, wrapper, id, &desc)) // is not calling CrossOriginWrapper prop desc
            return false;

          if (!desc.object()) {
            vp.setUndefined();
            return true;
          }

          if (desc.isDataDescriptor()) {
            vp.set(desc.value());
            return true;
          }

          if (!desc.isAccessorDescriptor()) {
            return false;
          }

          //need to deal with accessor :D
          return false;
    }*/

    bool getPrototype(JSContext * cx, JS::HandleObject wrapper, JS::MutableHandleObject protop) const override
    {
      protop.set(nullptr);
      return true;
    }

    bool setPrototype(JSContext* cx, JS::HandleObject wrapper, JS::HandleObject proto,
                                    JS::ObjectOpResult& result) const override
    {
      //TODO need to do a typeerror sometimes?
      return deny_access(cx);
    }

    bool enter(JSContext* cx, JS::HandleObject wrapper,
                              JS::HandleId id, BaseProxyHandler::Action act,
                              bool* bp) const override
    {
      if (!CrossOriginPolicy::check(cx, wrapper, id, act)) {
        *bp = JS_IsExceptionPending(cx) ?
            false : CrossOriginPolicy::deny(cx, act, id);//, mayThrow);
        return false;
      }
      *bp = true;
      return true;
    }

<<<<<<< 17ba361501d75a936810c80e17a65d4918a783d5
     bool ownPropertyKeys(JSContext *cx, JS::HandleObject wrapper, JS::AutoIdVector& props) const override
     {
      JS::AutoIdVector keys(cx);

=======
    //https://dxr.mozilla.org/mozilla-central/source/js/xpconnect/wrappers/XrayWrapper.cpp#2260
    bool get(JSContext* cx, JS::HandleObject wrapper, JS::HandleValue receiver,
             JS::HandleId id, JS::MutableHandleValue vp) const override
    {
        std::cout << "get" << std::endl;
        JS::Rooted<JS::PropertyDescriptor> desc(cx);
        if (!getPropertyDescriptor(cx, wrapper, id, &desc))
          return false;
        desc.assertCompleteIfFound(); //?

        if (!desc.object()) {
          vp.setUndefined();
          return true;
        }

        if (desc.isDataDescriptor()) {
          vp.set(desc.value());
          return true;
        }

        if (!desc.isAccessorDescriptor())
          return false;

        JS::RootedObject getter(cx, desc.getterObject());

        if (!getter) {
          vp.setUndefined();
          return true;
        }

        //TODO might need to do some work on second arg
        return Call(cx, receiver, getter, JS::HandleValueArray::empty(), vp);

    }

    bool ownPropertyKeys(JSContext *cx, JS::HandleObject wrapper, JS::AutoIdVector& props) const override
    {
      if (!keys.reserve(props.length() +
                       mozilla::ArrayLength(sCrossOriginWhitelistedSymbolCodes))) {
          return false;
      }

      //FIXME Missing the following keys on Window:
      // 0, 1, blur, closed, focus, length, opener
      js::GetPropertyKeys(cx, wrapper, JSITER_OWNONLY, &keys);
      size_t len = keys.length();
      if (!props.reserve(len)){
        return false;
      }
      for (auto key : keys ) {
        JS::RootedId rootedKey(cx, key);
        JS::HandleId keyHandle = JS::HandleId(rootedKey);
        if (CrossOriginPolicy::check(cx, wrapper, keyHandle, BaseProxyHandler::GET) || 
            CrossOriginPolicy::check(cx, wrapper, keyHandle, BaseProxyHandler::SET)) {
          props.append(key);
        }
      }
      return true;
    }

    bool getOwnPropertyDescriptor(JSContext* cx,
                                                 JS::Handle<JSObject*> wrapper,
                                                 JS::Handle<jsid> id,
                                                 JS::MutableHandle<JS::PropertyDescriptor> desc) const override
    {
      // All properties on cross-origin DOM objects are |own|
      return getPropertyDescriptor(cx, wrapper, id, desc);
    }

    //Not allowed
     bool defineProperty(JSContext *cx,
                                JS::HandleObject proxy, JS::HandleId id,
                                JS::Handle<JS::PropertyDescriptor> desc,
                                JS::ObjectOpResult &result) const override
    {
      return CrossOriginPolicy::deny();
    }

    // Not allowed
     bool delete_(JSContext *cx, JS::HandleObject proxy, JS::HandleId id,
                         JS::ObjectOpResult &result) const override
    {
      return CrossOriginPolicy::deny(); 
    }
};

class CrossOriginXrayWrapper : public ?? 
{
  bool
  getPropertyDescriptor(JSContext *cx, JS::HandleObject wrapper,
                        JS::HandleId id,
                        JS::MutableHandle<JS::PropertyDescriptor> desc) const
  {

  }
  
  bool 
  getOwnPropertyDescriptor(JSContext* cx,
                           JS::Handle<JSObject*> wrapper,
                           JS::Handle<jsid> id,
                           JS::MutableHandle<JS::PropertyDescriptor> desc) const
  {

  }

  bool
  ownPropertyKeys(JSContext *cx, JS::HandleObject wrapper, JS::AutoIdVector& props) const
  {

  }

  bool
  defineProperty(JSContext *cx,
                 JS::HandleObject proxy, JS::HandleId id,
                 JS::Handle<JS::PropertyDescriptor> desc,
                 JS::ObjectOpResult &result) const
  {
    return CrossOriginPolicy::deny();
  }

  bool
  delete_(JSContext *cx, JS::HandleObject proxy, 
          JS::HandleId id, JS::ObjectOpResult &result) const
  {
    return CrossOriginPolicy::deny();
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

void
SetThrowDOMExceptionCallback(void (*throw_dom_exception_callback)(JSContext* cx)) {
  set_throw_dom_exception_callback(throw_dom_exception_callback);
}

void
SetIsFrameIdCallback(bool (*is_frame_id_callback)(JSContext* cx, JSObject* obj, jsid idArg)) {
  set_is_frame_id_callback(is_frame_id_callback);
}

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
  return new CrossOriginWrapper();
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

/*
  the handler family check is comparing two memory addresses
  what happens if i modify it to compare the values there
 */
const void*
GetProxyHandler(JSObject* obj)
{
    const js::BaseProxyHandler* handler = js::GetProxyHandler(obj);
    const int * family = (int*) handler->family();
    assert(*family == HandlerFamily);
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
