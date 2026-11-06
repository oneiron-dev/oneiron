(()=>{var bV=Object.create;var{getPrototypeOf:fV,defineProperty:F_,getOwnPropertyNames:mV}=Object;var hV=Object.prototype.hasOwnProperty;var PZ=(J,H,Y)=>{Y=J!=null?bV(fV(J)):{};let K=H||!J||!J.__esModule?F_(Y,"default",{value:J,enumerable:!0}):Y;for(let W of mV(J))if(!hV.call(K,W))F_(K,W,{get:()=>J[W],enumerable:!0});return K};var h6=(J,H)=>()=>(H||J((H={exports:{}}).exports,H),H.exports);var R_=h6((P7,Sz)=>{(function(){function J(_,E){Object.defineProperty(K.prototype,_,{get:function(){console.warn("%s(...) is deprecated in plain JavaScript React classes. %s",E[0],E[1])}})}function H(_){if(_===null||typeof _!=="object")return null;return _=Z5&&_[Z5]||_["@@iterator"],typeof _==="function"?_:null}function Y(_,E){_=(_=_.constructor)&&(_.displayName||_.name)||"ReactClass";var a=_+"."+E;M4[a]||(console.error("Can't call %s on a component that is not yet mounted. This is a no-op, but it might indicate a bug in your application. Instead, assign to `this.state` directly or define a `state = {};` class property with the desired state in the %s component.",E,_),M4[a]=!0)}function K(_,E,a){this.props=_,this.context=E,this.refs=Y2,this.updater=a||_2}function W(){}function O(_,E,a){this.props=_,this.context=E,this.refs=Y2,this.updater=a||_2}function A(){}function C(_){return""+_}function x(_){try{C(_);var E=!1}catch(e){E=!0}if(E){E=console;var a=E.error,H4=typeof Symbol==="function"&&Symbol.toStringTag&&_[Symbol.toStringTag]||_.constructor.name||"Object";return a.call(E,"The provided key is an unsupported type %s. This value must be coerced to a string before using it here.",H4),C(_)}}function J4(_){if(_==null)return null;if(typeof _==="function")return _.$$typeof===M2?null:_.displayName||_.name||null;if(typeof _==="string")return _;switch(_){case C4:return"Fragment";case s:return"Profiler";case R7:return"StrictMode";case EZ:return"Suspense";case I2:return"SuspenseList";case eZ:return"Activity"}if(typeof _==="object")switch(typeof _.tag==="number"&&console.error("Received an unexpected object in getComponentNameFromType(). This is likely a bug in React. Please file an issue."),_.$$typeof){case $4:return"Portal";case Q7:return _.displayName||"Context";case c4:return(_._context.displayName||"Context")+".Consumer";case W7:var E=_.render;return _=_.displayName,_||(_=E.displayName||E.name||"",_=_!==""?"ForwardRef("+_+")":"ForwardRef"),_;case u7:return E=_.displayName||null,E!==null?E:J4(_.type)||"Memo";case AZ:E=_._payload,_=_._init;try{return J4(_(E))}catch(a){}}return null}function b(_){if(_===C4)return"<>";if(typeof _==="object"&&_!==null&&_.$$typeof===AZ)return"<...>";try{var E=J4(_);return E?"<"+E+">":"<...>"}catch(a){return"<...>"}}function g(){var _=N4.A;return _===null?null:_.getOwner()}function R(){return Error("react-stack-top-frame")}function o(_){if(U4.call(_,"key")){var E=Object.getOwnPropertyDescriptor(_,"key").get;if(E&&E.isReactWarning)return!1}return _.key!==void 0}function p(_,E){function a(){z7||(z7=!0,console.error("%s: `key` is not a prop. Trying to access it will result in `undefined` being returned. If you need to access the same value within the child component, you should pass it as a different prop. (https://react.dev/link/special-props)",E))}a.isReactWarning=!0,Object.defineProperty(_,"key",{get:a,configurable:!0})}function q4(){var _=J4(this.type);return t4[_]||(t4[_]=!0,console.error("Accessing element.ref was removed in React 19. ref is now a regular prop. It will be removed from the JSX Element type in a future release.")),_=this.props.ref,_!==void 0?_:null}function h(_,E,a,H4,e,x4){var F4=a.ref;return _={$$typeof:O4,type:_,key:E,props:a,_owner:H4},(F4!==void 0?F4:null)!==null?Object.defineProperty(_,"ref",{enumerable:!1,get:q4}):Object.defineProperty(_,"ref",{enumerable:!1,value:null}),_._store={},Object.defineProperty(_._store,"validated",{configurable:!1,enumerable:!1,writable:!0,value:0}),Object.defineProperty(_,"_debugInfo",{configurable:!1,enumerable:!1,writable:!0,value:null}),Object.defineProperty(_,"_debugStack",{configurable:!1,enumerable:!1,writable:!0,value:e}),Object.defineProperty(_,"_debugTask",{configurable:!1,enumerable:!1,writable:!0,value:x4}),Object.freeze&&(Object.freeze(_.props),Object.freeze(_)),_}function t(_,E){return E=h(_.type,E,_.props,_._owner,_._debugStack,_._debugTask),_._store&&(E._store.validated=_._store.validated),E}function I4(_){u4(_)?_._store&&(_._store.validated=1):typeof _==="object"&&_!==null&&_.$$typeof===AZ&&(_._payload.status==="fulfilled"?u4(_._payload.value)&&_._payload.value._store&&(_._payload.value._store.validated=1):_._store&&(_._store.validated=1))}function u4(_){return typeof _==="object"&&_!==null&&_.$$typeof===O4}function i4(_){var E={"=":"=0",":":"=2"};return"$"+_.replace(/[=:]/g,function(a){return E[a]})}function g7(_,E){return typeof _==="object"&&_!==null&&_.key!=null?(x(_.key),i4(""+_.key)):E.toString(36)}function h7(_){switch(_.status){case"fulfilled":return _.value;case"rejected":throw _.reason;default:switch(typeof _.status==="string"?_.then(A,A):(_.status="pending",_.then(function(E){_.status==="pending"&&(_.status="fulfilled",_.value=E)},function(E){_.status==="pending"&&(_.status="rejected",_.reason=E)})),_.status){case"fulfilled":return _.value;case"rejected":throw _.reason}}throw _}function T4(_,E,a,H4,e){var x4=typeof _;if(x4==="undefined"||x4==="boolean")_=null;var F4=!1;if(_===null)F4=!0;else switch(x4){case"bigint":case"string":case"number":F4=!0;break;case"object":switch(_.$$typeof){case O4:case $4:F4=!0;break;case AZ:return F4=_._init,T4(F4(_._payload),E,a,H4,e)}}if(F4){F4=_,e=e(F4);var E4=H4===""?"."+g7(F4,0):H4;return s7(e)?(a="",E4!=null&&(a=E4.replace(A7,"$&/")+"/"),T4(e,E,a,"",function(M7){return M7})):e!=null&&(u4(e)&&(e.key!=null&&(F4&&F4.key===e.key||x(e.key)),a=t(e,a+(e.key==null||F4&&F4.key===e.key?"":(""+e.key).replace(A7,"$&/")+"/")+E4),H4!==""&&F4!=null&&u4(F4)&&F4.key==null&&F4._store&&!F4._store.validated&&(a._store.validated=2),e=a),E.push(e)),1}if(F4=0,E4=H4===""?".":H4+":",s7(_))for(var Q4=0;Q4<_.length;Q4++)H4=_[Q4],x4=E4+g7(H4,Q4),F4+=T4(H4,E,a,x4,e);else if(Q4=H(_),typeof Q4==="function")for(Q4===_.entries&&(S7||console.warn("Using Maps as children is not supported. Use an array of keyed ReactElements instead."),S7=!0),_=Q4.call(_),Q4=0;!(H4=_.next()).done;)H4=H4.value,x4=E4+g7(H4,Q4++),F4+=T4(H4,E,a,x4,e);else if(x4==="object"){if(typeof _.then==="function")return T4(h7(_),E,a,H4,e);throw E=String(_),Error("Objects are not valid as a React child (found: "+(E==="[object Object]"?"object with keys {"+Object.keys(_).join(", ")+"}":E)+"). If you meant to render a collection of children, use an array instead.")}return F4}function p4(_,E,a){if(_==null)return _;var H4=[],e=0;return T4(_,H4,"","",function(x4){return E.call(a,x4,e++)}),H4}function N7(_){if(_._status===-1){var E=_._ioInfo;E!=null&&(E.start=E.end=performance.now()),E=_._result;var a=E();if(a.then(function(e){if(_._status===0||_._status===-1){_._status=1,_._result=e;var x4=_._ioInfo;x4!=null&&(x4.end=performance.now()),a.status===void 0&&(a.status="fulfilled",a.value=e)}},function(e){if(_._status===0||_._status===-1){_._status=2,_._result=e;var x4=_._ioInfo;x4!=null&&(x4.end=performance.now()),a.status===void 0&&(a.status="rejected",a.reason=e)}}),E=_._ioInfo,E!=null){E.value=a;var H4=a.displayName;typeof H4==="string"&&(E.name=H4)}_._status===-1&&(_._status=0,_._result=a)}if(_._status===1)return E=_._result,E===void 0&&console.error(`lazy: Expected the result of a dynamic import() call. Instead received: %s

Your code should look like: 
  const MyComponent = lazy(() => import('./MyComponent'))

Did you accidentally put curly braces around the import?`,E),"default"in E||console.error(`lazy: Expected the result of a dynamic import() call. Instead received: %s

Your code should look like: 
  const MyComponent = lazy(() => import('./MyComponent'))`,E),E.default;throw _._result}function Y4(){var _=N4.H;return _===null&&console.error(`Invalid hook call. Hooks can only be called inside of the body of a function component. This could happen for one of the following reasons:
1. You might have mismatching versions of React and the renderer (such as React DOM)
2. You might be breaking the Rules of Hooks
3. You might have more than one copy of React in the same app
See https://react.dev/link/invalid-hook-call for tips about how to debug and fix this problem.`),_}function l4(){N4.asyncTransitions--}function d4(_){if(u===null)try{var E=("require"+Math.random()).slice(0,7);u=(Sz&&Sz[E]).call(Sz,"timers").setImmediate}catch(a){u=function(H4){f===!1&&(f=!0,typeof MessageChannel>"u"&&console.error("This browser does not have a MessageChannel implementation, so enqueuing tasks via await act(async () => ...) will fail. Please file an issue at https://github.com/facebook/react/issues if you encounter this warning."));var e=new MessageChannel;e.port1.onmessage=H4,e.port2.postMessage(void 0)}}return u(_)}function b4(_){return 1<_.length&&typeof AggregateError==="function"?AggregateError(_):_[0]}function n4(_,E){E!==G4-1&&console.error("You seem to have overlapping act() calls, this is not supported. Be sure to await previous act() calls before making a new one. "),G4=E}function B4(_,E,a){var H4=N4.actQueue;if(H4!==null)if(H4.length!==0)try{L4(H4),d4(function(){return B4(_,E,a)});return}catch(e){N4.thrownErrors.push(e)}else N4.actQueue=null;0<N4.thrownErrors.length?(H4=b4(N4.thrownErrors),N4.thrownErrors.length=0,a(H4)):E(_)}function L4(_){if(!S4){S4=!0;var E=0;try{for(;E<_.length;E++){var a=_[E];do{N4.didUsePromise=!1;var H4=a(!1);if(H4!==null){if(N4.didUsePromise){_[E]=a,_.splice(0,E);return}a=H4}else break}while(1)}_.length=0}catch(e){_.splice(0,E+1),N4.thrownErrors.push(e)}finally{S4=!1}}}typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart(Error());var O4=Symbol.for("react.transitional.element"),$4=Symbol.for("react.portal"),C4=Symbol.for("react.fragment"),R7=Symbol.for("react.strict_mode"),s=Symbol.for("react.profiler"),c4=Symbol.for("react.consumer"),Q7=Symbol.for("react.context"),W7=Symbol.for("react.forward_ref"),EZ=Symbol.for("react.suspense"),I2=Symbol.for("react.suspense_list"),u7=Symbol.for("react.memo"),AZ=Symbol.for("react.lazy"),eZ=Symbol.for("react.activity"),Z5=Symbol.iterator,M4={},_2={isMounted:function(){return!1},enqueueForceUpdate:function(_){Y(_,"forceUpdate")},enqueueReplaceState:function(_){Y(_,"replaceState")},enqueueSetState:function(_){Y(_,"setState")}},uZ=Object.assign,Y2={};Object.freeze(Y2),K.prototype.isReactComponent={},K.prototype.setState=function(_,E){if(typeof _!=="object"&&typeof _!=="function"&&_!=null)throw Error("takes an object of state variables to update or a function which returns an object of state variables.");this.updater.enqueueSetState(this,_,E,"setState")},K.prototype.forceUpdate=function(_){this.updater.enqueueForceUpdate(this,_,"forceUpdate")};var qZ={isMounted:["isMounted","Instead, make sure to clean up subscriptions and pending requests in componentWillUnmount to prevent memory leaks."],replaceState:["replaceState","Refactor your code to use setState instead (see https://github.com/facebook/react/issues/3236)."]};for(j4 in qZ)qZ.hasOwnProperty(j4)&&J(j4,qZ[j4]);W.prototype=K.prototype,qZ=O.prototype=new W,qZ.constructor=O,uZ(qZ,K.prototype),qZ.isPureReactComponent=!0;var s7=Array.isArray,M2=Symbol.for("react.client.reference"),N4={H:null,A:null,T:null,S:null,actQueue:null,asyncTransitions:0,isBatchingLegacy:!1,didScheduleLegacyUpdate:!1,didUsePromise:!1,thrownErrors:[],getCurrentStack:null,recentlyCreatedOwnerStacks:0},U4=Object.prototype.hasOwnProperty,D4=console.createTask?console.createTask:function(){return null};qZ={react_stack_bottom_frame:function(_){return _()}};var z7,J7,t4={},b7=qZ.react_stack_bottom_frame.bind(qZ,R)(),o7=D4(b(R)),S7=!1,A7=/\/+/g,o4=typeof reportError==="function"?reportError:function(_){if(typeof window==="object"&&typeof window.ErrorEvent==="function"){var E=new window.ErrorEvent("error",{bubbles:!0,cancelable:!0,message:typeof _==="object"&&_!==null&&typeof _.message==="string"?String(_.message):String(_),error:_});if(!window.dispatchEvent(E))return}else if(typeof process==="object"&&typeof process.emit==="function"){process.emit("uncaughtException",_);return}console.error(_)},f=!1,u=null,G4=0,z4=!1,S4=!1,m4=typeof queueMicrotask==="function"?function(_){queueMicrotask(function(){return queueMicrotask(_)})}:d4;qZ=Object.freeze({__proto__:null,c:function(_){return Y4().useMemoCache(_)}});var j4={map:p4,forEach:function(_,E,a){p4(_,function(){E.apply(this,arguments)},a)},count:function(_){var E=0;return p4(_,function(){E++}),E},toArray:function(_){return p4(_,function(E){return E})||[]},only:function(_){if(!u4(_))throw Error("React.Children.only expected to receive a single React element child.");return _}};P7.Activity=eZ,P7.Children=j4,P7.Component=K,P7.Fragment=C4,P7.Profiler=s,P7.PureComponent=O,P7.StrictMode=R7,P7.Suspense=EZ,P7.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE=N4,P7.__COMPILER_RUNTIME=qZ,P7.act=function(_){var E=N4.actQueue,a=G4;G4++;var H4=N4.actQueue=E!==null?E:[],e=!1;try{var x4=_()}catch(Q4){N4.thrownErrors.push(Q4)}if(0<N4.thrownErrors.length)throw n4(E,a),_=b4(N4.thrownErrors),N4.thrownErrors.length=0,_;if(x4!==null&&typeof x4==="object"&&typeof x4.then==="function"){var F4=x4;return m4(function(){e||z4||(z4=!0,console.error("You called act(async () => ...) without await. This could lead to unexpected testing behaviour, interleaving multiple act calls and mixing their scopes. You should - await act(async () => ...);"))}),{then:function(Q4,M7){e=!0,F4.then(function(U7){if(n4(E,a),a===0){try{L4(H4),d4(function(){return B4(U7,Q4,M7)})}catch(f7){N4.thrownErrors.push(f7)}if(0<N4.thrownErrors.length){var H7=b4(N4.thrownErrors);N4.thrownErrors.length=0,M7(H7)}}else Q4(U7)},function(U7){n4(E,a),0<N4.thrownErrors.length?(U7=b4(N4.thrownErrors),N4.thrownErrors.length=0,M7(U7)):M7(U7)})}}}var E4=x4;if(n4(E,a),a===0&&(L4(H4),H4.length!==0&&m4(function(){e||z4||(z4=!0,console.error("A component suspended inside an `act` scope, but the `act` call was not awaited. When testing React components that depend on asynchronous data, you must await the result:\n\nawait act(() => ...)"))}),N4.actQueue=null),0<N4.thrownErrors.length)throw _=b4(N4.thrownErrors),N4.thrownErrors.length=0,_;return{then:function(Q4,M7){e=!0,a===0?(N4.actQueue=H4,d4(function(){return B4(E4,Q4,M7)})):Q4(E4)}}},P7.cache=function(_){return function(){return _.apply(null,arguments)}},P7.cacheSignal=function(){return null},P7.captureOwnerStack=function(){var _=N4.getCurrentStack;return _===null?null:_()},P7.cloneElement=function(_,E,a){if(_===null||_===void 0)throw Error("The argument must be a React element, but you passed "+_+".");var H4=uZ({},_.props),e=_.key,x4=_._owner;if(E!=null){var F4;Z:{if(U4.call(E,"ref")&&(F4=Object.getOwnPropertyDescriptor(E,"ref").get)&&F4.isReactWarning){F4=!1;break Z}F4=E.ref!==void 0}F4&&(x4=g()),o(E)&&(x(E.key),e=""+E.key);for(E4 in E)!U4.call(E,E4)||E4==="key"||E4==="__self"||E4==="__source"||E4==="ref"&&E.ref===void 0||(H4[E4]=E[E4])}var E4=arguments.length-2;if(E4===1)H4.children=a;else if(1<E4){F4=Array(E4);for(var Q4=0;Q4<E4;Q4++)F4[Q4]=arguments[Q4+2];H4.children=F4}H4=h(_.type,e,H4,x4,_._debugStack,_._debugTask);for(e=2;e<arguments.length;e++)I4(arguments[e]);return H4},P7.createContext=function(_){return _={$$typeof:Q7,_currentValue:_,_currentValue2:_,_threadCount:0,Provider:null,Consumer:null},_.Provider=_,_.Consumer={$$typeof:c4,_context:_},_._currentRenderer=null,_._currentRenderer2=null,_},P7.createElement=function(_,E,a){for(var H4=2;H4<arguments.length;H4++)I4(arguments[H4]);H4={};var e=null;if(E!=null)for(Q4 in J7||!("__self"in E)||"key"in E||(J7=!0,console.warn("Your app (or one of its dependencies) is using an outdated JSX transform. Update to the modern JSX transform for faster performance: https://react.dev/link/new-jsx-transform")),o(E)&&(x(E.key),e=""+E.key),E)U4.call(E,Q4)&&Q4!=="key"&&Q4!=="__self"&&Q4!=="__source"&&(H4[Q4]=E[Q4]);var x4=arguments.length-2;if(x4===1)H4.children=a;else if(1<x4){for(var F4=Array(x4),E4=0;E4<x4;E4++)F4[E4]=arguments[E4+2];Object.freeze&&Object.freeze(F4),H4.children=F4}if(_&&_.defaultProps)for(Q4 in x4=_.defaultProps,x4)H4[Q4]===void 0&&(H4[Q4]=x4[Q4]);e&&p(H4,typeof _==="function"?_.displayName||_.name||"Unknown":_);var Q4=1e4>N4.recentlyCreatedOwnerStacks++;return h(_,e,H4,g(),Q4?Error("react-stack-top-frame"):b7,Q4?D4(b(_)):o7)},P7.createRef=function(){var _={current:null};return Object.seal(_),_},P7.forwardRef=function(_){_!=null&&_.$$typeof===u7?console.error("forwardRef requires a render function but received a `memo` component. Instead of forwardRef(memo(...)), use memo(forwardRef(...))."):typeof _!=="function"?console.error("forwardRef requires a render function but was given %s.",_===null?"null":typeof _):_.length!==0&&_.length!==2&&console.error("forwardRef render functions accept exactly two parameters: props and ref. %s",_.length===1?"Did you forget to use the ref parameter?":"Any additional parameter will be undefined."),_!=null&&_.defaultProps!=null&&console.error("forwardRef render functions do not support defaultProps. Did you accidentally pass a React component?");var E={$$typeof:W7,render:_},a;return Object.defineProperty(E,"displayName",{enumerable:!1,configurable:!0,get:function(){return a},set:function(H4){a=H4,_.name||_.displayName||(Object.defineProperty(_,"name",{value:H4}),_.displayName=H4)}}),E},P7.isValidElement=u4,P7.lazy=function(_){_={_status:-1,_result:_};var E={$$typeof:AZ,_payload:_,_init:N7},a={name:"lazy",start:-1,end:-1,value:null,owner:null,debugStack:Error("react-stack-top-frame"),debugTask:console.createTask?console.createTask("lazy()"):null};return _._ioInfo=a,E._debugInfo=[{awaited:a}],E},P7.memo=function(_,E){_==null&&console.error("memo: The first argument must be a component. Instead received: %s",_===null?"null":typeof _),E={$$typeof:u7,type:_,compare:E===void 0?null:E};var a;return Object.defineProperty(E,"displayName",{enumerable:!1,configurable:!0,get:function(){return a},set:function(H4){a=H4,_.name||_.displayName||(Object.defineProperty(_,"name",{value:H4}),_.displayName=H4)}}),E},P7.startTransition=function(_){var E=N4.T,a={};a._updatedFibers=new Set,N4.T=a;try{var H4=_(),e=N4.S;e!==null&&e(a,H4),typeof H4==="object"&&H4!==null&&typeof H4.then==="function"&&(N4.asyncTransitions++,H4.then(l4,l4),H4.then(A,o4))}catch(x4){o4(x4)}finally{E===null&&a._updatedFibers&&(_=a._updatedFibers.size,a._updatedFibers.clear(),10<_&&console.warn("Detected a large number of updates inside startTransition. If this is due to a subscription please re-write it to use React provided hooks. Otherwise concurrent mode guarantees are off the table.")),E!==null&&a.types!==null&&(E.types!==null&&E.types!==a.types&&console.error("We expected inner Transitions to have transferred the outer types set and that you cannot add to the outer Transition while inside the inner.This is a bug in React."),E.types=a.types),N4.T=E}},P7.unstable_useCacheRefresh=function(){return Y4().useCacheRefresh()},P7.use=function(_){return Y4().use(_)},P7.useActionState=function(_,E,a){return Y4().useActionState(_,E,a)},P7.useCallback=function(_,E){return Y4().useCallback(_,E)},P7.useContext=function(_){var E=Y4();return _.$$typeof===c4&&console.error("Calling useContext(Context.Consumer) is not supported and will cause bugs. Did you mean to call useContext(Context) instead?"),E.useContext(_)},P7.useDebugValue=function(_,E){return Y4().useDebugValue(_,E)},P7.useDeferredValue=function(_,E){return Y4().useDeferredValue(_,E)},P7.useEffect=function(_,E){return _==null&&console.warn("React Hook useEffect requires an effect callback. Did you forget to pass a callback to the hook?"),Y4().useEffect(_,E)},P7.useEffectEvent=function(_){return Y4().useEffectEvent(_)},P7.useId=function(){return Y4().useId()},P7.useImperativeHandle=function(_,E,a){return Y4().useImperativeHandle(_,E,a)},P7.useInsertionEffect=function(_,E){return _==null&&console.warn("React Hook useInsertionEffect requires an effect callback. Did you forget to pass a callback to the hook?"),Y4().useInsertionEffect(_,E)},P7.useLayoutEffect=function(_,E){return _==null&&console.warn("React Hook useLayoutEffect requires an effect callback. Did you forget to pass a callback to the hook?"),Y4().useLayoutEffect(_,E)},P7.useMemo=function(_,E){return Y4().useMemo(_,E)},P7.useOptimistic=function(_,E){return Y4().useOptimistic(_,E)},P7.useReducer=function(_,E,a){return Y4().useReducer(_,E,a)},P7.useRef=function(_){return Y4().useRef(_)},P7.useState=function(_){return Y4().useState(_)},P7.useSyncExternalStore=function(_,E,a){return Y4().useSyncExternalStore(_,E,a)},P7.useTransition=function(){return Y4().useTransition()},P7.version="19.2.8",typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop(Error())})()});var E5=h6((QM,M_)=>{M_.exports=R_()});var N_=h6((SZ)=>{(function(){function J(){if(i4=!1,p4){var B4=SZ.unstable_now();l4=B4;var L4=!0;try{Z:{I4=!1,u4&&(u4=!1,h7(N7),N7=-1),t=!0;var O4=h;try{G:{O(B4);for(q4=Y(R);q4!==null&&!(q4.expirationTime>B4&&C());){var $4=q4.callback;if(typeof $4==="function"){q4.callback=null,h=q4.priorityLevel;var C4=$4(q4.expirationTime<=B4);if(B4=SZ.unstable_now(),typeof C4==="function"){q4.callback=C4,O(B4),L4=!0;break G}q4===Y(R)&&K(R),O(B4)}else K(R);q4=Y(R)}if(q4!==null)L4=!0;else{var R7=Y(o);R7!==null&&x(A,R7.startTime-B4),L4=!1}}break Z}finally{q4=null,h=O4,t=!1}L4=void 0}}finally{L4?d4():p4=!1}}}function H(B4,L4){var O4=B4.length;B4.push(L4);Z:for(;0<O4;){var $4=O4-1>>>1,C4=B4[$4];if(0<W(C4,L4))B4[$4]=L4,B4[O4]=C4,O4=$4;else break Z}}function Y(B4){return B4.length===0?null:B4[0]}function K(B4){if(B4.length===0)return null;var L4=B4[0],O4=B4.pop();if(O4!==L4){B4[0]=O4;Z:for(var $4=0,C4=B4.length,R7=C4>>>1;$4<R7;){var s=2*($4+1)-1,c4=B4[s],Q7=s+1,W7=B4[Q7];if(0>W(c4,O4))Q7<C4&&0>W(W7,c4)?(B4[$4]=W7,B4[Q7]=O4,$4=Q7):(B4[$4]=c4,B4[s]=O4,$4=s);else if(Q7<C4&&0>W(W7,O4))B4[$4]=W7,B4[Q7]=O4,$4=Q7;else break Z}}return L4}function W(B4,L4){var O4=B4.sortIndex-L4.sortIndex;return O4!==0?O4:B4.id-L4.id}function O(B4){for(var L4=Y(o);L4!==null;){if(L4.callback===null)K(o);else if(L4.startTime<=B4)K(o),L4.sortIndex=L4.expirationTime,H(R,L4);else break;L4=Y(o)}}function A(B4){if(u4=!1,O(B4),!I4)if(Y(R)!==null)I4=!0,p4||(p4=!0,d4());else{var L4=Y(o);L4!==null&&x(A,L4.startTime-B4)}}function C(){return i4?!0:SZ.unstable_now()-l4<Y4?!1:!0}function x(B4,L4){N7=g7(function(){B4(SZ.unstable_now())},L4)}if(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart(Error()),SZ.unstable_now=void 0,typeof performance==="object"&&typeof performance.now==="function"){var J4=performance;SZ.unstable_now=function(){return J4.now()}}else{var b=Date,g=b.now();SZ.unstable_now=function(){return b.now()-g}}var R=[],o=[],p=1,q4=null,h=3,t=!1,I4=!1,u4=!1,i4=!1,g7=typeof setTimeout==="function"?setTimeout:null,h7=typeof clearTimeout==="function"?clearTimeout:null,T4=typeof setImmediate<"u"?setImmediate:null,p4=!1,N7=-1,Y4=5,l4=-1;if(typeof T4==="function")var d4=function(){T4(J)};else if(typeof MessageChannel<"u"){var b4=new MessageChannel,n4=b4.port2;b4.port1.onmessage=J,d4=function(){n4.postMessage(null)}}else d4=function(){g7(J,0)};SZ.unstable_IdlePriority=5,SZ.unstable_ImmediatePriority=1,SZ.unstable_LowPriority=4,SZ.unstable_NormalPriority=3,SZ.unstable_Profiling=null,SZ.unstable_UserBlockingPriority=2,SZ.unstable_cancelCallback=function(B4){B4.callback=null},SZ.unstable_forceFrameRate=function(B4){0>B4||125<B4?console.error("forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported"):Y4=0<B4?Math.floor(1000/B4):5},SZ.unstable_getCurrentPriorityLevel=function(){return h},SZ.unstable_next=function(B4){switch(h){case 1:case 2:case 3:var L4=3;break;default:L4=h}var O4=h;h=L4;try{return B4()}finally{h=O4}},SZ.unstable_requestPaint=function(){i4=!0},SZ.unstable_runWithPriority=function(B4,L4){switch(B4){case 1:case 2:case 3:case 4:case 5:break;default:B4=3}var O4=h;h=B4;try{return L4()}finally{h=O4}},SZ.unstable_scheduleCallback=function(B4,L4,O4){var $4=SZ.unstable_now();switch(typeof O4==="object"&&O4!==null?(O4=O4.delay,O4=typeof O4==="number"&&0<O4?$4+O4:$4):O4=$4,B4){case 1:var C4=-1;break;case 2:C4=250;break;case 5:C4=1073741823;break;case 4:C4=1e4;break;default:C4=5000}return C4=O4+C4,B4={id:p++,callback:L4,priorityLevel:B4,startTime:O4,expirationTime:C4,sortIndex:-1},O4>$4?(B4.sortIndex=O4,H(o,B4),Y(R)===null&&B4===Y(o)&&(u4?(h7(N7),N7=-1):u4=!0,x(A,O4-$4))):(B4.sortIndex=C4,H(R,B4),I4||t||(I4=!0,p4||(p4=!0,d4()))),B4},SZ.unstable_shouldYield=C,SZ.unstable_wrapCallback=function(B4){var L4=h;return function(){var O4=h;h=L4;try{return B4.apply(this,arguments)}finally{h=O4}}},typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop(Error())})()});var P_=h6((qM,D_)=>{D_.exports=N_()});var A_=h6((r2)=>{(function(){function J(){}function H(g){return""+g}function Y(g,R,o){var p=3<arguments.length&&arguments[3]!==void 0?arguments[3]:null;try{H(p);var q4=!1}catch(h){q4=!0}return q4&&(console.error("The provided key is an unsupported type %s. This value must be coerced to a string before using it here.",typeof Symbol==="function"&&Symbol.toStringTag&&p[Symbol.toStringTag]||p.constructor.name||"Object"),H(p)),{$$typeof:J4,key:p==null?null:""+p,children:g,containerInfo:R,implementation:o}}function K(g,R){if(g==="font")return"";if(typeof R==="string")return R==="use-credentials"?R:""}function W(g){return g===null?"`null`":g===void 0?"`undefined`":g===""?"an empty string":'something with type "'+typeof g+'"'}function O(g){return g===null?"`null`":g===void 0?"`undefined`":g===""?"an empty string":typeof g==="string"?JSON.stringify(g):typeof g==="number"?"`"+g+"`":'something with type "'+typeof g+'"'}function A(){var g=b.H;return g===null&&console.error(`Invalid hook call. Hooks can only be called inside of the body of a function component. This could happen for one of the following reasons:
1. You might have mismatching versions of React and the renderer (such as React DOM)
2. You might be breaking the Rules of Hooks
3. You might have more than one copy of React in the same app
See https://react.dev/link/invalid-hook-call for tips about how to debug and fix this problem.`),g}typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart(Error());var C=E5(),x={d:{f:J,r:function(){throw Error("Invalid form element. requestFormReset must be passed a form that was rendered by React.")},D:J,C:J,L:J,m:J,X:J,S:J,M:J},p:0,findDOMNode:null},J4=Symbol.for("react.portal"),b=C.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;typeof Map==="function"&&Map.prototype!=null&&typeof Map.prototype.forEach==="function"&&typeof Set==="function"&&Set.prototype!=null&&typeof Set.prototype.clear==="function"&&typeof Set.prototype.forEach==="function"||console.error("React depends on Map and Set built-in types. Make sure that you load a polyfill in older browsers. https://reactjs.org/link/react-polyfills"),r2.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE=x,r2.createPortal=function(g,R){var o=2<arguments.length&&arguments[2]!==void 0?arguments[2]:null;if(!R||R.nodeType!==1&&R.nodeType!==9&&R.nodeType!==11)throw Error("Target container is not a DOM element.");return Y(g,R,null,o)},r2.flushSync=function(g){var R=b.T,o=x.p;try{if(b.T=null,x.p=2,g)return g()}finally{b.T=R,x.p=o,x.d.f()&&console.error("flushSync was called from inside a lifecycle method. React cannot flush when React is already rendering. Consider moving this call to a scheduler task or micro task.")}},r2.preconnect=function(g,R){typeof g==="string"&&g?R!=null&&typeof R!=="object"?console.error("ReactDOM.preconnect(): Expected the `options` argument (second) to be an object but encountered %s instead. The only supported option at this time is `crossOrigin` which accepts a string.",O(R)):R!=null&&typeof R.crossOrigin!=="string"&&console.error("ReactDOM.preconnect(): Expected the `crossOrigin` option (second argument) to be a string but encountered %s instead. Try removing this option or passing a string value instead.",W(R.crossOrigin)):console.error("ReactDOM.preconnect(): Expected the `href` argument (first) to be a non-empty string but encountered %s instead.",W(g)),typeof g==="string"&&(R?(R=R.crossOrigin,R=typeof R==="string"?R==="use-credentials"?R:"":void 0):R=null,x.d.C(g,R))},r2.prefetchDNS=function(g){if(typeof g!=="string"||!g)console.error("ReactDOM.prefetchDNS(): Expected the `href` argument (first) to be a non-empty string but encountered %s instead.",W(g));else if(1<arguments.length){var R=arguments[1];typeof R==="object"&&R.hasOwnProperty("crossOrigin")?console.error("ReactDOM.prefetchDNS(): Expected only one argument, `href`, but encountered %s as a second argument instead. This argument is reserved for future options and is currently disallowed. It looks like the you are attempting to set a crossOrigin property for this DNS lookup hint. Browsers do not perform DNS queries using CORS and setting this attribute on the resource hint has no effect. Try calling ReactDOM.prefetchDNS() with just a single string argument, `href`.",O(R)):console.error("ReactDOM.prefetchDNS(): Expected only one argument, `href`, but encountered %s as a second argument instead. This argument is reserved for future options and is currently disallowed. Try calling ReactDOM.prefetchDNS() with just a single string argument, `href`.",O(R))}typeof g==="string"&&x.d.D(g)},r2.preinit=function(g,R){if(typeof g==="string"&&g?R==null||typeof R!=="object"?console.error("ReactDOM.preinit(): Expected the `options` argument (second) to be an object with an `as` property describing the type of resource to be preinitialized but encountered %s instead.",O(R)):R.as!=="style"&&R.as!=="script"&&console.error('ReactDOM.preinit(): Expected the `as` property in the `options` argument (second) to contain a valid value describing the type of resource to be preinitialized but encountered %s instead. Valid values for `as` are "style" and "script".',O(R.as)):console.error("ReactDOM.preinit(): Expected the `href` argument (first) to be a non-empty string but encountered %s instead.",W(g)),typeof g==="string"&&R&&typeof R.as==="string"){var o=R.as,p=K(o,R.crossOrigin),q4=typeof R.integrity==="string"?R.integrity:void 0,h=typeof R.fetchPriority==="string"?R.fetchPriority:void 0;o==="style"?x.d.S(g,typeof R.precedence==="string"?R.precedence:void 0,{crossOrigin:p,integrity:q4,fetchPriority:h}):o==="script"&&x.d.X(g,{crossOrigin:p,integrity:q4,fetchPriority:h,nonce:typeof R.nonce==="string"?R.nonce:void 0})}},r2.preinitModule=function(g,R){var o="";if(typeof g==="string"&&g||(o+=" The `href` argument encountered was "+W(g)+"."),R!==void 0&&typeof R!=="object"?o+=" The `options` argument encountered was "+W(R)+".":R&&("as"in R)&&R.as!=="script"&&(o+=" The `as` option encountered was "+O(R.as)+"."),o)console.error("ReactDOM.preinitModule(): Expected up to two arguments, a non-empty `href` string and, optionally, an `options` object with a valid `as` property.%s",o);else switch(o=R&&typeof R.as==="string"?R.as:"script",o){case"script":break;default:o=O(o),console.error('ReactDOM.preinitModule(): Currently the only supported "as" type for this function is "script" but received "%s" instead. This warning was generated for `href` "%s". In the future other module types will be supported, aligning with the import-attributes proposal. Learn more here: (https://github.com/tc39/proposal-import-attributes)',o,g)}if(typeof g==="string")if(typeof R==="object"&&R!==null){if(R.as==null||R.as==="script")o=K(R.as,R.crossOrigin),x.d.M(g,{crossOrigin:o,integrity:typeof R.integrity==="string"?R.integrity:void 0,nonce:typeof R.nonce==="string"?R.nonce:void 0})}else R==null&&x.d.M(g)},r2.preload=function(g,R){var o="";if(typeof g==="string"&&g||(o+=" The `href` argument encountered was "+W(g)+"."),R==null||typeof R!=="object"?o+=" The `options` argument encountered was "+W(R)+".":typeof R.as==="string"&&R.as||(o+=" The `as` option encountered was "+W(R.as)+"."),o&&console.error('ReactDOM.preload(): Expected two arguments, a non-empty `href` string and an `options` object with an `as` property valid for a `<link rel="preload" as="..." />` tag.%s',o),typeof g==="string"&&typeof R==="object"&&R!==null&&typeof R.as==="string"){o=R.as;var p=K(o,R.crossOrigin);x.d.L(g,o,{crossOrigin:p,integrity:typeof R.integrity==="string"?R.integrity:void 0,nonce:typeof R.nonce==="string"?R.nonce:void 0,type:typeof R.type==="string"?R.type:void 0,fetchPriority:typeof R.fetchPriority==="string"?R.fetchPriority:void 0,referrerPolicy:typeof R.referrerPolicy==="string"?R.referrerPolicy:void 0,imageSrcSet:typeof R.imageSrcSet==="string"?R.imageSrcSet:void 0,imageSizes:typeof R.imageSizes==="string"?R.imageSizes:void 0,media:typeof R.media==="string"?R.media:void 0})}},r2.preloadModule=function(g,R){var o="";typeof g==="string"&&g||(o+=" The `href` argument encountered was "+W(g)+"."),R!==void 0&&typeof R!=="object"?o+=" The `options` argument encountered was "+W(R)+".":R&&("as"in R)&&typeof R.as!=="string"&&(o+=" The `as` option encountered was "+W(R.as)+"."),o&&console.error('ReactDOM.preloadModule(): Expected two arguments, a non-empty `href` string and, optionally, an `options` object with an `as` property valid for a `<link rel="modulepreload" as="..." />` tag.%s',o),typeof g==="string"&&(R?(o=K(R.as,R.crossOrigin),x.d.m(g,{as:typeof R.as==="string"&&R.as!=="script"?R.as:void 0,crossOrigin:o,integrity:typeof R.integrity==="string"?R.integrity:void 0})):x.d.m(g))},r2.requestFormReset=function(g){x.d.r(g)},r2.unstable_batchedUpdates=function(g,R){return g(R)},r2.useFormState=function(g,R,o){return A().useFormState(g,R,o)},r2.useFormStatus=function(){return A().useHostTransitionStatus()},r2.version="19.2.8",typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop(Error())})()});var vz=h6((XM,C_)=>{C_.exports=A_()});var T_=h6((kz)=>{(function(){function J(Z,G){for(Z=Z.memoizedState;Z!==null&&0<G;)Z=Z.next,G--;return Z}function H(Z,G,B,$){if(B>=G.length)return $;var z=G[B],Q=j2(Z)?Z.slice():k7({},Z);return Q[z]=H(Z[z],G,B+1,$),Q}function Y(Z,G,B){if(G.length!==B.length)console.warn("copyWithRename() expects paths of the same length");else{for(var $=0;$<B.length-1;$++)if(G[$]!==B[$]){console.warn("copyWithRename() expects paths to be the same except for the deepest key");return}return K(Z,G,B,0)}}function K(Z,G,B,$){var z=G[$],Q=j2(Z)?Z.slice():k7({},Z);return $+1===G.length?(Q[B[$]]=Q[z],j2(Q)?Q.splice(z,1):delete Q[z]):Q[z]=K(Z[z],G,B,$+1),Q}function W(Z,G,B){var $=G[B],z=j2(Z)?Z.slice():k7({},Z);if(B+1===G.length)return j2(z)?z.splice($,1):delete z[$],z;return z[$]=W(Z[$],G,B+1),z}function O(){return!1}function A(){return null}function C(){console.error("Do not call Hooks inside useEffect(...), useMemo(...), or other built-in Hooks. You can only call Hooks at the top level of your React function. For more information, see https://react.dev/link/rules-of-hooks")}function x(){console.error("Context can only be read while React is rendering. In classes, you can read it in the render method or getDerivedStateFromProps. In function components, you can read it directly in the function body, but not inside Hooks like useReducer() or useMemo().")}function J4(){}function b(){}function g(Z){var G=[];return Z.forEach(function(B){G.push(B)}),G.sort().join(", ")}function R(Z,G,B,$){return new GQ(Z,G,B,$)}function o(Z,G){Z.context===o8&&(EJ(Z.current,2,G,Z,null,null),kG())}function p(Z,G){if(d5!==null){var B=G.staleFamilies;G=G.updatedFamilies,j1(),AG(Z.current,G,B),kG()}}function q4(Z){d5=Z}function h(Z){return!(!Z||Z.nodeType!==1&&Z.nodeType!==9&&Z.nodeType!==11)}function t(Z){var G=Z,B=Z;if(Z.alternate)for(;G.return;)G=G.return;else{Z=G;do G=Z,(G.flags&4098)!==0&&(B=G.return),Z=G.return;while(Z)}return G.tag===3?B:null}function I4(Z){if(Z.tag===13){var G=Z.memoizedState;if(G===null&&(Z=Z.alternate,Z!==null&&(G=Z.memoizedState)),G!==null)return G.dehydrated}return null}function u4(Z){if(Z.tag===31){var G=Z.memoizedState;if(G===null&&(Z=Z.alternate,Z!==null&&(G=Z.memoizedState)),G!==null)return G.dehydrated}return null}function i4(Z){if(t(Z)!==Z)throw Error("Unable to find node on an unmounted component.")}function g7(Z){var G=Z.alternate;if(!G){if(G=t(Z),G===null)throw Error("Unable to find node on an unmounted component.");return G!==Z?null:Z}for(var B=Z,$=G;;){var z=B.return;if(z===null)break;var Q=z.alternate;if(Q===null){if($=z.return,$!==null){B=$;continue}break}if(z.child===Q.child){for(Q=z.child;Q;){if(Q===B)return i4(z),Z;if(Q===$)return i4(z),G;Q=Q.sibling}throw Error("Unable to find node on an unmounted component.")}if(B.return!==$.return)B=z,$=Q;else{for(var q=!1,X=z.child;X;){if(X===B){q=!0,B=z,$=Q;break}if(X===$){q=!0,$=z,B=Q;break}X=X.sibling}if(!q){for(X=Q.child;X;){if(X===B){q=!0,B=Q,$=z;break}if(X===$){q=!0,$=Q,B=z;break}X=X.sibling}if(!q)throw Error("Child was not found in either parent set. This indicates a bug in React related to the return pointer. Please file an issue.")}}if(B.alternate!==$)throw Error("Return fibers should always be each others' alternates. This error is likely caused by a bug in React. Please file an issue.")}if(B.tag!==3)throw Error("Unable to find node on an unmounted component.");return B.stateNode.current===B?Z:G}function h7(Z){var G=Z.tag;if(G===5||G===26||G===27||G===6)return Z;for(Z=Z.child;Z!==null;){if(G=h7(Z),G!==null)return G;Z=Z.sibling}return null}function T4(Z){if(Z===null||typeof Z!=="object")return null;return Z=Sj&&Z[Sj]||Z["@@iterator"],typeof Z==="function"?Z:null}function p4(Z){if(Z==null)return null;if(typeof Z==="function")return Z.$$typeof===aL?null:Z.displayName||Z.name||null;if(typeof Z==="string")return Z;switch(Z){case uG:return"Fragment";case yJ:return"Profiler";case C$:return"StrictMode";case bJ:return"Suspense";case fJ:return"SuspenseList";case mJ:return"Activity"}if(typeof Z==="object")switch(typeof Z.tag==="number"&&console.error("Received an unexpected object in getComponentNameFromType(). This is likely a bug in React. Please file an issue."),Z.$$typeof){case hG:return"Portal";case w6:return Z.displayName||"Context";case gJ:return(Z._context.displayName||"Context")+".Consumer";case M1:var G=Z.render;return Z=Z.displayName,Z||(Z=G.displayName||G.name||"",Z=Z!==""?"ForwardRef("+Z+")":"ForwardRef"),Z;case T$:return G=Z.displayName||null,G!==null?G:p4(Z.type)||"Memo";case R5:G=Z._payload,Z=Z._init;try{return p4(Z(G))}catch(B){}}return null}function N7(Z){return typeof Z.tag==="number"?Y4(Z):typeof Z.name==="string"?Z.name:null}function Y4(Z){var G=Z.type;switch(Z.tag){case 31:return"Activity";case 24:return"Cache";case 9:return(G._context.displayName||"Context")+".Consumer";case 10:return G.displayName||"Context";case 18:return"DehydratedFragment";case 11:return Z=G.render,Z=Z.displayName||Z.name||"",G.displayName||(Z!==""?"ForwardRef("+Z+")":"ForwardRef");case 7:return"Fragment";case 26:case 27:case 5:return G;case 4:return"Portal";case 3:return"Root";case 6:return"Text";case 16:return p4(G);case 8:return G===C$?"StrictMode":"Mode";case 22:return"Offscreen";case 12:return"Profiler";case 21:return"Scope";case 13:return"Suspense";case 19:return"SuspenseList";case 25:return"TracingMarker";case 1:case 0:case 14:case 15:if(typeof G==="function")return G.displayName||G.name||null;if(typeof G==="string")return G;break;case 29:if(G=Z._debugInfo,G!=null){for(var B=G.length-1;0<=B;B--)if(typeof G[B].name==="string")return G[B].name}if(Z.return!==null)return Y4(Z.return)}return null}function l4(Z){return{current:Z}}function d4(Z,G){0>q8?console.error("Unexpected pop."):(G!==uJ[q8]&&console.error("Unexpected Fiber popped."),Z.current=hJ[q8],hJ[q8]=null,uJ[q8]=null,q8--)}function b4(Z,G,B){q8++,hJ[q8]=Z.current,uJ[q8]=B,Z.current=G}function n4(Z){return Z===null&&console.error("Expected host context to exist. This error is likely caused by a bug in React. Please file an issue."),Z}function B4(Z,G){b4(p8,G,Z),b4(N1,Z,Z),b4(d8,null,Z);var B=G.nodeType;switch(B){case 9:case 11:B=B===9?"#document":"#fragment",G=(G=G.documentElement)?(G=G.namespaceURI)?Bj(G):M8:M8;break;default:if(B=G.tagName,G=G.namespaceURI)G=Bj(G),G=$j(G,B);else switch(B){case"svg":G=M0;break;case"math":G=Az;break;default:G=M8}}B=B.toLowerCase(),B=nz(null,B),B={context:G,ancestorInfo:B},d4(d8,Z),b4(d8,B,Z)}function L4(Z){d4(d8,Z),d4(N1,Z),d4(p8,Z)}function O4(){return n4(d8.current)}function $4(Z){Z.memoizedState!==null&&b4(E$,Z,Z);var G=n4(d8.current),B=Z.type,$=$j(G.context,B);B=nz(G.ancestorInfo,B),$={context:$,ancestorInfo:B},G!==$&&(b4(N1,Z,Z),b4(d8,$,Z))}function C4(Z){N1.current===Z&&(d4(d8,Z),d4(N1,Z)),E$.current===Z&&(d4(E$,Z),WB._currentValue=BG)}function R7(){}function s(){if(D1===0){vj=console.log,kj=console.info,yj=console.warn,gj=console.error,bj=console.group,fj=console.groupCollapsed,mj=console.groupEnd;var Z={configurable:!0,enumerable:!0,value:R7,writable:!0};Object.defineProperties(console,{info:Z,log:Z,warn:Z,error:Z,group:Z,groupCollapsed:Z,groupEnd:Z})}D1++}function c4(){if(D1--,D1===0){var Z={configurable:!0,enumerable:!0,writable:!0};Object.defineProperties(console,{log:k7({},Z,{value:vj}),info:k7({},Z,{value:kj}),warn:k7({},Z,{value:yj}),error:k7({},Z,{value:gj}),group:k7({},Z,{value:bj}),groupCollapsed:k7({},Z,{value:fj}),groupEnd:k7({},Z,{value:mj})})}0>D1&&console.error("disabledDepth fell below zero. This is a bug in React. Please file an issue.")}function Q7(Z){var G=Error.prepareStackTrace;if(Error.prepareStackTrace=void 0,Z=Z.stack,Error.prepareStackTrace=G,Z.startsWith(`Error: react-stack-top-frame
`)&&(Z=Z.slice(29)),G=Z.indexOf(`
`),G!==-1&&(Z=Z.slice(G+1)),G=Z.indexOf("react_stack_bottom_frame"),G!==-1&&(G=Z.lastIndexOf(`
`,G)),G!==-1)Z=Z.slice(0,G);else return"";return Z}function W7(Z){if(dJ===void 0)try{throw Error()}catch(B){var G=B.stack.trim().match(/\n( *(at )?)/);dJ=G&&G[1]||"",hj=-1<B.stack.indexOf(`
    at`)?" (<anonymous>)":-1<B.stack.indexOf("@")?"@unknown:0:0":""}return`
`+dJ+Z+hj}function EZ(Z,G){if(!Z||pJ)return"";var B=cJ.get(Z);if(B!==void 0)return B;pJ=!0,B=Error.prepareStackTrace,Error.prepareStackTrace=void 0;var $=null;$=l.H,l.H=null,s();try{var z={DetermineComponentFrameRoot:function(){try{if(G){var P=function(){throw Error()};if(Object.defineProperty(P.prototype,"props",{set:function(){throw Error()}}),typeof Reflect==="object"&&Reflect.construct){try{Reflect.construct(P,[])}catch(R4){var d=R4}Reflect.construct(Z,[],P)}else{try{P.call()}catch(R4){d=R4}Z.call(P.prototype)}}else{try{throw Error()}catch(R4){d=R4}(P=Z())&&typeof P.catch==="function"&&P.catch(function(){})}}catch(R4){if(R4&&d&&typeof R4.stack==="string")return[R4.stack,d.stack]}return[null,null]}};z.DetermineComponentFrameRoot.displayName="DetermineComponentFrameRoot";var Q=Object.getOwnPropertyDescriptor(z.DetermineComponentFrameRoot,"name");Q&&Q.configurable&&Object.defineProperty(z.DetermineComponentFrameRoot,"name",{value:"DetermineComponentFrameRoot"});var q=z.DetermineComponentFrameRoot(),X=q[0],j=q[1];if(X&&j){var U=X.split(`
`),k=j.split(`
`);for(q=Q=0;Q<U.length&&!U[Q].includes("DetermineComponentFrameRoot");)Q++;for(;q<k.length&&!k[q].includes("DetermineComponentFrameRoot");)q++;if(Q===U.length||q===k.length)for(Q=U.length-1,q=k.length-1;1<=Q&&0<=q&&U[Q]!==k[q];)q--;for(;1<=Q&&0<=q;Q--,q--)if(U[Q]!==k[q]){if(Q!==1||q!==1)do if(Q--,q--,0>q||U[Q]!==k[q]){var y=`
`+U[Q].replace(" at new "," at ");return Z.displayName&&y.includes("<anonymous>")&&(y=y.replace("<anonymous>",Z.displayName)),typeof Z==="function"&&cJ.set(Z,y),y}while(1<=Q&&0<=q);break}}}finally{pJ=!1,l.H=$,c4(),Error.prepareStackTrace=B}return U=(U=Z?Z.displayName||Z.name:"")?W7(U):"",typeof Z==="function"&&cJ.set(Z,U),U}function I2(Z,G){switch(Z.tag){case 26:case 27:case 5:return W7(Z.type);case 16:return W7("Lazy");case 13:return Z.child!==G&&G!==null?W7("Suspense Fallback"):W7("Suspense");case 19:return W7("SuspenseList");case 0:case 15:return EZ(Z.type,!1);case 11:return EZ(Z.type.render,!1);case 1:return EZ(Z.type,!0);case 31:return W7("Activity");default:return""}}function u7(Z){try{var G="",B=null;do{G+=I2(Z,B);var $=Z._debugInfo;if($)for(var z=$.length-1;0<=z;z--){var Q=$[z];if(typeof Q.name==="string"){var q=G;Z:{var{name:X,env:j,debugLocation:U}=Q;if(U!=null){var k=Q7(U),y=k.lastIndexOf(`
`),P=y===-1?k:k.slice(y+1);if(P.indexOf(X)!==-1){var d=`
`+P;break Z}}d=W7(X+(j?" ["+j+"]":""))}G=q+d}}B=Z,Z=Z.return}while(Z);return G}catch(R4){return`
Error generating stack: `+R4.message+`
`+R4.stack}}function AZ(Z){return(Z=Z?Z.displayName||Z.name:"")?W7(Z):""}function eZ(){if(M5===null)return null;var Z=M5._debugOwner;return Z!=null?N7(Z):null}function Z5(){if(M5===null)return"";var Z=M5;try{var G="";switch(Z.tag===6&&(Z=Z.return),Z.tag){case 26:case 27:case 5:G+=W7(Z.type);break;case 13:G+=W7("Suspense");break;case 19:G+=W7("SuspenseList");break;case 31:G+=W7("Activity");break;case 30:case 0:case 15:case 1:Z._debugOwner||G!==""||(G+=AZ(Z.type));break;case 11:Z._debugOwner||G!==""||(G+=AZ(Z.type.render))}for(;Z;)if(typeof Z.tag==="number"){var B=Z;Z=B._debugOwner;var $=B._debugStack;if(Z&&$){var z=Q7($);z!==""&&(G+=`
`+z)}}else if(Z.debugStack!=null){var Q=Z.debugStack;(Z=Z.owner)&&Q&&(G+=`
`+Q7(Q))}else break;var q=G}catch(X){q=`
Error generating stack: `+X.message+`
`+X.stack}return q}function M4(Z,G,B,$,z,Q,q){var X=M5;_2(Z);try{return Z!==null&&Z._debugTask?Z._debugTask.run(G.bind(null,B,$,z,Q,q)):G(B,$,z,Q,q)}finally{_2(X)}throw Error("runWithFiberInDEV should never be called in production. This is a bug in React.")}function _2(Z){l.getCurrentStack=Z===null?null:Z5,I6=!1,M5=Z}function uZ(Z){return typeof Symbol==="function"&&Symbol.toStringTag&&Z[Symbol.toStringTag]||Z.constructor.name||"Object"}function Y2(Z){try{return qZ(Z),!1}catch(G){return!0}}function qZ(Z){return""+Z}function s7(Z,G){if(Y2(Z))return console.error("The provided `%s` attribute is an unsupported type %s. This value must be coerced to a string before using it here.",G,uZ(Z)),qZ(Z)}function M2(Z,G){if(Y2(Z))return console.error("The provided `%s` CSS property is an unsupported type %s. This value must be coerced to a string before using it here.",G,uZ(Z)),qZ(Z)}function N4(Z){if(Y2(Z))return console.error("Form field values (value, checked, defaultValue, or defaultChecked props) must be strings, not %s. This value must be coerced to a string before using it here.",uZ(Z)),qZ(Z)}function U4(Z){if(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__>"u")return!1;var G=__REACT_DEVTOOLS_GLOBAL_HOOK__;if(G.isDisabled)return!0;if(!G.supportsFiber)return console.error("The installed version of React DevTools is too old and will not work with the current version of React. Please update React DevTools. https://react.dev/link/react-devtools"),!0;try{pG=G.inject(Z),y2=G}catch(B){console.error("React instrumentation encountered an error: %o.",B)}return G.checkDCE?!0:!1}function D4(Z){if(typeof ZU==="function"&&GU(Z),y2&&typeof y2.setStrictMode==="function")try{y2.setStrictMode(pG,Z)}catch(G){x6||(x6=!0,console.error("React instrumentation encountered an error: %o",G))}}function z7(Z){return Z>>>=0,Z===0?32:31-(BU(Z)/$U|0)|0}function J7(Z){var G=Z&42;if(G!==0)return G;switch(Z&-Z){case 1:return 1;case 2:return 2;case 4:return 4;case 8:return 8;case 16:return 16;case 32:return 32;case 64:return 64;case 128:return 128;case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:return Z&261888;case 262144:case 524288:case 1048576:case 2097152:return Z&3932160;case 4194304:case 8388608:case 16777216:case 33554432:return Z&62914560;case 67108864:return 67108864;case 134217728:return 134217728;case 268435456:return 268435456;case 536870912:return 536870912;case 1073741824:return 0;default:return console.error("Should have found matching lanes. This is a bug in React."),Z}}function t4(Z,G,B){var $=Z.pendingLanes;if($===0)return 0;var z=0,Q=Z.suspendedLanes,q=Z.pingedLanes;Z=Z.warmLanes;var X=$&134217727;return X!==0?($=X&~Q,$!==0?z=J7($):(q&=X,q!==0?z=J7(q):B||(B=X&~Z,B!==0&&(z=J7(B))))):(X=$&~Q,X!==0?z=J7(X):q!==0?z=J7(q):B||(B=$&~Z,B!==0&&(z=J7(B)))),z===0?0:G!==0&&G!==z&&(G&Q)===0&&(Q=z&-z,B=G&-G,Q>=B||Q===32&&(B&4194048)!==0)?G:z}function b7(Z,G){return(Z.pendingLanes&~(Z.suspendedLanes&~Z.pingedLanes)&G)===0}function o7(Z,G){switch(Z){case 1:case 2:case 4:case 8:case 64:return G+250;case 16:case 32:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:return G+5000;case 4194304:case 8388608:case 16777216:case 33554432:return-1;case 67108864:case 134217728:case 268435456:case 536870912:case 1073741824:return-1;default:return console.error("Should have found matching lanes. This is a bug in React."),-1}}function S7(){var Z=x$;return x$<<=1,(x$&62914560)===0&&(x$=4194304),Z}function A7(Z){for(var G=[],B=0;31>B;B++)G.push(Z);return G}function o4(Z,G){Z.pendingLanes|=G,G!==268435456&&(Z.suspendedLanes=0,Z.pingedLanes=0,Z.warmLanes=0)}function f(Z,G,B,$,z,Q){var q=Z.pendingLanes;Z.pendingLanes=B,Z.suspendedLanes=0,Z.pingedLanes=0,Z.warmLanes=0,Z.expiredLanes&=B,Z.entangledLanes&=B,Z.errorRecoveryDisabledLanes&=B,Z.shellSuspendCounter=0;var{entanglements:X,expirationTimes:j,hiddenUpdates:U}=Z;for(B=q&~B;0<B;){var k=31-d2(B),y=1<<k;X[k]=0,j[k]=-1;var P=U[k];if(P!==null)for(U[k]=null,k=0;k<P.length;k++){var d=P[k];d!==null&&(d.lane&=-536870913)}B&=~y}$!==0&&u(Z,$,0),Q!==0&&z===0&&Z.tag!==0&&(Z.suspendedLanes|=Q&~(q&~G))}function u(Z,G,B){Z.pendingLanes|=G,Z.suspendedLanes&=~G;var $=31-d2(G);Z.entangledLanes|=G,Z.entanglements[$]=Z.entanglements[$]|1073741824|B&261930}function G4(Z,G){var B=Z.entangledLanes|=G;for(Z=Z.entanglements;B;){var $=31-d2(B),z=1<<$;z&G|Z[$]&G&&(Z[$]|=G),B&=~z}}function z4(Z,G){var B=G&-G;return B=(B&42)!==0?1:S4(B),(B&(Z.suspendedLanes|G))!==0?0:B}function S4(Z){switch(Z){case 2:Z=1;break;case 8:Z=4;break;case 32:Z=16;break;case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:case 4194304:case 8388608:case 16777216:case 33554432:Z=128;break;case 268435456:Z=134217728;break;default:Z=0}return Z}function m4(Z,G,B){if(S6)for(Z=Z.pendingUpdatersLaneMap;0<B;){var $=31-d2(B),z=1<<$;Z[$].add(G),B&=~z}}function j4(Z,G){if(S6)for(var{pendingUpdatersLaneMap:B,memoizedUpdaters:$}=Z;0<G;){var z=31-d2(G);Z=1<<z,z=B[z],0<z.size&&(z.forEach(function(Q){var q=Q.alternate;q!==null&&$.has(q)||$.add(Q)}),z.clear()),G&=~Z}}function _(Z){return Z&=-Z,N5!==0&&N5<Z?z6!==0&&z6<Z?(Z&134217727)!==0?v6:S$:z6:N5}function E(){var Z=BZ.p;if(Z!==0)return Z;return Z=window.event,Z===void 0?v6:Aj(Z.type)}function a(Z,G){var B=BZ.p;try{return BZ.p=Z,G()}finally{BZ.p=B}}function H4(Z){delete Z[E2],delete Z[p2],delete Z[oJ],delete Z[zU],delete Z[QU]}function e(Z){var G=Z[E2];if(G)return G;for(var B=Z.parentNode;B;){if(G=B[l8]||B[E2]){if(B=G.alternate,G.child!==null||B!==null&&B.child!==null)for(Z=jj(Z);Z!==null;){if(B=Z[E2])return B;Z=jj(Z)}return G}Z=B,B=Z.parentNode}return null}function x4(Z){if(Z=Z[E2]||Z[l8]){var G=Z.tag;if(G===5||G===6||G===13||G===31||G===26||G===27||G===3)return Z}return null}function F4(Z){var G=Z.tag;if(G===5||G===26||G===27||G===6)return Z.stateNode;throw Error("getNodeFromInstance: Invalid argument.")}function E4(Z){var G=Z[uj];return G||(G=Z[uj]={hoistableStyles:new Map,hoistableScripts:new Map}),G}function Q4(Z){Z[P1]=!0}function M7(Z,G){U7(Z,G),U7(Z+"Capture",G)}function U7(Z,G){k9[Z]&&console.error("EventRegistry: More than one plugin attempted to publish the same registration name, `%s`.",Z),k9[Z]=G;var B=Z.toLowerCase();rJ[B]=Z,Z==="onDoubleClick"&&(rJ.ondblclick=Z);for(Z=0;Z<G.length;Z++)dj.add(G[Z])}function H7(Z,G){JU[G.type]||G.onChange||G.onInput||G.readOnly||G.disabled||G.value==null||(Z==="select"?console.error("You provided a `value` prop to a form field without an `onChange` handler. This will render a read-only field. If the field should be mutable use `defaultValue`. Otherwise, set `onChange`."):console.error("You provided a `value` prop to a form field without an `onChange` handler. This will render a read-only field. If the field should be mutable use `defaultValue`. Otherwise, set either `onChange` or `readOnly`.")),G.onChange||G.readOnly||G.disabled||G.checked==null||console.error("You provided a `checked` prop to a form field without an `onChange` handler. This will render a read-only field. If the field should be mutable use `defaultChecked`. Otherwise, set either `onChange` or `readOnly`.")}function f7(Z){if($6.call(cj,Z))return!0;if($6.call(pj,Z))return!1;if(qU.test(Z))return cj[Z]=!0;return pj[Z]=!0,console.error("Invalid attribute name: `%s`",Z),!1}function X7(Z,G,B){if(f7(G)){if(!Z.hasAttribute(G)){switch(typeof B){case"symbol":case"object":return B;case"function":return B;case"boolean":if(B===!1)return B}return B===void 0?void 0:null}if(Z=Z.getAttribute(G),Z===""&&B===!0)return!0;return s7(B,G),Z===""+B?B:Z}}function e7(Z,G,B){if(f7(G))if(B===null)Z.removeAttribute(G);else{switch(typeof B){case"undefined":case"function":case"symbol":Z.removeAttribute(G);return;case"boolean":var $=G.toLowerCase().slice(0,5);if($!=="data-"&&$!=="aria-"){Z.removeAttribute(G);return}}s7(B,G),Z.setAttribute(G,""+B)}}function kZ(Z,G,B){if(B===null)Z.removeAttribute(G);else{switch(typeof B){case"undefined":case"function":case"symbol":case"boolean":Z.removeAttribute(G);return}s7(B,G),Z.setAttribute(G,""+B)}}function dZ(Z,G,B,$){if($===null)Z.removeAttribute(B);else{switch(typeof $){case"undefined":case"function":case"symbol":case"boolean":Z.removeAttribute(B);return}s7($,B),Z.setAttributeNS(G,B,""+$)}}function yZ(Z){switch(typeof Z){case"bigint":case"boolean":case"number":case"string":case"undefined":return Z;case"object":return N4(Z),Z;default:return""}}function N2(Z){var G=Z.type;return(Z=Z.nodeName)&&Z.toLowerCase()==="input"&&(G==="checkbox"||G==="radio")}function t5(Z,G,B){var $=Object.getOwnPropertyDescriptor(Z.constructor.prototype,G);if(!Z.hasOwnProperty(G)&&typeof $<"u"&&typeof $.get==="function"&&typeof $.set==="function"){var{get:z,set:Q}=$;return Object.defineProperty(Z,G,{configurable:!0,get:function(){return z.call(this)},set:function(q){N4(q),B=""+q,Q.call(this,q)}}),Object.defineProperty(Z,G,{enumerable:$.enumerable}),{getValue:function(){return B},setValue:function(q){N4(q),B=""+q},stopTracking:function(){Z._valueTracker=null,delete Z[G]}}}}function P8(Z){if(!Z._valueTracker){var G=N2(Z)?"checked":"value";Z._valueTracker=t5(Z,G,""+Z[G])}}function wZ(Z){if(!Z)return!1;var G=Z._valueTracker;if(!G)return!0;var B=G.getValue(),$="";return Z&&($=N2(Z)?Z.checked?"true":"false":Z.value),Z=$,Z!==B?(G.setValue(Z),!0):!1}function G5(Z){if(Z=Z||(typeof document<"u"?document:void 0),typeof Z>"u")return null;try{return Z.activeElement||Z.body}catch(G){return Z.body}}function D2(Z){return Z.replace(HU,function(G){return"\\"+G.charCodeAt(0).toString(16)+" "})}function AB(Z,G){G.checked===void 0||G.defaultChecked===void 0||sj||(console.error("%s contains an input of type %s with both checked and defaultChecked props. Input elements must be either controlled or uncontrolled (specify either the checked prop, or the defaultChecked prop, but not both). Decide between using a controlled or uncontrolled input element and remove one of these props. More info: https://react.dev/link/controlled-components",eZ()||"A component",G.type),sj=!0),G.value===void 0||G.defaultValue===void 0||lj||(console.error("%s contains an input of type %s with both value and defaultValue props. Input elements must be either controlled or uncontrolled (specify either the value prop, or the defaultValue prop, but not both). Decide between using a controlled or uncontrolled input element and remove one of these props. More info: https://react.dev/link/controlled-components",eZ()||"A component",G.type),lj=!0)}function K7(Z,G,B,$,z,Q,q,X){if(Z.name="",q!=null&&typeof q!=="function"&&typeof q!=="symbol"&&typeof q!=="boolean"?(s7(q,"type"),Z.type=q):Z.removeAttribute("type"),G!=null)if(q==="number"){if(G===0&&Z.value===""||Z.value!=G)Z.value=""+yZ(G)}else Z.value!==""+yZ(G)&&(Z.value=""+yZ(G));else q!=="submit"&&q!=="reset"||Z.removeAttribute("value");G!=null?V9(Z,q,yZ(G)):B!=null?V9(Z,q,yZ(B)):$!=null&&Z.removeAttribute("value"),z==null&&Q!=null&&(Z.defaultChecked=!!Q),z!=null&&(Z.checked=z&&typeof z!=="function"&&typeof z!=="symbol"),X!=null&&typeof X!=="function"&&typeof X!=="symbol"&&typeof X!=="boolean"?(s7(X,"name"),Z.name=""+yZ(X)):Z.removeAttribute("name")}function b2(Z,G,B,$,z,Q,q,X){if(Q!=null&&typeof Q!=="function"&&typeof Q!=="symbol"&&typeof Q!=="boolean"&&(s7(Q,"type"),Z.type=Q),G!=null||B!=null){if(!(Q!=="submit"&&Q!=="reset"||G!==void 0&&G!==null)){P8(Z);return}B=B!=null?""+yZ(B):"",G=G!=null?""+yZ(G):B,X||G===Z.value||(Z.value=G),Z.defaultValue=G}$=$!=null?$:z,$=typeof $!=="function"&&typeof $!=="symbol"&&!!$,Z.checked=X?Z.checked:!!$,Z.defaultChecked=!!$,q!=null&&typeof q!=="function"&&typeof q!=="symbol"&&typeof q!=="boolean"&&(s7(q,"name"),Z.name=q),P8(Z)}function V9(Z,G,B){G==="number"&&G5(Z.ownerDocument)===Z||Z.defaultValue===""+B||(Z.defaultValue=""+B)}function XG(Z,G){G.value==null&&(typeof G.children==="object"&&G.children!==null?kJ.Children.forEach(G.children,function(B){B==null||typeof B==="string"||typeof B==="number"||typeof B==="bigint"||ij||(ij=!0,console.error("Cannot infer the option value of complex children. Pass a `value` prop or use a plain string as children to <option>."))}):G.dangerouslySetInnerHTML==null||oj||(oj=!0,console.error("Pass a `value` prop if you set dangerouslyInnerHTML so React knows which value should be selected."))),G.selected==null||aj||(console.error("Use the `defaultValue` or `value` props on <select> instead of setting `selected` on <option>."),aj=!0)}function K6(){var Z=eZ();return Z?`

Check the render method of \``+Z+"`.":""}function A8(Z,G,B,$){if(Z=Z.options,G){G={};for(var z=0;z<B.length;z++)G["$"+B[z]]=!0;for(B=0;B<Z.length;B++)z=G.hasOwnProperty("$"+Z[B].value),Z[B].selected!==z&&(Z[B].selected=z),z&&$&&(Z[B].defaultSelected=!0)}else{B=""+yZ(B),G=null;for(z=0;z<Z.length;z++){if(Z[z].value===B){Z[z].selected=!0,$&&(Z[z].defaultSelected=!0);return}G!==null||Z[z].disabled||(G=Z[z])}G!==null&&(G.selected=!0)}}function x0(Z,G){for(Z=0;Z<nj.length;Z++){var B=nj[Z];if(G[B]!=null){var $=j2(G[B]);G.multiple&&!$?console.error("The `%s` prop supplied to <select> must be an array if `multiple` is true.%s",B,K6()):!G.multiple&&$&&console.error("The `%s` prop supplied to <select> must be a scalar value if `multiple` is false.%s",B,K6())}}G.value===void 0||G.defaultValue===void 0||rj||(console.error("Select elements must be either controlled or uncontrolled (specify either the value prop, or the defaultValue prop, but not both). Decide between using a controlled or uncontrolled select element and remove one of these props. More info: https://react.dev/link/controlled-components"),rj=!0)}function CB(Z,G){G.value===void 0||G.defaultValue===void 0||tj||(console.error("%s contains a textarea with both value and defaultValue props. Textarea elements must be either controlled or uncontrolled (specify either the value prop, or the defaultValue prop, but not both). Decide between using a controlled or uncontrolled textarea and remove one of these props. More info: https://react.dev/link/controlled-components",eZ()||"A component"),tj=!0),G.children!=null&&G.value==null&&console.error("Use the `defaultValue` or `value` props instead of setting children on <textarea>.")}function TB(Z,G,B){if(G!=null&&(G=""+yZ(G),G!==Z.value&&(Z.value=G),B==null)){Z.defaultValue!==G&&(Z.defaultValue=G);return}Z.defaultValue=B!=null?""+yZ(B):""}function EB(Z,G,B,$){if(G==null){if($!=null){if(B!=null)throw Error("If you supply `defaultValue` on a <textarea>, do not pass children.");if(j2($)){if(1<$.length)throw Error("<textarea> can only have at most one child.");$=$[0]}B=$}B==null&&(B=""),G=B}B=yZ(G),Z.defaultValue=B,$=Z.textContent,$===B&&$!==""&&$!==null&&(Z.value=$),P8(Z)}function YG(Z,G){return Z.serverProps===void 0&&Z.serverTail.length===0&&Z.children.length===1&&3<Z.distanceFromLeaf&&Z.distanceFromLeaf>15-G?YG(Z.children[0],G):Z}function f2(Z){return"  "+"  ".repeat(Z)}function p6(Z){return"+ "+"  ".repeat(Z)}function Y5(Z){return"- "+"  ".repeat(Z)}function O9(Z){switch(Z.tag){case 26:case 27:case 5:return Z.type;case 16:return"Lazy";case 31:return"Activity";case 13:return"Suspense";case 19:return"SuspenseList";case 0:case 15:return Z=Z.type,Z.displayName||Z.name||null;case 11:return Z=Z.type.render,Z.displayName||Z.name||null;case 1:return Z=Z.type,Z.displayName||Z.name||null;default:return null}}function P2(Z,G){return ej.test(Z)?(Z=JSON.stringify(Z),Z.length>G-2?8>G?'{"..."}':"{"+Z.slice(0,G-7)+'..."}':"{"+Z+"}"):Z.length>G?5>G?'{"..."}':Z.slice(0,G-3)+"...":Z}function c6(Z,G,B){var $=120-2*B;if(G===null)return p6(B)+P2(Z,$)+`
`;if(typeof G==="string"){for(var z=0;z<G.length&&z<Z.length&&G.charCodeAt(z)===Z.charCodeAt(z);z++);return z>$-8&&10<z&&(Z="..."+Z.slice(z-8),G="..."+G.slice(z-8)),p6(B)+P2(Z,$)+`
`+Y5(B)+P2(G,$)+`
`}return f2(B)+P2(Z,$)+`
`}function jG(Z){return Object.prototype.toString.call(Z).replace(/^\[object (.*)\]$/,function(G,B){return B})}function e5(Z,G){switch(typeof Z){case"string":return Z=JSON.stringify(Z),Z.length>G?5>G?'"..."':Z.slice(0,G-4)+'..."':Z;case"object":if(Z===null)return"null";if(j2(Z))return"[...]";if(Z.$$typeof===E6)return(G=p4(Z.type))?"<"+G+">":"<...>";var B=jG(Z);if(B==="Object"){B="",G-=2;for(var $ in Z)if(Z.hasOwnProperty($)){var z=JSON.stringify($);if(z!=='"'+$+'"'&&($=z),G-=$.length-2,z=e5(Z[$],15>G?G:15),G-=z.length,0>G){B+=B===""?"...":", ...";break}B+=(B===""?"":",")+$+":"+z}return"{"+B+"}"}return B;case"function":return(G=Z.displayName||Z.name)?"function "+G:"function";default:return String(Z)}}function I5(Z,G){return typeof Z!=="string"||ej.test(Z)?"{"+e5(Z,G-2)+"}":Z.length>G-2?5>G?'"..."':'"'+Z.slice(0,G-5)+'..."':'"'+Z+'"'}function l6(Z,G,B){var $=120-B.length-Z.length,z=[],Q;for(Q in G)if(G.hasOwnProperty(Q)&&Q!=="children"){var q=I5(G[Q],120-B.length-Q.length-1);$-=Q.length+q.length+2,z.push(Q+"="+q)}return z.length===0?B+"<"+Z+`>
`:0<$?B+"<"+Z+" "+z.join(" ")+`>
`:B+"<"+Z+`
`+B+"  "+z.join(`
`+B+"  ")+`
`+B+`>
`}function j5(Z,G,B){var $="",z=k7({},G),Q;for(Q in Z)if(Z.hasOwnProperty(Q)){delete z[Q];var q=120-2*B-Q.length-2,X=e5(Z[Q],q);G.hasOwnProperty(Q)?(q=e5(G[Q],q),$+=p6(B)+Q+": "+X+`
`,$+=Y5(B)+Q+": "+q+`
`):$+=p6(B)+Q+": "+X+`
`}for(var j in z)z.hasOwnProperty(j)&&(Z=e5(z[j],120-2*B-j.length-2),$+=Y5(B)+j+": "+Z+`
`);return $}function S0(Z,G,B,$){var z="",Q=new Map;for(U in B)B.hasOwnProperty(U)&&Q.set(U.toLowerCase(),U);if(Q.size===1&&Q.has("children"))z+=l6(Z,G,f2($));else{for(var q in G)if(G.hasOwnProperty(q)&&q!=="children"){var X=120-2*($+1)-q.length-1,j=Q.get(q.toLowerCase());if(j!==void 0){Q.delete(q.toLowerCase());var U=G[q];j=B[j];var k=I5(U,X);X=I5(j,X),typeof U==="object"&&U!==null&&typeof j==="object"&&j!==null&&jG(U)==="Object"&&jG(j)==="Object"&&(2<Object.keys(U).length||2<Object.keys(j).length||-1<k.indexOf("...")||-1<X.indexOf("..."))?z+=f2($+1)+q+`={{
`+j5(U,j,$+2)+f2($+1)+`}}
`:(z+=p6($+1)+q+"="+k+`
`,z+=Y5($+1)+q+"="+X+`
`)}else z+=f2($+1)+q+"="+I5(G[q],X)+`
`}Q.forEach(function(y){if(y!=="children"){var P=120-2*($+1)-y.length-1;z+=Y5($+1)+y+"="+I5(B[y],P)+`
`}}),z=z===""?f2($)+"<"+Z+`>
`:f2($)+"<"+Z+`
`+z+f2($)+`>
`}if(Z=B.children,G=G.children,typeof Z==="string"||typeof Z==="number"||typeof Z==="bigint"){if(Q="",typeof G==="string"||typeof G==="number"||typeof G==="bigint")Q=""+G;z+=c6(Q,""+Z,$+1)}else if(typeof G==="string"||typeof G==="number"||typeof G==="bigint")z=Z==null?z+c6(""+G,null,$+1):z+c6(""+G,void 0,$+1);return z}function m2(Z,G){var B=O9(Z);if(B===null){B="";for(Z=Z.child;Z;)B+=m2(Z,G),Z=Z.sibling;return B}return f2(G)+"<"+B+`>
`}function v0(Z,G){var B=YG(Z,G);if(B!==Z&&(Z.children.length!==1||Z.children[0]!==B))return f2(G)+`...
`+v0(B,G+1);B="";var $=Z.fiber._debugInfo;if($)for(var z=0;z<$.length;z++){var Q=$[z].name;typeof Q==="string"&&(B+=f2(G)+"<"+Q+`>
`,G++)}if($="",z=Z.fiber.pendingProps,Z.fiber.tag===6)$=c6(z,Z.serverProps,G),G++;else if(Q=O9(Z.fiber),Q!==null)if(Z.serverProps===void 0){$=G;var q=120-2*$-Q.length-2,X="";for(U in z)if(z.hasOwnProperty(U)&&U!=="children"){var j=I5(z[U],15);if(q-=U.length+j.length+2,0>q){X+=" ...";break}X+=" "+U+"="+j}$=f2($)+"<"+Q+X+`>
`,G++}else Z.serverProps===null?($=l6(Q,z,p6(G)),G++):typeof Z.serverProps==="string"?console.error("Should not have matched a non HostText fiber to a Text node. This is a bug in React."):($=S0(Q,z,Z.serverProps,G),G++);var U="";z=Z.fiber.child;for(Q=0;z&&Q<Z.children.length;)q=Z.children[Q],q.fiber===z?(U+=v0(q,G),Q++):U+=m2(z,G),z=z.sibling;z&&0<Z.children.length&&(U+=f2(G)+`...
`),z=Z.serverTail,Z.serverProps===null&&G--;for(Z=0;Z<z.length;Z++)Q=z[Z],U=typeof Q==="string"?U+(Y5(G)+P2(Q,120-2*G)+`
`):U+l6(Q.type,Q.props,Y5(G));return B+$+U}function k0(Z){try{return`

`+v0(Z,0)}catch(G){return""}}function y0(Z,G,B){for(var $=G,z=null,Q=0;$;)$===Z&&(Q=0),z={fiber:$,children:z!==null?[z]:[],serverProps:$===G?B:$===Z?null:void 0,serverTail:[],distanceFromLeaf:Q},Q++,$=$.return;return z!==null?k0(z).replaceAll(/^[+-]/gm,">"):""}function nz(Z,G){var B=k7({},Z||GK),$={tag:G};if(ZK.indexOf(G)!==-1&&(B.aTagInScope=null,B.buttonTagInScope=null,B.nobrTagInScope=null),YU.indexOf(G)!==-1&&(B.pTagInButtonScope=null),XU.indexOf(G)!==-1&&G!=="address"&&G!=="div"&&G!=="p"&&(B.listItemTagAutoclosing=null,B.dlItemTagAutoclosing=null),B.current=$,G==="form"&&(B.formTag=$),G==="a"&&(B.aTagInScope=$),G==="button"&&(B.buttonTagInScope=$),G==="nobr"&&(B.nobrTagInScope=$),G==="p"&&(B.pTagInButtonScope=$),G==="li"&&(B.listItemTagAutoclosing=$),G==="dd"||G==="dt")B.dlItemTagAutoclosing=$;return G==="#document"||G==="html"?B.containerTagInScope=null:B.containerTagInScope||(B.containerTagInScope=$),Z!==null||G!=="#document"&&G!=="html"&&G!=="body"?B.implicitRootScope===!0&&(B.implicitRootScope=!1):B.implicitRootScope=!0,B}function KG(Z,G,B){switch(G){case"select":return Z==="hr"||Z==="option"||Z==="optgroup"||Z==="script"||Z==="template"||Z==="#text";case"optgroup":return Z==="option"||Z==="#text";case"option":return Z==="#text";case"tr":return Z==="th"||Z==="td"||Z==="style"||Z==="script"||Z==="template";case"tbody":case"thead":case"tfoot":return Z==="tr"||Z==="style"||Z==="script"||Z==="template";case"colgroup":return Z==="col"||Z==="template";case"table":return Z==="caption"||Z==="colgroup"||Z==="tbody"||Z==="tfoot"||Z==="thead"||Z==="style"||Z==="script"||Z==="template";case"head":return Z==="base"||Z==="basefont"||Z==="bgsound"||Z==="link"||Z==="meta"||Z==="title"||Z==="noscript"||Z==="noframes"||Z==="style"||Z==="script"||Z==="template";case"html":if(B)break;return Z==="head"||Z==="body"||Z==="frameset";case"frameset":return Z==="frame";case"#document":if(!B)return Z==="html"}switch(Z){case"h1":case"h2":case"h3":case"h4":case"h5":case"h6":return G!=="h1"&&G!=="h2"&&G!=="h3"&&G!=="h4"&&G!=="h5"&&G!=="h6";case"rp":case"rt":return jU.indexOf(G)===-1;case"caption":case"col":case"colgroup":case"frameset":case"frame":case"tbody":case"td":case"tfoot":case"th":case"thead":case"tr":return G==null;case"head":return B||G===null;case"html":return B&&G==="#document"||G===null;case"body":return B&&(G==="#document"||G==="html")||G===null}return!0}function vH(Z,G){switch(Z){case"address":case"article":case"aside":case"blockquote":case"center":case"details":case"dialog":case"dir":case"div":case"dl":case"fieldset":case"figcaption":case"figure":case"footer":case"header":case"hgroup":case"main":case"menu":case"nav":case"ol":case"p":case"section":case"summary":case"ul":case"pre":case"listing":case"table":case"hr":case"xmp":case"h1":case"h2":case"h3":case"h4":case"h5":case"h6":return G.pTagInButtonScope;case"form":return G.formTag||G.pTagInButtonScope;case"li":return G.listItemTagAutoclosing;case"dd":case"dt":return G.dlItemTagAutoclosing;case"button":return G.buttonTagInScope;case"a":return G.aTagInScope;case"nobr":return G.nobrTagInScope}return null}function tz(Z,G){for(;Z;){switch(Z.tag){case 5:case 26:case 27:if(Z.type===G)return Z}Z=Z.return}return null}function wB(Z,G){G=G||GK;var B=G.current;if(G=(B=KG(Z,B&&B.tag,G.implicitRootScope)?null:B)?null:vH(Z,G),G=B||G,!G)return!0;var $=G.tag;if(G=String(!!B)+"|"+Z+"|"+$,v$[G])return!1;v$[G]=!0;var z=(G=M5)?tz(G.return,$):null,Q=G!==null&&z!==null?y0(z,G,null):"",q="<"+Z+">";return B?(B="",$==="table"&&Z==="tr"&&(B+=" Add a <tbody>, <thead> or <tfoot> to your code to match the DOM tree generated by the browser."),console.error(`In HTML, %s cannot be a child of <%s>.%s
This will cause a hydration error.%s`,q,$,B,Q)):console.error(`In HTML, %s cannot be a descendant of <%s>.
This will cause a hydration error.%s`,q,$,Q),G&&(Z=G.return,z===null||Z===null||z===Z&&Z._debugOwner===G._debugOwner||M4(z,function(){console.error(`<%s> cannot contain a nested %s.
See this log for the ancestor stack trace.`,$,q)})),!1}function g0(Z,G,B){if(B||KG("#text",G,!1))return!0;if(B="#text|"+G,v$[B])return!1;v$[B]=!0;var $=(B=M5)?tz(B,G):null;return B=B!==null&&$!==null?y0($,B,B.tag!==6?{children:null}:null):"",/\S/.test(Z)?console.error(`In HTML, text nodes cannot be a child of <%s>.
This will cause a hydration error.%s`,G,B):console.error(`In HTML, whitespace text nodes cannot be a child of <%s>. Make sure you don't have any extra whitespace between tags on each line of your source code.
This will cause a hydration error.%s`,G,B),!1}function WG(Z,G){if(G){var B=Z.firstChild;if(B&&B===Z.lastChild&&B.nodeType===3){B.nodeValue=G;return}}Z.textContent=G}function kH(Z){return Z.replace(_U,function(G,B){return B.toUpperCase()})}function b0(Z,G,B){var $=G.indexOf("--")===0;$||(-1<G.indexOf("-")?cG.hasOwnProperty(G)&&cG[G]||(cG[G]=!0,console.error("Unsupported style property %s. Did you mean %s?",G,kH(G.replace(WU,"ms-")))):KU.test(G)?cG.hasOwnProperty(G)&&cG[G]||(cG[G]=!0,console.error("Unsupported vendor-prefixed style property %s. Did you mean %s?",G,G.charAt(0).toUpperCase()+G.slice(1))):!zK.test(B)||tJ.hasOwnProperty(B)&&tJ[B]||(tJ[B]=!0,console.error(`Style property values shouldn't contain a semicolon. Try "%s: %s" instead.`,G,B.replace(zK,""))),typeof B==="number"&&(isNaN(B)?QK||(QK=!0,console.error("`NaN` is an invalid value for the `%s` css style property.",G)):isFinite(B)||JK||(JK=!0,console.error("`Infinity` is an invalid value for the `%s` css style property.",G)))),B==null||typeof B==="boolean"||B===""?$?Z.setProperty(G,""):G==="float"?Z.cssFloat="":Z[G]="":$?Z.setProperty(G,B):typeof B!=="number"||B===0||qK.has(G)?G==="float"?Z.cssFloat=B:(M2(B,G),Z[G]=(""+B).trim()):Z[G]=B+"px"}function f0(Z,G,B){if(G!=null&&typeof G!=="object")throw Error("The `style` prop expects a mapping from style properties to values, not a string. For example, style={{marginRight: spacing + 'em'}} when using JSX.");if(G&&Object.freeze(G),Z=Z.style,B!=null){if(G){var $={};if(B){for(var z in B)if(B.hasOwnProperty(z)&&!G.hasOwnProperty(z))for(var Q=nJ[z]||[z],q=0;q<Q.length;q++)$[Q[q]]=z}for(var X in G)if(G.hasOwnProperty(X)&&(!B||B[X]!==G[X]))for(z=nJ[X]||[X],Q=0;Q<z.length;Q++)$[z[Q]]=X;X={};for(var j in G)for(z=nJ[j]||[j],Q=0;Q<z.length;Q++)X[z[Q]]=j;j={};for(var U in $)if(z=$[U],(Q=X[U])&&z!==Q&&(q=z+","+Q,!j[q])){j[q]=!0,q=console;var k=G[z];q.error.call(q,"%s a style property during rerender (%s) when a conflicting property is set (%s) can lead to styling bugs. To avoid this, don't mix shorthand and non-shorthand properties for the same value; instead, replace the shorthand with separate values.",k==null||typeof k==="boolean"||k===""?"Removing":"Updating",z,Q)}}for(var y in B)!B.hasOwnProperty(y)||G!=null&&G.hasOwnProperty(y)||(y.indexOf("--")===0?Z.setProperty(y,""):y==="float"?Z.cssFloat="":Z[y]="");for(var P in G)U=G[P],G.hasOwnProperty(P)&&B[P]!==U&&b0(Z,P,U)}else for($ in G)G.hasOwnProperty($)&&b0(Z,$,G[$])}function x5(Z){if(Z.indexOf("-")===-1)return!1;switch(Z){case"annotation-xml":case"color-profile":case"font-face":case"font-face-src":case"font-face-uri":case"font-face-format":case"font-face-name":case"missing-glyph":return!1;default:return!0}}function gZ(Z){return LU.get(Z)||Z}function C8(Z,G){if($6.call(sG,G)&&sG[G])return!0;if(VU.test(G)){if(Z="aria-"+G.slice(4).toLowerCase(),Z=HK.hasOwnProperty(Z)?Z:null,Z==null)return console.error("Invalid ARIA attribute `%s`. ARIA attributes follow the pattern aria-* and must be lowercase.",G),sG[G]=!0;if(G!==Z)return console.error("Invalid ARIA attribute `%s`. Did you mean `%s`?",G,Z),sG[G]=!0}if(UU.test(G)){if(Z=G.toLowerCase(),Z=HK.hasOwnProperty(Z)?Z:null,Z==null)return sG[G]=!0,!1;G!==Z&&(console.error("Unknown ARIA attribute `%s`. Did you mean `%s`?",G,Z),sG[G]=!0)}return!0}function S5(Z,G){var B=[],$;for($ in G)C8(Z,$)||B.push($);G=B.map(function(z){return"`"+z+"`"}).join(", "),B.length===1?console.error("Invalid aria prop %s on <%s> tag. For details, see https://react.dev/link/invalid-aria-props",G,Z):1<B.length&&console.error("Invalid aria props %s on <%s> tag. For details, see https://react.dev/link/invalid-aria-props",G,Z)}function L2(Z,G,B,$){if($6.call(c2,G)&&c2[G])return!0;var z=G.toLowerCase();if(z==="onfocusin"||z==="onfocusout")return console.error("React uses onFocus and onBlur instead of onFocusIn and onFocusOut. All React events are normalized to bubble, so onFocusIn and onFocusOut are not needed/supported by React."),c2[G]=!0;if(typeof B==="function"&&(Z==="form"&&G==="action"||Z==="input"&&G==="formAction"||Z==="button"&&G==="formAction"))return!0;if($!=null){if(Z=$.possibleRegistrationNames,$.registrationNameDependencies.hasOwnProperty(G))return!0;if($=Z.hasOwnProperty(z)?Z[z]:null,$!=null)return console.error("Invalid event handler property `%s`. Did you mean `%s`?",G,$),c2[G]=!0;if(YK.test(G))return console.error("Unknown event handler property `%s`. It will be ignored.",G),c2[G]=!0}else if(YK.test(G))return OU.test(G)&&console.error("Invalid event handler property `%s`. React events use the camelCase naming convention, for example `onClick`.",G),c2[G]=!0;if(FU.test(G)||RU.test(G))return!0;if(z==="innerhtml")return console.error("Directly setting property `innerHTML` is not permitted. For more information, lookup documentation on `dangerouslySetInnerHTML`."),c2[G]=!0;if(z==="aria")return console.error("The `aria` attribute is reserved for future use in React. Pass individual `aria-` attributes instead."),c2[G]=!0;if(z==="is"&&B!==null&&B!==void 0&&typeof B!=="string")return console.error("Received a `%s` for a string attribute `is`. If this is expected, cast the value to a string.",typeof B),c2[G]=!0;if(typeof B==="number"&&isNaN(B))return console.error("Received NaN for the `%s` attribute. If this is expected, cast the value to a string.",G),c2[G]=!0;if(y$.hasOwnProperty(z)){if(z=y$[z],z!==G)return console.error("Invalid DOM property `%s`. Did you mean `%s`?",G,z),c2[G]=!0}else if(G!==z)return console.error("React does not recognize the `%s` prop on a DOM element. If you intentionally want it to appear in the DOM as a custom attribute, spell it as lowercase `%s` instead. If you accidentally passed it from a parent component, remove it from the DOM element.",G,z),c2[G]=!0;switch(G){case"dangerouslySetInnerHTML":case"children":case"style":case"suppressContentEditableWarning":case"suppressHydrationWarning":case"defaultValue":case"defaultChecked":case"innerHTML":case"ref":return!0;case"innerText":case"textContent":return!0}switch(typeof B){case"boolean":switch(G){case"autoFocus":case"checked":case"multiple":case"muted":case"selected":case"contentEditable":case"spellCheck":case"draggable":case"value":case"autoReverse":case"externalResourcesRequired":case"focusable":case"preserveAlpha":case"allowFullScreen":case"async":case"autoPlay":case"controls":case"default":case"defer":case"disabled":case"disablePictureInPicture":case"disableRemotePlayback":case"formNoValidate":case"hidden":case"loop":case"noModule":case"noValidate":case"open":case"playsInline":case"readOnly":case"required":case"reversed":case"scoped":case"seamless":case"itemScope":case"capture":case"download":case"inert":return!0;default:if(z=G.toLowerCase().slice(0,5),z==="data-"||z==="aria-")return!0;return B?console.error('Received `%s` for a non-boolean attribute `%s`.\n\nIf you want to write it to the DOM, pass a string instead: %s="%s" or %s={value.toString()}.',B,G,G,B,G):console.error('Received `%s` for a non-boolean attribute `%s`.\n\nIf you want to write it to the DOM, pass a string instead: %s="%s" or %s={value.toString()}.\n\nIf you used to conditionally omit it with %s={condition && value}, pass %s={condition ? value : undefined} instead.',B,G,G,B,G,G,G),c2[G]=!0}case"function":case"symbol":return c2[G]=!0,!1;case"string":if(B==="false"||B==="true"){switch(G){case"checked":case"selected":case"multiple":case"muted":case"allowFullScreen":case"async":case"autoPlay":case"controls":case"default":case"defer":case"disabled":case"disablePictureInPicture":case"disableRemotePlayback":case"formNoValidate":case"hidden":case"loop":case"noModule":case"noValidate":case"open":case"playsInline":case"readOnly":case"required":case"reversed":case"scoped":case"seamless":case"itemScope":case"inert":break;default:return!0}console.error("Received the string `%s` for the boolean attribute `%s`. %s Did you mean %s={%s}?",B,G,B==="false"?"The browser will interpret it as a truthy value.":'Although this works, it will not work as expected if you pass the string "false".',G,B),c2[G]=!0}}return!0}function ez(Z,G,B){var $=[],z;for(z in G)L2(Z,z,G[z],B)||$.push(z);G=$.map(function(Q){return"`"+Q+"`"}).join(", "),$.length===1?console.error("Invalid value for prop %s on <%s> tag. Either remove it from the element, or pass a string or number value to keep it in the DOM. For details, see https://react.dev/link/attribute-behavior ",G,Z):1<$.length&&console.error("Invalid values for props %s on <%s> tag. Either remove them from the element, or pass a string or number value to keep them in the DOM. For details, see https://react.dev/link/attribute-behavior ",G,Z)}function F9(Z){return MU.test(""+Z)?"javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')":Z}function Z6(){}function T7(Z){return Z=Z.target||Z.srcElement||window,Z.correspondingUseElement&&(Z=Z.correspondingUseElement),Z.nodeType===3?Z.parentNode:Z}function IB(Z){var G=x4(Z);if(G&&(Z=G.stateNode)){var B=Z[p2]||null;Z:switch(Z=G.stateNode,G.type){case"input":if(K7(Z,B.value,B.defaultValue,B.defaultValue,B.checked,B.defaultChecked,B.type,B.name),G=B.name,B.type==="radio"&&G!=null){for(B=Z;B.parentNode;)B=B.parentNode;s7(G,"name"),B=B.querySelectorAll('input[name="'+D2(""+G)+'"][type="radio"]');for(G=0;G<B.length;G++){var $=B[G];if($!==Z&&$.form===Z.form){var z=$[p2]||null;if(!z)throw Error("ReactDOMInput: Mixing React and non-React radio inputs with the same `name` is not supported.");K7($,z.value,z.defaultValue,z.defaultValue,z.checked,z.defaultChecked,z.type,z.name)}}for(G=0;G<B.length;G++)$=B[G],$.form===Z.form&&wZ($)}break Z;case"textarea":TB(Z,B.value,B.defaultValue);break Z;case"select":G=B.value,G!=null&&A8(Z,!!B.multiple,G,!1)}}}function K5(Z,G,B){if(eJ)return Z(G,B);eJ=!0;try{var $=Z(G);return $}finally{if(eJ=!1,aG!==null||iG!==null){if(kG(),aG&&(G=aG,Z=iG,iG=aG=null,IB(G),Z))for(G=0;G<Z.length;G++)IB(Z[G])}}}function T8(Z,G){var B=Z.stateNode;if(B===null)return null;var $=B[p2]||null;if($===null)return null;B=$[G];Z:switch(G){case"onClick":case"onClickCapture":case"onDoubleClick":case"onDoubleClickCapture":case"onMouseDown":case"onMouseDownCapture":case"onMouseMove":case"onMouseMoveCapture":case"onMouseUp":case"onMouseUpCapture":case"onMouseEnter":($=!$.disabled)||(Z=Z.type,$=!(Z==="button"||Z==="input"||Z==="select"||Z==="textarea")),Z=!$;break Z;default:Z=!1}if(Z)return null;if(B&&typeof B!=="function")throw Error("Expected `"+G+"` listener to be a function, instead got a value of `"+typeof B+"` type.");return B}function m0(){if(g$)return g$;var Z,G=Gq,B=G.length,$,z="value"in s8?s8.value:s8.textContent,Q=z.length;for(Z=0;Z<B&&G[Z]===z[Z];Z++);var q=B-Z;for($=1;$<=q&&G[B-$]===z[Q-$];$++);return g$=z.slice(Z,1<$?1-$:void 0)}function R9(Z){var G=Z.keyCode;return"charCode"in Z?(Z=Z.charCode,Z===0&&G===13&&(Z=13)):Z=G,Z===10&&(Z=13),32<=Z||Z===13?Z:0}function _G(){return!0}function h0(){return!1}function pZ(Z){function G(B,$,z,Q,q){this._reactName=B,this._targetInst=z,this.type=$,this.nativeEvent=Q,this.target=q,this.currentTarget=null;for(var X in Z)Z.hasOwnProperty(X)&&(B=Z[X],this[X]=B?B(Q):Q[X]);return this.isDefaultPrevented=(Q.defaultPrevented!=null?Q.defaultPrevented:Q.returnValue===!1)?_G:h0,this.isPropagationStopped=h0,this}return k7(G.prototype,{preventDefault:function(){this.defaultPrevented=!0;var B=this.nativeEvent;B&&(B.preventDefault?B.preventDefault():typeof B.returnValue!=="unknown"&&(B.returnValue=!1),this.isDefaultPrevented=_G)},stopPropagation:function(){var B=this.nativeEvent;B&&(B.stopPropagation?B.stopPropagation():typeof B.cancelBubble!=="unknown"&&(B.cancelBubble=!0),this.isPropagationStopped=_G)},persist:function(){},isPersistent:_G}),G}function iZ(Z){var G=this.nativeEvent;return G.getModifierState?G.getModifierState(Z):(Z=kU[Z])?!!G[Z]:!1}function M9(){return iZ}function u0(Z,G){switch(Z){case"keyup":return sU.indexOf(G.keyCode)!==-1;case"keydown":return G.keyCode!==_K;case"keypress":case"mousedown":case"focusout":return!0;default:return!1}}function B5(Z){return Z=Z.detail,typeof Z==="object"&&"data"in Z?Z.data:null}function s6(Z,G){switch(Z){case"compositionend":return B5(G);case"keypress":if(G.which!==UK)return null;return OK=!0,VK;case"textInput":return Z=G.data,Z===VK&&OK?null:Z;default:return null}}function CZ(Z,G){if(oG)return Z==="compositionend"||!Qq&&u0(Z,G)?(Z=m0(),g$=Gq=s8=null,oG=!1,Z):null;switch(Z){case"paste":return null;case"keypress":if(!(G.ctrlKey||G.altKey||G.metaKey)||G.ctrlKey&&G.altKey){if(G.char&&1<G.char.length)return G.char;if(G.which)return String.fromCharCode(G.which)}return null;case"compositionend":return LK&&G.locale!=="ko"?null:G.data;default:return null}}function LG(Z){var G=Z&&Z.nodeName&&Z.nodeName.toLowerCase();return G==="input"?!!iU[Z.type]:G==="textarea"?!0:!1}function a6(Z){if(!k6)return!1;Z="on"+Z;var G=Z in document;return G||(G=document.createElement("div"),G.setAttribute(Z,"return;"),G=typeof G[Z]==="function"),G}function d0(Z,G,B,$){aG?iG?iG.push($):iG=[$]:aG=$,G=U$(G,"onChange"),0<G.length&&(B=new b$("onChange","change",null,B,$),Z.push({event:B,listeners:G}))}function E8(Z){lY(Z,0)}function N9(Z){var G=F4(Z);if(wZ(G))return Z}function UG(Z,G){if(Z==="change")return G}function p0(){I1&&(I1.detachEvent("onpropertychange",w8),x1=I1=null)}function w8(Z){if(Z.propertyName==="value"&&N9(x1)){var G=[];d0(G,x1,Z,T7(Z)),K5(E8,G)}}function xB(Z,G,B){Z==="focusin"?(p0(),I1=G,x1=B,I1.attachEvent("onpropertychange",w8)):Z==="focusout"&&p0()}function VG(Z){if(Z==="selectionchange"||Z==="keyup"||Z==="keydown")return N9(x1)}function D9(Z,G){if(Z==="click")return N9(G)}function OG(Z,G){if(Z==="input"||Z==="change")return N9(G)}function ZQ(Z,G){return Z===G&&(Z!==0||1/Z===1/G)||Z!==Z&&G!==G}function v5(Z,G){if(l2(Z,G))return!0;if(typeof Z!=="object"||Z===null||typeof G!=="object"||G===null)return!1;var B=Object.keys(Z),$=Object.keys(G);if(B.length!==$.length)return!1;for($=0;$<B.length;$++){var z=B[$];if(!$6.call(G,z)||!l2(Z[z],G[z]))return!1}return!0}function k5(Z){for(;Z&&Z.firstChild;)Z=Z.firstChild;return Z}function c0(Z,G){var B=k5(Z);Z=0;for(var $;B;){if(B.nodeType===3){if($=Z+B.textContent.length,Z<=G&&$>=G)return{node:B,offset:G-Z};Z=$}Z:{for(;B;){if(B.nextSibling){B=B.nextSibling;break Z}B=B.parentNode}B=void 0}B=k5(B)}}function i6(Z,G){return Z&&G?Z===G?!0:Z&&Z.nodeType===3?!1:G&&G.nodeType===3?i6(Z,G.parentNode):("contains"in Z)?Z.contains(G):Z.compareDocumentPosition?!!(Z.compareDocumentPosition(G)&16):!1:!1}function W5(Z){Z=Z!=null&&Z.ownerDocument!=null&&Z.ownerDocument.defaultView!=null?Z.ownerDocument.defaultView:window;for(var G=G5(Z.document);G instanceof Z.HTMLIFrameElement;){try{var B=typeof G.contentWindow.location.href==="string"}catch($){B=!1}if(B)Z=G.contentWindow;else break;G=G5(Z.document)}return G}function o6(Z){var G=Z&&Z.nodeName&&Z.nodeName.toLowerCase();return G&&(G==="input"&&(Z.type==="text"||Z.type==="search"||Z.type==="tel"||Z.type==="url"||Z.type==="password")||G==="textarea"||Z.contentEditable==="true")}function I8(Z,G,B){var $=B.window===B?B.document:B.nodeType===9?B:B.ownerDocument;qq||rG==null||rG!==G5($)||($=rG,("selectionStart"in $)&&o6($)?$={start:$.selectionStart,end:$.selectionEnd}:($=($.ownerDocument&&$.ownerDocument.defaultView||window).getSelection(),$={anchorNode:$.anchorNode,anchorOffset:$.anchorOffset,focusNode:$.focusNode,focusOffset:$.focusOffset}),S1&&v5(S1,$)||(S1=$,$=U$(Jq,"onSelect"),0<$.length&&(G=new b$("onSelect","select",null,G,B),Z.push({event:G,listeners:$}),G.target=rG)))}function y5(Z,G){var B={};return B[Z.toLowerCase()]=G.toLowerCase(),B["Webkit"+Z]="webkit"+G,B["Moz"+Z]="moz"+G,B}function W6(Z){if(Hq[Z])return Hq[Z];if(!nG[Z])return Z;var G=nG[Z],B;for(B in G)if(G.hasOwnProperty(B)&&B in RK)return Hq[Z]=G[B];return Z}function x2(Z,G){AK.set(Z,G),M7(G,[Z])}function SB(Z){for(var G=m$,B=0;B<Z.length;B++){var $=Z[B];if(typeof $==="object"&&$!==null)if(j2($)&&$.length===2&&typeof $[0]==="string"){if(G!==m$&&G!==Wq)return jq;G=Wq}else return jq;else{if(typeof $==="function"||typeof $==="string"&&50<$.length||G!==m$&&G!==Kq)return jq;G=Kq}}return G}function P9(Z,G,B,$){for(var z in Z)$6.call(Z,z)&&z[0]!=="_"&&g5(z,Z[z],G,B,$)}function g5(Z,G,B,$,z){switch(typeof G){case"object":if(G===null){G="null";break}else{if(G.$$typeof===E6){var Q=p4(G.type)||"…",q=G.key;G=G.props;var X=Object.keys(G),j=X.length;if(q==null&&j===0){G="<"+Q+" />";break}if(3>$||j===1&&X[0]==="children"&&q==null){G="<"+Q+" … />";break}B.push([z+"  ".repeat($)+Z,"<"+Q]),q!==null&&g5("key",q,B,$+1,z),Z=!1;for(var U in G)U==="children"?G.children!=null&&(!j2(G.children)||0<G.children.length)&&(Z=!0):$6.call(G,U)&&U[0]!=="_"&&g5(U,G[U],B,$+1,z);B.push(["",Z?">…</"+Q+">":"/>"]);return}if(Q=Object.prototype.toString.call(G),Q=Q.slice(8,Q.length-1),Q==="Array"){if(U=SB(G),U===Kq||U===m$){G=JSON.stringify(G);break}else if(U===Wq){B.push([z+"  ".repeat($)+Z,""]);for(Z=0;Z<G.length;Z++)Q=G[Z],g5(Q[0],Q[1],B,$+1,z);return}}if(Q==="Promise"){if(G.status==="fulfilled"){if(Q=B.length,g5(Z,G.value,B,$,z),B.length>Q){B=B[Q],B[1]="Promise<"+(B[1]||"Object")+">";return}}else if(G.status==="rejected"&&(Q=B.length,g5(Z,G.reason,B,$,z),B.length>Q)){B=B[Q],B[1]="Rejected Promise<"+B[1]+">";return}B.push(["  ".repeat($)+Z,"Promise"]);return}Q==="Object"&&(U=Object.getPrototypeOf(G))&&typeof U.constructor==="function"&&(Q=U.constructor.name),B.push([z+"  ".repeat($)+Z,Q==="Object"?3>$?"":"…":Q]),3>$&&P9(G,B,$+1,z);return}case"function":G=G.name===""?"() => {}":G.name+"() {}";break;case"string":G=G===GV?"…":JSON.stringify(G);break;case"undefined":G="undefined";break;case"boolean":G=G?"true":"false";break;default:G=String(G)}B.push([z+"  ".repeat($)+Z,G])}function l0(Z,G,B,$){var z=!0;for(q in Z)q in G||(B.push([h$+"  ".repeat($)+q,"…"]),z=!1);for(var Q in G)if(Q in Z){var q=Z[Q],X=G[Q];if(q!==X){if($===0&&Q==="children")z="  ".repeat($)+Q,B.push([h$+z,"…"],[u$+z,"…"]);else{if(!(3<=$)){if(typeof q==="object"&&typeof X==="object"&&q!==null&&X!==null&&q.$$typeof===X.$$typeof)if(X.$$typeof===E6){if(q.type===X.type&&q.key===X.key){q=p4(X.type)||"…",z="  ".repeat($)+Q,q="<"+q+" … />",B.push([h$+z,q],[u$+z,q]),z=!1;continue}}else{var j=Object.prototype.toString.call(q),U=Object.prototype.toString.call(X);if(j===U&&(U==="[object Object]"||U==="[object Array]")){j=[EK+"  ".repeat($)+Q,U==="[object Array]"?"Array":""],B.push(j),U=B.length,l0(q,X,B,$+1)?U===B.length&&(j[1]="Referentially unequal but deeply equal objects. Consider memoization."):z=!1;continue}}else if(typeof q==="function"&&typeof X==="function"&&q.name===X.name&&q.length===X.length&&(j=Function.prototype.toString.call(q),U=Function.prototype.toString.call(X),j===U)){q=X.name===""?"() => {}":X.name+"() {}",B.push([EK+"  ".repeat($)+Q,q+" Referentially unequal function closure. Consider memoization."]);continue}}g5(Q,q,B,$,h$),g5(Q,X,B,$,u$)}z=!1}}else B.push([u$+"  ".repeat($)+Q,"…"]),z=!1;return z}function S2(Z){m7=Z&63?"Blocking":Z&64?"Gesture":Z&4194176?"Transition":Z&62914560?"Suspense":Z&2080374784?"Idle":"Other"}function v2(Z,G,B,$){MZ&&(i8.start=G,i8.end=B,H8.color="warning",H8.tooltipText=$,H8.properties=null,(Z=Z._debugTask)?Z.run(performance.measure.bind(performance,$,i8)):performance.measure($,i8))}function B7(Z,G,B){v2(Z,G,B,"Reconnect")}function x8(Z,G,B,$,z){var Q=Y4(Z);if(Q!==null&&MZ){var{alternate:q,actualDuration:X}=Z;if(q===null||q.child!==Z.child)for(var j=Z.child;j!==null;j=j.sibling)X-=j.actualDuration;$=0.5>X?$?"tertiary-light":"primary-light":10>X?$?"tertiary":"primary":100>X?$?"tertiary-dark":"primary-dark":"error";var U=Z.memoizedProps;X=Z._debugTask,U!==null&&q!==null&&q.memoizedProps!==U?(j=[BV],U=l0(q.memoizedProps,U,j,0),1<j.length&&(U&&!a8&&(q.lanes&z)===0&&100<Z.actualDuration?(a8=!0,j[0]=$V,H8.color="warning",H8.tooltipText=wK):(H8.color=$,H8.tooltipText=Q),H8.properties=j,i8.start=G,i8.end=B,X!=null?X.run(performance.measure.bind(performance,"​"+Q,i8)):performance.measure("​"+Q,i8))):X!=null?X.run(console.timeStamp.bind(console,Q,G,B,h5,void 0,$)):console.timeStamp(Q,G,B,h5,void 0,$)}}function FG(Z,G,B,$){if(MZ){var z=Y4(Z);if(z!==null){for(var Q=null,q=[],X=0;X<$.length;X++){var j=$[X];Q==null&&j.source!==null&&(Q=j.source._debugTask),j=j.value,q.push(["Error",typeof j==="object"&&j!==null&&typeof j.message==="string"?String(j.message):String(j)])}Z.key!==null&&g5("key",Z.key,q,0,""),Z.memoizedProps!==null&&P9(Z.memoizedProps,q,0,""),Q==null&&(Q=Z._debugTask),Z={start:G,end:B,detail:{devtools:{color:"error",track:h5,tooltipText:Z.tag===13?"Hydration failed":"Error boundary caught an error",properties:q}}},Q?Q.run(performance.measure.bind(performance,"​"+z,Z)):performance.measure("​"+z,Z)}}}function b5(Z,G,B,$,z){if(z!==null){if(MZ){var Q=Y4(Z);if(Q!==null){$=[];for(var q=0;q<z.length;q++){var X=z[q].value;$.push(["Error",typeof X==="object"&&X!==null&&typeof X.message==="string"?String(X.message):String(X)])}Z.key!==null&&g5("key",Z.key,$,0,""),Z.memoizedProps!==null&&P9(Z.memoizedProps,$,0,""),G={start:G,end:B,detail:{devtools:{color:"error",track:h5,tooltipText:"A lifecycle or effect errored",properties:$}}},(Z=Z._debugTask)?Z.run(performance.measure.bind(performance,"​"+Q,G)):performance.measure("​"+Q,G)}}}else Q=Y4(Z),Q!==null&&MZ&&(z=1>$?"secondary-light":100>$?"secondary":500>$?"secondary-dark":"error",(Z=Z._debugTask)?Z.run(console.timeStamp.bind(console,Q,G,B,h5,void 0,z)):console.timeStamp(Q,G,B,h5,void 0,z))}function s0(Z,G,B,$){if(MZ&&!(G<=Z)){var z=(B&738197653)===B?"tertiary-dark":"primary-dark";B=(B&536870912)===B?"Prepared":(B&201326741)===B?"Hydrated":"Render",$?$.run(console.timeStamp.bind(console,B,Z,G,m7,y7,z)):console.timeStamp(B,Z,G,m7,y7,z)}}function r6(Z,G,B,$){!MZ||G<=Z||(B=(B&738197653)===B?"tertiary-dark":"primary-dark",$?$.run(console.timeStamp.bind(console,"Prewarm",Z,G,m7,y7,B)):console.timeStamp("Prewarm",Z,G,m7,y7,B))}function A9(Z,G,B,$){!MZ||G<=Z||(B=(B&738197653)===B?"tertiary-dark":"primary-dark",$?$.run(console.timeStamp.bind(console,"Suspended",Z,G,m7,y7,B)):console.timeStamp("Suspended",Z,G,m7,y7,B))}function vB(Z,G,B,$,z,Q){if(MZ&&!(G<=Z)){B=[];for(var q=0;q<$.length;q++){var X=$[q].value;B.push(["Recoverable Error",typeof X==="object"&&X!==null&&typeof X.message==="string"?String(X.message):String(X)])}Z={start:Z,end:G,detail:{devtools:{color:"primary-dark",track:m7,trackGroup:y7,tooltipText:z?"Hydration Failed":"Recovered after Error",properties:B}}},Q?Q.run(performance.measure.bind(performance,"Recovered",Z)):performance.measure("Recovered",Z)}}function RG(Z,G,B,$){!MZ||G<=Z||($?$.run(console.timeStamp.bind(console,"Errored",Z,G,m7,y7,"error")):console.timeStamp("Errored",Z,G,m7,y7,"error"))}function MG(Z,G,B,$){!MZ||G<=Z||($?$.run(console.timeStamp.bind(console,B,Z,G,m7,y7,"secondary-light")):console.timeStamp(B,Z,G,m7,y7,"secondary-light"))}function NG(Z,G,B,$,z){if(MZ&&!(G<=Z)){for(var Q=[],q=0;q<B.length;q++){var X=B[q].value;Q.push(["Error",typeof X==="object"&&X!==null&&typeof X.message==="string"?String(X.message):String(X)])}Z={start:Z,end:G,detail:{devtools:{color:"error",track:m7,trackGroup:y7,tooltipText:$?"Remaining Effects Errored":"Commit Errored",properties:Q}}},z?z.run(performance.measure.bind(performance,"Errored",Z)):performance.measure("Errored",Z)}}function S8(Z,G,B){!MZ||G<=Z||(B?B.run(console.timeStamp.bind(console,"Animating",Z,G,m7,y7,"secondary-dark")):console.timeStamp("Animating",Z,G,m7,y7,"secondary-dark"))}function n6(){for(var Z=tG,G=_q=tG=0;G<Z;){var B=u5[G];u5[G++]=null;var $=u5[G];u5[G++]=null;var z=u5[G];u5[G++]=null;var Q=u5[G];if(u5[G++]=null,$!==null&&z!==null){var q=$.pending;q===null?z.next=z:(z.next=q.next,q.next=z),$.pending=z}Q!==0&&DG(B,z,Q)}}function h2(Z,G,B,$){u5[tG++]=Z,u5[tG++]=G,u5[tG++]=B,u5[tG++]=$,_q|=$,Z.lanes|=$,Z=Z.alternate,Z!==null&&(Z.lanes|=$)}function a0(Z,G,B,$){return h2(Z,G,B,$),t6(Z)}function Z2(Z,G){return h2(Z,null,null,G),t6(Z)}function DG(Z,G,B){Z.lanes|=B;var $=Z.alternate;$!==null&&($.lanes|=B);for(var z=!1,Q=Z.return;Q!==null;)Q.childLanes|=B,$=Q.alternate,$!==null&&($.childLanes|=B),Q.tag===22&&(Z=Q.stateNode,Z===null||Z._visibility&v1||(z=!0)),Z=Q,Q=Q.return;return Z.tag===3?(Q=Z.stateNode,z&&G!==null&&(z=31-d2(B),Z=Q.hiddenUpdates,$=Z[z],$===null?Z[z]=[G]:$.push(G),G.lane=B|536870912),Q):null}function t6(Z){if(JB>OV)throw r9=JB=0,qB=aq=null,Error("Maximum update depth exceeded. This can happen when a component repeatedly calls setState inside componentWillUpdate or componentDidUpdate. React limits the number of nested updates to prevent infinite loops.");r9>FV&&(r9=0,qB=null,console.error("Maximum update depth exceeded. This can happen when a component calls setState inside useEffect, but useEffect either doesn't have a dependency array, or one of the dependencies changes on every render.")),Z.alternate===null&&(Z.flags&4098)!==0&&fY(Z);for(var G=Z,B=G.return;B!==null;)G.alternate===null&&(G.flags&4098)!==0&&fY(Z),G=B,B=G.return;return G.tag===3?G.stateNode:null}function e6(Z){if(d5===null)return Z;var G=d5(Z);return G===void 0?Z:G.current}function i0(Z){if(d5===null)return Z;var G=d5(Z);return G===void 0?Z!==null&&Z!==void 0&&typeof Z.render==="function"&&(G=e6(Z.render),Z.render!==G)?(G={$$typeof:M1,render:G},Z.displayName!==void 0&&(G.displayName=Z.displayName),G):Z:G.current}function _6(Z,G){if(d5===null)return!1;var B=Z.elementType;G=G.type;var $=!1,z=typeof G==="object"&&G!==null?G.$$typeof:null;switch(Z.tag){case 1:typeof G==="function"&&($=!0);break;case 0:typeof G==="function"?$=!0:z===R5&&($=!0);break;case 11:z===M1?$=!0:z===R5&&($=!0);break;case 14:case 15:z===T$?$=!0:z===R5&&($=!0);break;default:return!1}return $&&(Z=d5(B),Z!==void 0&&Z===d5(G))?!0:!1}function PG(Z){d5!==null&&typeof WeakSet==="function"&&(eG===null&&(eG=new WeakSet),eG.add(Z))}function AG(Z,G,B){do{var $=Z,z=$.alternate,Q=$.child,q=$.sibling,X=$.tag;$=$.type;var j=null;switch(X){case 0:case 15:case 1:j=$;break;case 11:j=$.render}if(d5===null)throw Error("Expected resolveFamily to be set during hot reload.");var U=!1;if($=!1,j!==null&&(j=d5(j),j!==void 0&&(B.has(j)?$=!0:G.has(j)&&(X===1?$=!0:U=!0))),eG!==null&&(eG.has(Z)||z!==null&&eG.has(z))&&($=!0),$&&(Z._debugNeedsRemount=!0),$||U)z=Z2(Z,2),z!==null&&bZ(z,Z,2);if(Q===null||$||AG(Q,G,B),q===null)break;Z=q}while(1)}function GQ(Z,G,B,$){this.tag=Z,this.key=B,this.sibling=this.child=this.return=this.stateNode=this.type=this.elementType=null,this.index=0,this.refCleanup=this.ref=null,this.pendingProps=G,this.dependencies=this.memoizedState=this.updateQueue=this.memoizedProps=null,this.mode=$,this.subtreeFlags=this.flags=0,this.deletions=null,this.childLanes=this.lanes=0,this.alternate=null,this.actualDuration=-0,this.actualStartTime=-1.1,this.treeBaseDuration=this.selfBaseDuration=-0,this._debugTask=this._debugStack=this._debugOwner=this._debugInfo=null,this._debugNeedsRemount=!1,this._debugHookTypes=null,IK||typeof Object.preventExtensions!=="function"||Object.preventExtensions(this)}function Z8(Z){return Z=Z.prototype,!(!Z||!Z.isReactComponent)}function k2(Z,G){var B=Z.alternate;switch(B===null?(B=R(Z.tag,G,Z.key,Z.mode),B.elementType=Z.elementType,B.type=Z.type,B.stateNode=Z.stateNode,B._debugOwner=Z._debugOwner,B._debugStack=Z._debugStack,B._debugTask=Z._debugTask,B._debugHookTypes=Z._debugHookTypes,B.alternate=Z,Z.alternate=B):(B.pendingProps=G,B.type=Z.type,B.flags=0,B.subtreeFlags=0,B.deletions=null,B.actualDuration=-0,B.actualStartTime=-1.1),B.flags=Z.flags&65011712,B.childLanes=Z.childLanes,B.lanes=Z.lanes,B.child=Z.child,B.memoizedProps=Z.memoizedProps,B.memoizedState=Z.memoizedState,B.updateQueue=Z.updateQueue,G=Z.dependencies,B.dependencies=G===null?null:{lanes:G.lanes,firstContext:G.firstContext,_debugThenableState:G._debugThenableState},B.sibling=Z.sibling,B.index=Z.index,B.ref=Z.ref,B.refCleanup=Z.refCleanup,B.selfBaseDuration=Z.selfBaseDuration,B.treeBaseDuration=Z.treeBaseDuration,B._debugInfo=Z._debugInfo,B._debugNeedsRemount=Z._debugNeedsRemount,B.tag){case 0:case 15:B.type=e6(Z.type);break;case 1:B.type=e6(Z.type);break;case 11:B.type=i0(Z.type)}return B}function kB(Z,G){Z.flags&=65011714;var B=Z.alternate;return B===null?(Z.childLanes=0,Z.lanes=G,Z.child=null,Z.subtreeFlags=0,Z.memoizedProps=null,Z.memoizedState=null,Z.updateQueue=null,Z.dependencies=null,Z.stateNode=null,Z.selfBaseDuration=0,Z.treeBaseDuration=0):(Z.childLanes=B.childLanes,Z.lanes=B.lanes,Z.child=B.child,Z.subtreeFlags=0,Z.deletions=null,Z.memoizedProps=B.memoizedProps,Z.memoizedState=B.memoizedState,Z.updateQueue=B.updateQueue,Z.type=B.type,G=B.dependencies,Z.dependencies=G===null?null:{lanes:G.lanes,firstContext:G.firstContext,_debugThenableState:G._debugThenableState},Z.selfBaseDuration=B.selfBaseDuration,Z.treeBaseDuration=B.treeBaseDuration),Z}function CG(Z,G,B,$,z,Q){var q=0,X=Z;if(typeof Z==="function")Z8(Z)&&(q=1),X=e6(X);else if(typeof Z==="string")q=O4(),q=kL(Z,B,q)?26:Z==="html"||Z==="head"||Z==="body"?27:5;else Z:switch(Z){case mJ:return G=R(31,B,G,z),G.elementType=mJ,G.lanes=Q,G;case uG:return F(B.children,z,Q,G);case C$:q=8,z|=g2,z|=Q6;break;case yJ:return Z=B,$=z,typeof Z.id!=="string"&&console.error('Profiler must specify an "id" of type `string` as a prop. Received the type `%s` instead.',typeof Z.id),G=R(12,Z,G,$|E7),G.elementType=yJ,G.lanes=Q,G.stateNode={effectDuration:0,passiveEffectDuration:0},G;case bJ:return G=R(13,B,G,z),G.elementType=bJ,G.lanes=Q,G;case fJ:return G=R(19,B,G,z),G.elementType=fJ,G.lanes=Q,G;default:if(typeof Z==="object"&&Z!==null)switch(Z.$$typeof){case w6:q=10;break Z;case gJ:q=9;break Z;case M1:q=11,X=i0(X);break Z;case T$:q=14;break Z;case R5:q=16,X=null;break Z}if(X="",Z===void 0||typeof Z==="object"&&Z!==null&&Object.keys(Z).length===0)X+=" You likely forgot to export your component from the file it's defined in, or you might have mixed up default and named imports.";Z===null?B="null":j2(Z)?B="array":Z!==void 0&&Z.$$typeof===E6?(B="<"+(p4(Z.type)||"Unknown")+" />",X=" Did you accidentally export a JSX literal instead of a component?"):B=typeof Z,(q=$?N7($):null)&&(X+=`

Check the render method of \``+q+"`."),q=29,B=Error("Element type is invalid: expected a string (for built-in components) or a class/function (for composite components) but got: "+(B+"."+X)),X=null}return G=R(q,B,G,z),G.elementType=Z,G.type=X,G.lanes=Q,G._debugOwner=$,G}function C9(Z,G,B){return G=CG(Z.type,Z.key,Z.props,Z._owner,G,B),G._debugOwner=Z._owner,G._debugStack=Z._debugStack,G._debugTask=Z._debugTask,G}function F(Z,G,B,$){return Z=R(7,Z,$,G),Z.lanes=B,Z}function N(Z,G,B){return Z=R(6,Z,null,G),Z.lanes=B,Z}function I(Z){var G=R(18,null,null,_7);return G.stateNode=Z,G}function w(Z,G,B){return G=R(4,Z.children!==null?Z.children:[],Z.key,G),G.lanes=B,G.stateNode={containerInfo:Z.containerInfo,pendingChildren:null,implementation:Z.implementation},G}function v(Z,G){if(typeof Z==="object"&&Z!==null){var B=Lq.get(Z);if(B!==void 0)return B;return G={value:Z,source:G,stack:u7(G)},Lq.set(Z,G),G}return{value:Z,source:G,stack:u7(G)}}function i(Z,G){$7(),Z0[G0++]=k1,Z0[G0++]=d$,d$=Z,k1=G}function V4(Z,G,B){$7(),p5[c5++]=Y8,p5[c5++]=j8,p5[c5++]=g9,g9=Z;var $=Y8;Z=j8;var z=32-d2($)-1;$&=~(1<<z),B+=1;var Q=32-d2(G)+z;if(30<Q){var q=z-z%5;Q=($&(1<<q)-1).toString(32),$>>=q,z-=q,Y8=1<<32-d2(G)+z|B<<z|$,j8=Q+Z}else Y8=1<<Q|B<<z|$,j8=Z}function P4(Z){$7(),Z.return!==null&&(i(Z,1),V4(Z,1,0))}function g4(Z){for(;Z===d$;)d$=Z0[--G0],Z0[G0]=null,k1=Z0[--G0],Z0[G0]=null;for(;Z===g9;)g9=p5[--c5],p5[c5]=null,j8=p5[--c5],p5[c5]=null,Y8=p5[--c5],p5[c5]=null}function s4(){return $7(),g9!==null?{id:Y8,overflow:j8}:null}function r4(Z,G){$7(),p5[c5++]=Y8,p5[c5++]=j8,p5[c5++]=g9,Y8=G.id,j8=G.overflow,g9=Z}function $7(){d7||console.error("Expected to be hydrating. This is a bug in React. Please file an issue.")}function D7(Z,G){if(Z.return===null){if(D5===null)D5={fiber:Z,children:[],serverProps:void 0,serverTail:[],distanceFromLeaf:G};else{if(D5.fiber!==Z)throw Error("Saw multiple hydration diff roots in a pass. This is a bug in React.");D5.distanceFromLeaf>G&&(D5.distanceFromLeaf=G)}return D5}var B=D7(Z.return,G+1).children;if(0<B.length&&B[B.length-1].fiber===Z)return B=B[B.length-1],B.distanceFromLeaf>G&&(B.distanceFromLeaf=G),B;return G={fiber:Z,children:[],serverProps:void 0,serverTail:[],distanceFromLeaf:G},B.push(G),G}function Z7(){d7&&console.error("We should not be hydrating here. This is a bug in React. Please file a bug.")}function k4(Z,G){y6||(Z=D7(Z,0),Z.serverProps=null,G!==null&&(G=Xj(G),Z.serverTail.push(G)))}function zZ(Z){var G=1<arguments.length&&arguments[1]!==void 0?arguments[1]:!1,B="",$=D5;throw $!==null&&(D5=null,B=k0($)),L7(v(Error("Hydration failed because the server rendered "+(G?"text":"HTML")+` didn't match the client. As a result this tree will be regenerated on the client. This can happen if a SSR-ed Client Component used:

- A server/client branch \`if (typeof window !== 'undefined')\`.
- Variable input such as \`Date.now()\` or \`Math.random()\` which changes each time it's called.
- Date formatting in a user's locale which doesn't match the server.
- External changing data without sending a snapshot of it along with the HTML.
- Invalid HTML tag nesting.

It can also happen if the client has a browser extension installed which messes with the HTML before React loaded.

https://react.dev/link/hydration-mismatch`+B),Z)),Uq}function ZZ(Z){var{stateNode:G,type:B,memoizedProps:$}=Z;switch(G[E2]=Z,G[p2]=$,UJ(B,$),B){case"dialog":c7("cancel",G),c7("close",G);break;case"iframe":case"object":case"embed":c7("load",G);break;case"video":case"audio":for(B=0;B<HB.length;B++)c7(HB[B],G);break;case"source":c7("error",G);break;case"img":case"image":case"link":c7("error",G),c7("load",G);break;case"details":c7("toggle",G);break;case"input":H7("input",$),c7("invalid",G),AB(G,$),b2(G,$.value,$.defaultValue,$.checked,$.defaultChecked,$.type,$.name,!0);break;case"option":XG(G,$);break;case"select":H7("select",$),c7("invalid",G),x0(G,$);break;case"textarea":H7("textarea",$),c7("invalid",G),CB(G,$),EB(G,$.value,$.defaultValue,$.children)}B=$.children,typeof B!=="string"&&typeof B!=="number"&&typeof B!=="bigint"||G.textContent===""+B||$.suppressHydrationWarning===!0||oY(G.textContent,B)?($.popover!=null&&(c7("beforetoggle",G),c7("toggle",G)),$.onScroll!=null&&c7("scroll",G),$.onScrollEnd!=null&&c7("scrollend",G),$.onClick!=null&&(G.onclick=Z6),G=!0):G=!1,G||zZ(Z,!0)}function cZ(Z){for(w2=Z.return;w2;)switch(w2.tag){case 5:case 31:case 13:l5=!1;return;case 27:case 3:l5=!0;return;default:w2=w2.return}}function a7(Z){if(Z!==w2)return!1;if(!d7)return cZ(Z),d7=!0,!1;var G=Z.tag,B;if(B=G!==3&&G!==27){if(B=G===5)B=Z.type,B=!(B!=="form"&&B!=="button")||MJ(Z.type,Z.memoizedProps);B=!B}if(B&&NZ){for(B=NZ;B;){var $=D7(Z,0),z=Xj(B);$.serverTail.push(z),B=z.type==="Suspense"?AJ(B):F5(B.nextSibling)}zZ(Z)}if(cZ(Z),G===13){if(Z=Z.memoizedState,Z=Z!==null?Z.dehydrated:null,!Z)throw Error("Expected to have a hydrated suspense instance. This error is likely caused by a bug in React. Please file an issue.");NZ=AJ(Z)}else if(G===31){if(Z=Z.memoizedState,Z=Z!==null?Z.dehydrated:null,!Z)throw Error("Expected to have a hydrated suspense instance. This error is likely caused by a bug in React. Please file an issue.");NZ=AJ(Z)}else G===27?(G=NZ,u8(Z.type)?(Z=QH,QH=null,NZ=Z):NZ=G):NZ=w2?F5(Z.stateNode.nextSibling):null;return!0}function HZ(){NZ=w2=null,y6=d7=!1}function Y7(){var Z=r8;return Z!==null&&(o2===null?o2=Z:o2.push.apply(o2,Z),r8=null),Z}function L7(Z){r8===null?r8=[Z]:r8.push(Z)}function LZ(){var Z=D5;if(Z!==null){D5=null;for(var G=k0(Z);0<Z.children.length;)Z=Z.children[0];M4(Z.fiber,function(){console.error(`A tree hydrated but some attributes of the server rendered HTML didn't match the client properties. This won't be patched up. This can happen if a SSR-ed Client Component used:

- A server/client branch \`if (typeof window !== 'undefined')\`.
- Variable input such as \`Date.now()\` or \`Math.random()\` which changes each time it's called.
- Date formatting in a user's locale which doesn't match the server.
- External changing data without sending a snapshot of it along with the HTML.
- Invalid HTML tag nesting.

It can also happen if the client has a browser extension installed which messes with the HTML before React loaded.

%s%s`,"https://react.dev/link/hydration-mismatch",G)})}}function UZ(){B0=p$=null,$0=!1}function G2(Z,G,B){b4(Vq,G._currentValue,Z),G._currentValue=B,b4(Oq,G._currentRenderer,Z),G._currentRenderer!==void 0&&G._currentRenderer!==null&&G._currentRenderer!==SK&&console.error("Detected multiple renderers concurrently rendering the same context provider. This is currently unsupported."),G._currentRenderer=SK}function lZ(Z,G){Z._currentValue=Vq.current;var B=Oq.current;d4(Oq,G),Z._currentRenderer=B,d4(Vq,G)}function oZ(Z,G,B){for(;Z!==null;){var $=Z.alternate;if((Z.childLanes&G)!==G?(Z.childLanes|=G,$!==null&&($.childLanes|=G)):$!==null&&($.childLanes&G)!==G&&($.childLanes|=G),Z===B)break;Z=Z.return}Z!==B&&console.error("Expected to find the propagation root when scheduling context work. This error is likely caused by a bug in React. Please file an issue.")}function G8(Z,G,B,$){var z=Z.child;z!==null&&(z.return=Z);for(;z!==null;){var Q=z.dependencies;if(Q!==null){var q=z.child;Q=Q.firstContext;Z:for(;Q!==null;){var X=Q;Q=z;for(var j=0;j<G.length;j++)if(X.context===G[j]){Q.lanes|=B,X=Q.alternate,X!==null&&(X.lanes|=B),oZ(Q.return,B,Z),$||(q=null);break Z}Q=X.next}}else if(z.tag===18){if(q=z.return,q===null)throw Error("We just came from a parent so we must have had a parent. This is a bug in React.");q.lanes|=B,Q=q.alternate,Q!==null&&(Q.lanes|=B),oZ(q,B,Z),q=null}else q=z.child;if(q!==null)q.return=z;else for(q=z;q!==null;){if(q===Z){q=null;break}if(z=q.sibling,z!==null){z.return=q.return,q=z;break}q=q.return}z=q}}function $5(Z,G,B,$){Z=null;for(var z=G,Q=!1;z!==null;){if(!Q){if((z.flags&524288)!==0)Q=!0;else if((z.flags&262144)!==0)break}if(z.tag===10){var q=z.alternate;if(q===null)throw Error("Should have a current fiber. This is a bug in React.");if(q=q.memoizedProps,q!==null){var X=z.type;l2(z.pendingProps.value,q.value)||(Z!==null?Z.push(X):Z=[X])}}else if(z===E$.current){if(q=z.alternate,q===null)throw Error("Should have a current fiber. This is a bug in React.");q.memoizedState.memoizedState!==z.memoizedState.memoizedState&&(Z!==null?Z.push(WB):Z=[WB])}z=z.return}Z!==null&&G8(G,Z,B,$),G.flags|=262144}function _5(Z){for(Z=Z.firstContext;Z!==null;){if(!l2(Z.context._currentValue,Z.memoizedValue))return!0;Z=Z.next}return!1}function YZ(Z){p$=Z,B0=null,Z=Z.dependencies,Z!==null&&(Z.firstContext=null)}function r7(Z){return $0&&console.error("Context can only be read while React is rendering. In classes, you can read it in the render method or getDerivedStateFromProps. In function components, you can read it directly in the function body, but not inside Hooks like useReducer() or useMemo()."),yB(p$,Z)}function f5(Z,G){return p$===null&&YZ(Z),yB(Z,G)}function yB(Z,G){var B=G._currentValue;if(G={context:G,memoizedValue:B,next:null},B0===null){if(Z===null)throw Error("Context can only be read while React is rendering. In classes, you can read it in the render method or getDerivedStateFromProps. In function components, you can read it directly in the function body, but not inside Hooks like useReducer() or useMemo().");B0=G,Z.dependencies={lanes:0,firstContext:G,_debugThenableState:null},Z.flags|=524288}else B0=B0.next=G;return B}function o0(){return{controller:new JV,data:new Map,refCount:0}}function B8(Z){Z.controller.signal.aborted&&console.warn("A cache instance was retained after it was already freed. This likely indicates a bug in React."),Z.refCount++}function T9(Z){Z.refCount--,0>Z.refCount&&console.warn("A cache instance was released after it was already freed. This likely indicates a bug in React."),Z.refCount===0&&qV(HV,function(){Z.controller.abort()})}function L6(Z,G,B){if((Z&127)!==0)0>g6&&(g6=z2(),g1=c$(G),Fq=G,B!=null&&(Rq=Y4(B)),(i7&(W2|C5))!==R2&&(fZ=!0,e8=y1),Z=U1(),G=L1(),Z!==z0||G!==b1?z0=-1.1:G!==null&&(e8=y1),f9=Z,b1=G);else if((Z&4194048)!==0&&0>s5&&(s5=z2(),f1=c$(G),vK=G,B!=null&&(kK=Y4(B)),0>_8)){if(Z=U1(),G=L1(),Z!==G9||G!==m9)G9=-1.1;Z9=Z,m9=G}}function C3(Z){if(0>g6){g6=z2(),g1=Z._debugTask!=null?Z._debugTask:null,(i7&(W2|C5))!==R2&&(e8=y1);var G=U1(),B=L1();G!==z0||B!==b1?z0=-1.1:B!==null&&(e8=y1),f9=G,b1=B}if(0>s5&&(s5=z2(),f1=Z._debugTask!=null?Z._debugTask:null,0>_8)){if(Z=U1(),G=L1(),Z!==G9||G!==m9)G9=-1.1;Z9=Z,m9=G}}function $8(){var Z=b9;return b9=0,Z}function gB(Z){var G=b9;return b9=Z,G}function r0(Z){var G=b9;return b9+=Z,G}function bB(){j7=G7=-1.1}function L5(){var Z=G7;return G7=-1.1,Z}function U5(Z){0<=Z&&(G7=Z)}function U6(){var Z=IZ;return IZ=-0,Z}function V6(Z){0<=Z&&(IZ=Z)}function O6(){var Z=TZ;return TZ=null,Z}function F6(){var Z=fZ;return fZ=!1,Z}function BQ(Z){s2=z2(),0>Z.actualStartTime&&(Z.actualStartTime=s2)}function $Q(Z){if(0<=s2){var G=z2()-s2;Z.actualDuration+=G,Z.selfBaseDuration=G,s2=-1}}function yH(Z){if(0<=s2){var G=z2()-s2;Z.actualDuration+=G,s2=-1}}function R6(){if(0<=s2){var Z=z2(),G=Z-s2;s2=-1,b9+=G,IZ+=G,j7=Z}}function gH(Z){TZ===null&&(TZ=[]),TZ.push(Z),W8===null&&(W8=[]),W8.push(Z)}function M6(){s2=z2(),0>G7&&(G7=s2)}function n0(Z){for(var G=Z.child;G;)Z.actualDuration+=G.actualDuration,G=G.sibling}function T3(Z,G){if(h1===null){var B=h1=[];Nq=0,h9=KJ(),Q0={status:"pending",value:void 0,then:function($){B.push($)}}}return Nq++,G.then(bH,bH),G}function bH(){if(--Nq===0&&(-1<s5||(_8=-1.1),h1!==null)){Q0!==null&&(Q0.status="fulfilled");var Z=h1;h1=null,h9=0,Q0=null;for(var G=0;G<Z.length;G++)(0,Z[G])()}}function E3(Z,G){var B=[],$={status:"pending",value:null,reason:null,then:function(z){B.push(z)}};return Z.then(function(){$.status="fulfilled",$.value=G;for(var z=0;z<B.length;z++)(0,B[z])(G)},function(z){$.status="rejected",$.reason=z;for(z=0;z<B.length;z++)(0,B[z])(void 0)}),$}function zQ(){var Z=u9.current;return Z!==null?Z:WZ.pooledCache}function fB(Z,G){G===null?b4(u9,u9.current,Z):b4(u9,G.pool,Z)}function fH(){var Z=zQ();return Z===null?null:{parent:$2._currentValue,pool:Z}}function mH(){return{didWarnAboutUncachedPromise:!1,thenables:[]}}function hH(Z){return Z=Z.status,Z==="fulfilled"||Z==="rejected"}function uH(Z,G,B){l.actQueue!==null&&(l.didUsePromise=!0);var $=Z.thenables;if(B=$[B],B===void 0?$.push(G):B!==G&&(Z.didWarnAboutUncachedPromise||(Z.didWarnAboutUncachedPromise=!0,console.error("A component was suspended by an uncached promise. Creating promises inside a Client Component or hook is not yet supported, except via a Suspense-compatible library or framework.")),G.then(Z6,Z6),G=B),G._debugInfo===void 0){Z=performance.now(),$=G.displayName;var z={name:typeof $==="string"?$:"Promise",start:Z,end:Z,value:G};G._debugInfo=[{awaited:z}],G.status!=="fulfilled"&&G.status!=="rejected"&&(Z=function(){z.end=performance.now()},G.then(Z,Z))}switch(G.status){case"fulfilled":return G.value;case"rejected":throw Z=G.reason,pH(Z),Z;default:if(typeof G.status==="string")G.then(Z6,Z6);else{if(Z=WZ,Z!==null&&100<Z.shellSuspendCounter)throw Error("An unknown Component is an async Client Component. Only Server Components can be async at the moment. This error is often caused by accidentally adding `'use client'` to a module that was originally written for the server.");Z=G,Z.status="pending",Z.then(function(Q){if(G.status==="pending"){var q=G;q.status="fulfilled",q.value=Q}},function(Q){if(G.status==="pending"){var q=G;q.status="rejected",q.reason=Q}})}switch(G.status){case"fulfilled":return G.value;case"rejected":throw Z=G.reason,pH(Z),Z}throw p9=G,a1=!0,J0}}function v8(Z){try{return KV(Z)}catch(G){if(G!==null&&typeof G==="object"&&typeof G.then==="function")throw p9=G,a1=!0,J0;throw G}}function dH(){if(p9===null)throw Error("Expected a suspended thenable. This is a bug in React. Please file an issue.");var Z=p9;return p9=null,a1=!1,Z}function pH(Z){if(Z===J0||Z===t$)throw Error("Hooks are not supported inside an async component. This error is often caused by accidentally adding `'use client'` to a module that was originally written for the server.")}function A2(Z){var G=w7;return Z!=null&&(w7=G===null?Z:G.concat(Z)),G}function QQ(){var Z=w7;if(Z!=null){for(var G=Z.length-1;0<=G;G--)if(Z[G].name!=null){var B=Z[G].debugTask;if(B!=null)return B}}return null}function mB(Z,G,B){for(var $=Object.keys(Z.props),z=0;z<$.length;z++){var Q=$[z];if(Q!=="children"&&Q!=="key"){G===null&&(G=C9(Z,B.mode,0),G._debugInfo=w7,G.return=B),M4(G,function(q){console.error("Invalid prop `%s` supplied to `React.Fragment`. React.Fragment can only have `key` and `children` props.",q)},Q);break}}}function hB(Z){var G=i1;return i1+=1,q0===null&&(q0=mH()),uH(q0,Z,G)}function t0(Z,G){G=G.props.ref,Z.ref=G!==void 0?G:null}function cH(Z,G){if(G.$$typeof===lL)throw Error(`A React Element from an older version of React was rendered. This is not supported. It can happen if:
- Multiple copies of the "react" package is used.
- A library pre-bundled an old copy of "react" or "react/jsx-runtime".
- A compiler tries to "inline" JSX instead of using the runtime.`);throw Z=Object.prototype.toString.call(G),Error("Objects are not valid as a React child (found: "+(Z==="[object Object]"?"object with keys {"+Object.keys(G).join(", ")+"}":Z)+"). If you meant to render a collection of children, use an array instead.")}function uB(Z,G){var B=QQ();B!==null?B.run(cH.bind(null,Z,G)):cH(Z,G)}function lH(Z,G){var B=Y4(Z)||"Component";ZW[B]||(ZW[B]=!0,G=G.displayName||G.name||"Component",Z.tag===3?console.error(`Functions are not valid as a React child. This may happen if you return %s instead of <%s /> from render. Or maybe you meant to call this function rather than return it.
  root.render(%s)`,G,G,G):console.error(`Functions are not valid as a React child. This may happen if you return %s instead of <%s /> from render. Or maybe you meant to call this function rather than return it.
  <%s>{%s}</%s>`,G,G,B,G,B))}function dB(Z,G){var B=QQ();B!==null?B.run(lH.bind(null,Z,G)):lH(Z,G)}function sH(Z,G){var B=Y4(Z)||"Component";GW[B]||(GW[B]=!0,G=String(G),Z.tag===3?console.error(`Symbols are not valid as a React child.
  root.render(%s)`,G):console.error(`Symbols are not valid as a React child.
  <%s>%s</%s>`,B,G,B))}function pB(Z,G){var B=QQ();B!==null?B.run(sH.bind(null,Z,G)):sH(Z,G)}function aH(Z){function G(D,T){if(Z){var S=D.deletions;S===null?(D.deletions=[T],D.flags|=16):S.push(T)}}function B(D,T){if(!Z)return null;for(;T!==null;)G(D,T),T=T.sibling;return null}function $(D){for(var T=new Map;D!==null;)D.key!==null?T.set(D.key,D):T.set(D.index,D),D=D.sibling;return T}function z(D,T){return D=k2(D,T),D.index=0,D.sibling=null,D}function Q(D,T,S){if(D.index=S,!Z)return D.flags|=1048576,T;if(S=D.alternate,S!==null)return S=S.index,S<T?(D.flags|=67108866,T):S;return D.flags|=67108866,T}function q(D){return Z&&D.alternate===null&&(D.flags|=67108866),D}function X(D,T,S,r){if(T===null||T.tag!==6)return T=N(S,D.mode,r),T.return=D,T._debugOwner=D,T._debugTask=D._debugTask,T._debugInfo=w7,T;return T=z(T,S),T.return=D,T._debugInfo=w7,T}function j(D,T,S,r){var w4=S.type;if(w4===uG)return T=k(D,T,S.props.children,r,S.key),mB(S,T,D),T;if(T!==null&&(T.elementType===w4||_6(T,S)||typeof w4==="object"&&w4!==null&&w4.$$typeof===R5&&v8(w4)===T.type))return T=z(T,S.props),t0(T,S),T.return=D,T._debugOwner=S._owner,T._debugInfo=w7,T;return T=C9(S,D.mode,r),t0(T,S),T.return=D,T._debugInfo=w7,T}function U(D,T,S,r){if(T===null||T.tag!==4||T.stateNode.containerInfo!==S.containerInfo||T.stateNode.implementation!==S.implementation)return T=w(S,D.mode,r),T.return=D,T._debugInfo=w7,T;return T=z(T,S.children||[]),T.return=D,T._debugInfo=w7,T}function k(D,T,S,r,w4){if(T===null||T.tag!==7)return T=F(S,D.mode,r,w4),T.return=D,T._debugOwner=D,T._debugTask=D._debugTask,T._debugInfo=w7,T;return T=z(T,S),T.return=D,T._debugInfo=w7,T}function y(D,T,S){if(typeof T==="string"&&T!==""||typeof T==="number"||typeof T==="bigint")return T=N(""+T,D.mode,S),T.return=D,T._debugOwner=D,T._debugTask=D._debugTask,T._debugInfo=w7,T;if(typeof T==="object"&&T!==null){switch(T.$$typeof){case E6:return S=C9(T,D.mode,S),t0(S,T),S.return=D,D=A2(T._debugInfo),S._debugInfo=w7,w7=D,S;case hG:return T=w(T,D.mode,S),T.return=D,T._debugInfo=w7,T;case R5:var r=A2(T._debugInfo);return T=v8(T),D=y(D,T,S),w7=r,D}if(j2(T)||T4(T))return S=F(T,D.mode,S,null),S.return=D,S._debugOwner=D,S._debugTask=D._debugTask,D=A2(T._debugInfo),S._debugInfo=w7,w7=D,S;if(typeof T.then==="function")return r=A2(T._debugInfo),D=y(D,hB(T),S),w7=r,D;if(T.$$typeof===w6)return y(D,f5(D,T),S);uB(D,T)}return typeof T==="function"&&dB(D,T),typeof T==="symbol"&&pB(D,T),null}function P(D,T,S,r){var w4=T!==null?T.key:null;if(typeof S==="string"&&S!==""||typeof S==="number"||typeof S==="bigint")return w4!==null?null:X(D,T,""+S,r);if(typeof S==="object"&&S!==null){switch(S.$$typeof){case E6:return S.key===w4?(w4=A2(S._debugInfo),D=j(D,T,S,r),w7=w4,D):null;case hG:return S.key===w4?U(D,T,S,r):null;case R5:return w4=A2(S._debugInfo),S=v8(S),D=P(D,T,S,r),w7=w4,D}if(j2(S)||T4(S)){if(w4!==null)return null;return w4=A2(S._debugInfo),D=k(D,T,S,r,null),w7=w4,D}if(typeof S.then==="function")return w4=A2(S._debugInfo),D=P(D,T,hB(S),r),w7=w4,D;if(S.$$typeof===w6)return P(D,T,f5(D,S),r);uB(D,S)}return typeof S==="function"&&dB(D,S),typeof S==="symbol"&&pB(D,S),null}function d(D,T,S,r,w4){if(typeof r==="string"&&r!==""||typeof r==="number"||typeof r==="bigint")return D=D.get(S)||null,X(T,D,""+r,w4);if(typeof r==="object"&&r!==null){switch(r.$$typeof){case E6:return S=D.get(r.key===null?S:r.key)||null,D=A2(r._debugInfo),T=j(T,S,r,w4),w7=D,T;case hG:return D=D.get(r.key===null?S:r.key)||null,U(T,D,r,w4);case R5:var O7=A2(r._debugInfo);return r=v8(r),T=d(D,T,S,r,w4),w7=O7,T}if(j2(r)||T4(r))return S=D.get(S)||null,D=A2(r._debugInfo),T=k(T,S,r,w4,null),w7=D,T;if(typeof r.then==="function")return O7=A2(r._debugInfo),T=d(D,T,S,hB(r),w4),w7=O7,T;if(r.$$typeof===w6)return d(D,T,S,f5(T,r),w4);uB(T,r)}return typeof r==="function"&&dB(T,r),typeof r==="symbol"&&pB(T,r),null}function R4(D,T,S,r){if(typeof S!=="object"||S===null)return r;switch(S.$$typeof){case E6:case hG:b(D,T,S);var w4=S.key;if(typeof w4!=="string")break;if(r===null){r=new Set,r.add(w4);break}if(!r.has(w4)){r.add(w4);break}M4(T,function(){console.error("Encountered two children with the same key, `%s`. Keys should be unique so that components maintain their identity across updates. Non-unique keys may cause children to be duplicated and/or omitted — the behavior is unsupported and could change in a future version.",w4)});break;case R5:S=v8(S),R4(D,T,S,r)}return r}function v4(D,T,S,r){for(var w4=null,O7=null,e4=null,a4=T,C7=T=0,DZ=null;a4!==null&&C7<S.length;C7++){a4.index>C7?(DZ=a4,a4=null):DZ=a4.sibling;var nZ=P(D,a4,S[C7],r);if(nZ===null){a4===null&&(a4=DZ);break}w4=R4(D,nZ,S[C7],w4),Z&&a4&&nZ.alternate===null&&G(D,a4),T=Q(nZ,T,C7),e4===null?O7=nZ:e4.sibling=nZ,e4=nZ,a4=DZ}if(C7===S.length)return B(D,a4),d7&&i(D,C7),O7;if(a4===null){for(;C7<S.length;C7++)a4=y(D,S[C7],r),a4!==null&&(w4=R4(D,a4,S[C7],w4),T=Q(a4,T,C7),e4===null?O7=a4:e4.sibling=a4,e4=a4);return d7&&i(D,C7),O7}for(a4=$(a4);C7<S.length;C7++)DZ=d(a4,D,C7,S[C7],r),DZ!==null&&(w4=R4(D,DZ,S[C7],w4),Z&&DZ.alternate!==null&&a4.delete(DZ.key===null?C7:DZ.key),T=Q(DZ,T,C7),e4===null?O7=DZ:e4.sibling=DZ,e4=DZ);return Z&&a4.forEach(function(D8){return G(D,D8)}),d7&&i(D,C7),O7}function OZ(D,T,S,r){if(S==null)throw Error("An iterable object provided no iterator.");for(var w4=null,O7=null,e4=T,a4=T=0,C7=null,DZ=null,nZ=S.next();e4!==null&&!nZ.done;a4++,nZ=S.next()){e4.index>a4?(C7=e4,e4=null):C7=e4.sibling;var D8=P(D,e4,nZ.value,r);if(D8===null){e4===null&&(e4=C7);break}DZ=R4(D,D8,nZ.value,DZ),Z&&e4&&D8.alternate===null&&G(D,e4),T=Q(D8,T,a4),O7===null?w4=D8:O7.sibling=D8,O7=D8,e4=C7}if(nZ.done)return B(D,e4),d7&&i(D,a4),w4;if(e4===null){for(;!nZ.done;a4++,nZ=S.next())e4=y(D,nZ.value,r),e4!==null&&(DZ=R4(D,e4,nZ.value,DZ),T=Q(e4,T,a4),O7===null?w4=e4:O7.sibling=e4,O7=e4);return d7&&i(D,a4),w4}for(e4=$(e4);!nZ.done;a4++,nZ=S.next())C7=d(e4,D,a4,nZ.value,r),C7!==null&&(DZ=R4(D,C7,nZ.value,DZ),Z&&C7.alternate!==null&&e4.delete(C7.key===null?a4:C7.key),T=Q(C7,T,a4),O7===null?w4=C7:O7.sibling=C7,O7=C7);return Z&&e4.forEach(function(gV){return G(D,gV)}),d7&&i(D,a4),w4}function l7(D,T,S,r){if(typeof S==="object"&&S!==null&&S.type===uG&&S.key===null&&(mB(S,null,D),S=S.props.children),typeof S==="object"&&S!==null){switch(S.$$typeof){case E6:var w4=A2(S._debugInfo);Z:{for(var O7=S.key;T!==null;){if(T.key===O7){if(O7=S.type,O7===uG){if(T.tag===7){B(D,T.sibling),r=z(T,S.props.children),r.return=D,r._debugOwner=S._owner,r._debugInfo=w7,mB(S,r,D),D=r;break Z}}else if(T.elementType===O7||_6(T,S)||typeof O7==="object"&&O7!==null&&O7.$$typeof===R5&&v8(O7)===T.type){B(D,T.sibling),r=z(T,S.props),t0(r,S),r.return=D,r._debugOwner=S._owner,r._debugInfo=w7,D=r;break Z}B(D,T);break}else G(D,T);T=T.sibling}S.type===uG?(r=F(S.props.children,D.mode,r,S.key),r.return=D,r._debugOwner=D,r._debugTask=D._debugTask,r._debugInfo=w7,mB(S,r,D),D=r):(r=C9(S,D.mode,r),t0(r,S),r.return=D,r._debugInfo=w7,D=r)}return D=q(D),w7=w4,D;case hG:Z:{w4=S;for(S=w4.key;T!==null;){if(T.key===S)if(T.tag===4&&T.stateNode.containerInfo===w4.containerInfo&&T.stateNode.implementation===w4.implementation){B(D,T.sibling),r=z(T,w4.children||[]),r.return=D,D=r;break Z}else{B(D,T);break}else G(D,T);T=T.sibling}r=w(w4,D.mode,r),r.return=D,D=r}return q(D);case R5:return w4=A2(S._debugInfo),S=v8(S),D=l7(D,T,S,r),w7=w4,D}if(j2(S))return w4=A2(S._debugInfo),D=v4(D,T,S,r),w7=w4,D;if(T4(S)){if(w4=A2(S._debugInfo),O7=T4(S),typeof O7!=="function")throw Error("An object is not an iterable. This error is likely caused by a bug in React. Please file an issue.");var e4=O7.call(S);if(e4===S){if(D.tag!==0||Object.prototype.toString.call(D.type)!=="[object GeneratorFunction]"||Object.prototype.toString.call(e4)!=="[object Generator]")tK||console.error("Using Iterators as children is unsupported and will likely yield unexpected results because enumerating a generator mutates it. You may convert it to an array with `Array.from()` or the `[...spread]` operator before rendering. You can also use an Iterable that can iterate multiple times over the same items."),tK=!0}else S.entries!==O7||Cq||(console.error("Using Maps as children is not supported. Use an array of keyed ReactElements instead."),Cq=!0);return D=OZ(D,T,e4,r),w7=w4,D}if(typeof S.then==="function")return w4=A2(S._debugInfo),D=l7(D,T,hB(S),r),w7=w4,D;if(S.$$typeof===w6)return l7(D,T,f5(D,S),r);uB(D,S)}if(typeof S==="string"&&S!==""||typeof S==="number"||typeof S==="bigint")return w4=""+S,T!==null&&T.tag===6?(B(D,T.sibling),r=z(T,w4),r.return=D,D=r):(B(D,T),r=N(w4,D.mode,r),r.return=D,r._debugOwner=D,r._debugTask=D._debugTask,r._debugInfo=w7,D=r),q(D);return typeof S==="function"&&dB(D,S),typeof S==="symbol"&&pB(D,S),B(D,T)}return function(D,T,S,r){var w4=w7;w7=null;try{i1=0;var O7=l7(D,T,S,r);return q0=null,O7}catch(DZ){if(DZ===J0||DZ===t$)throw DZ;var e4=R(29,DZ,null,D.mode);e4.lanes=r,e4.return=D;var a4=e4._debugInfo=w7;if(e4._debugOwner=D._debugOwner,e4._debugTask=D._debugTask,a4!=null){for(var C7=a4.length-1;0<=C7;C7--)if(typeof a4[C7].stack==="string"){e4._debugOwner=a4[C7],e4._debugTask=a4[C7].debugTask;break}}return e4}finally{w7=w4}}}function iH(Z,G){var B=j2(Z);return Z=!B&&typeof T4(Z)==="function",B||Z?(B=B?"array":"iterable",console.error("A nested %s was passed to row #%s in <SuspenseList />. Wrap it in an additional SuspenseList to configure its revealOrder: <SuspenseList revealOrder=...> ... <SuspenseList revealOrder=...>{%s}</SuspenseList> ... </SuspenseList>",B,G,B),!1):!0}function JQ(Z){Z.updateQueue={baseState:Z.memoizedState,firstBaseUpdate:null,lastBaseUpdate:null,shared:{pending:null,lanes:0,hiddenCallbacks:null},callbacks:null}}function qQ(Z,G){Z=Z.updateQueue,G.updateQueue===Z&&(G.updateQueue={baseState:Z.baseState,firstBaseUpdate:Z.firstBaseUpdate,lastBaseUpdate:Z.lastBaseUpdate,shared:Z.shared,callbacks:null})}function k8(Z){return{lane:Z,tag:$W,payload:null,callback:null,next:null}}function y8(Z,G,B){var $=Z.updateQueue;if($===null)return null;if($=$.shared,Eq===$&&!JW){var z=Y4(Z);console.error(`An update (setState, replaceState, or forceUpdate) was scheduled from inside an update function. Update functions should be pure, with zero side-effects. Consider using componentDidUpdate or a callback.

Please update the following component: %s`,z),JW=!0}if((i7&W2)!==R2)return z=$.pending,z===null?G.next=G:(G.next=z.next,z.next=G),$.pending=G,G=t6(Z),DG(Z,null,B),G;return h2(Z,$,G,B),t6(Z)}function e0(Z,G,B){if(G=G.updateQueue,G!==null&&(G=G.shared,(B&4194048)!==0)){var $=G.lanes;$&=Z.pendingLanes,B|=$,G.lanes=B,G4(Z,B)}}function cB(Z,G){var{updateQueue:B,alternate:$}=Z;if($!==null&&($=$.updateQueue,B===$)){var z=null,Q=null;if(B=B.firstBaseUpdate,B!==null){do{var q={lane:B.lane,tag:B.tag,payload:B.payload,callback:null,next:null};Q===null?z=Q=q:Q=Q.next=q,B=B.next}while(B!==null);Q===null?z=Q=G:Q=Q.next=G}else z=Q=G;B={baseState:$.baseState,firstBaseUpdate:z,lastBaseUpdate:Q,shared:$.shared,callbacks:$.callbacks},Z.updateQueue=B;return}Z=B.lastBaseUpdate,Z===null?B.firstBaseUpdate=G:Z.next=G,B.lastBaseUpdate=G}function Z1(){if(wq){var Z=Q0;if(Z!==null)throw Z}}function G1(Z,G,B,$){wq=!1;var z=Z.updateQueue;B9=!1,Eq=z.shared;var{firstBaseUpdate:Q,lastBaseUpdate:q}=z,X=z.shared.pending;if(X!==null){z.shared.pending=null;var j=X,U=j.next;j.next=null,q===null?Q=U:q.next=U,q=j;var k=Z.alternate;k!==null&&(k=k.updateQueue,X=k.lastBaseUpdate,X!==q&&(X===null?k.firstBaseUpdate=U:X.next=U,k.lastBaseUpdate=j))}if(Q!==null){var y=z.baseState;q=0,k=U=j=null,X=Q;do{var P=X.lane&-536870913,d=P!==X.lane;if(d?(I7&P)===P:($&P)===P){P!==0&&P===h9&&(wq=!0),k!==null&&(k=k.next={lane:0,tag:X.tag,payload:X.payload,callback:null,next:null});Z:{P=Z;var R4=X,v4=G,OZ=B;switch(R4.tag){case zW:if(R4=R4.payload,typeof R4==="function"){$0=!0;var l7=R4.call(OZ,y,v4);if(P.mode&g2){D4(!0);try{R4.call(OZ,y,v4)}finally{D4(!1)}}$0=!1,y=l7;break Z}y=R4;break Z;case Tq:P.flags=P.flags&-65537|128;case $W:if(l7=R4.payload,typeof l7==="function"){if($0=!0,R4=l7.call(OZ,y,v4),P.mode&g2){D4(!0);try{l7.call(OZ,y,v4)}finally{D4(!1)}}$0=!1}else R4=l7;if(R4===null||R4===void 0)break Z;y=k7({},y,R4);break Z;case QW:B9=!0}}P=X.callback,P!==null&&(Z.flags|=64,d&&(Z.flags|=8192),d=z.callbacks,d===null?z.callbacks=[P]:d.push(P))}else d={lane:P,tag:X.tag,payload:X.payload,callback:X.callback,next:null},k===null?(U=k=d,j=y):k=k.next=d,q|=P;if(X=X.next,X===null)if(X=z.shared.pending,X===null)break;else d=X,X=d.next,d.next=null,z.lastBaseUpdate=d,z.shared.pending=null}while(1);k===null&&(j=y),z.baseState=j,z.firstBaseUpdate=U,z.lastBaseUpdate=k,Q===null&&(z.shared.lanes=0),Q9|=q,Z.lanes=q,Z.memoizedState=y}Eq=null}function oH(Z,G){if(typeof Z!=="function")throw Error("Invalid argument passed as callback. Expected a function. Instead received: "+Z);Z.call(G)}function w3(Z,G){var B=Z.shared.hiddenCallbacks;if(B!==null)for(Z.shared.hiddenCallbacks=null,Z=0;Z<B.length;Z++)oH(B[Z],G)}function rH(Z,G){var B=Z.callbacks;if(B!==null)for(Z.callbacks=null,Z=0;Z<B.length;Z++)oH(B[Z],G)}function nH(Z,G){var B=m6;b4(Zz,B,Z),b4(H0,G,Z),m6=B|G.baseLanes}function HQ(Z){b4(Zz,m6,Z),b4(H0,H0.current,Z)}function XQ(Z){m6=Zz.current,d4(H0,Z),d4(Zz,Z)}function g8(Z){var G=Z.alternate;b4(rZ,rZ.current&X0,Z),b4(P5,Z,Z),a5===null&&(G===null||H0.current!==null?a5=Z:G.memoizedState!==null&&(a5=Z))}function YQ(Z){b4(rZ,rZ.current,Z),b4(P5,Z,Z),a5===null&&(a5=Z)}function tH(Z){Z.tag===22?(b4(rZ,rZ.current,Z),b4(P5,Z,Z),a5===null&&(a5=Z)):b8(Z)}function b8(Z){b4(rZ,rZ.current,Z),b4(P5,P5.current,Z)}function V5(Z){d4(P5,Z),a5===Z&&(a5=null),d4(rZ,Z)}function lB(Z){for(var G=Z;G!==null;){if(G.tag===13){var B=G.memoizedState;if(B!==null&&(B=B.dehydrated,B===null||DJ(B)||PJ(B)))return G}else if(G.tag===19&&(G.memoizedProps.revealOrder==="forwards"||G.memoizedProps.revealOrder==="backwards"||G.memoizedProps.revealOrder==="unstable_legacy-backwards"||G.memoizedProps.revealOrder==="together")){if((G.flags&128)!==0)return G}else if(G.child!==null){G.child.return=G,G=G.child;continue}if(G===Z)break;for(;G.sibling===null;){if(G.return===null||G.return===Z)return null;G=G.return}G.sibling.return=G.return,G=G.sibling}return null}function v7(){var Z=c;o5===null?o5=[Z]:o5.push(Z)}function _4(){var Z=c;if(o5!==null&&(O8++,o5[O8]!==Z)){var G=Y4(V7);if(!qW.has(G)&&(qW.add(G),o5!==null)){for(var B="",$=0;$<=O8;$++){var z=o5[$],Q=$===O8?Z:z;for(z=$+1+". "+z;30>z.length;)z+=" ";z+=Q+`
`,B+=z}console.error(`React has detected a change in the order of Hooks called by %s. This will lead to bugs and errors if not fixed. For more information, read the Rules of Hooks: https://react.dev/link/rules-of-hooks

   Previous render            Next render
   ------------------------------------------------------
%s   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
`,G,B)}}}function TG(Z){Z===void 0||Z===null||j2(Z)||console.error("%s received a final argument that is not an array (instead, received `%s`). When specified, the final argument must be an array.",c,typeof Z)}function sB(){var Z=Y4(V7);XW.has(Z)||(XW.add(Z),console.error("ReactDOM.useFormState has been renamed to React.useActionState. Please update %s to use React.useActionState.",Z))}function sZ(){throw Error(`Invalid hook call. Hooks can only be called inside of the body of a function component. This could happen for one of the following reasons:
1. You might have mismatching versions of React and the renderer (such as React DOM)
2. You might be breaking the Rules of Hooks
3. You might have more than one copy of React in the same app
See https://react.dev/link/invalid-hook-call for tips about how to debug and fix this problem.`)}function jQ(Z,G){if(n1)return!1;if(G===null)return console.error("%s received a final argument during this render, but not during the previous render. Even though the final argument is optional, its type cannot change between renders.",c),!1;Z.length!==G.length&&console.error(`The final argument passed to %s changed size between renders. The order and size of this array must remain constant.

Previous: %s
Incoming: %s`,c,"["+G.join(", ")+"]","["+Z.join(", ")+"]");for(var B=0;B<G.length&&B<Z.length;B++)if(!l2(Z[B],G[B]))return!1;return!0}function KQ(Z,G,B,$,z,Q){if(U8=Q,V7=G,o5=Z!==null?Z._debugHookTypes:null,O8=-1,n1=Z!==null&&Z.type!==G.type,Object.prototype.toString.call(B)==="[object AsyncFunction]"||Object.prototype.toString.call(B)==="[object AsyncGeneratorFunction]")Q=Y4(V7),Iq.has(Q)||(Iq.add(Q),console.error("%s is an async Client Component. Only Server Components can be async at the moment. This error is often caused by accidentally adding `'use client'` to a module that was originally written for the server.",Q===null?"An unknown Component":"<"+Q+">"));G.memoizedState=null,G.updateQueue=null,G.lanes=0,l.H=Z!==null&&Z.memoizedState!==null?Sq:o5!==null?YW:xq,l9=Q=(G.mode&g2)!==_7;var q=Dq(B,$,z);if(l9=!1,j0&&(q=WQ(G,B,$,z)),Q){D4(!0);try{q=WQ(G,B,$,z)}finally{D4(!1)}}return eH(Z,G),q}function eH(Z,G){G._debugHookTypes=o5,G.dependencies===null?V8!==null&&(G.dependencies={lanes:0,firstContext:null,_debugThenableState:V8}):G.dependencies._debugThenableState=V8,l.H=t1;var B=KZ!==null&&KZ.next!==null;if(U8=0,o5=c=Q2=KZ=V7=null,O8=-1,Z!==null&&(Z.flags&65011712)!==(G.flags&65011712)&&console.error("Internal React error: Expected static flag was missing. Please notify the React team."),Bz=!1,r1=0,V8=null,B)throw Error("Rendered fewer hooks than expected. This may be caused by an accidental early return statement.");Z===null||J2||(Z=Z.dependencies,Z!==null&&_5(Z)&&(J2=!0)),a1?(a1=!1,Z=!0):Z=!1,Z&&(G=Y4(G)||"Unknown",HW.has(G)||Iq.has(G)||(HW.add(G),console.error("`use` was called from inside a try/catch block. This is not allowed and can lead to unexpected behavior. To handle errors triggered by `use`, wrap your component in a error boundary.")))}function WQ(Z,G,B,$){V7=Z;var z=0;do{if(j0&&(V8=null),r1=0,j0=!1,z>=_V)throw Error("Too many re-renders. React limits the number of renders to prevent an infinite loop.");if(z+=1,n1=!1,Q2=KZ=null,Z.updateQueue!=null){var Q=Z.updateQueue;Q.lastEffect=null,Q.events=null,Q.stores=null,Q.memoCache!=null&&(Q.memoCache.index=0)}O8=-1,l.H=jW,Q=Dq(G,B,$)}while(j0);return Q}function I3(){var Z=l.H,G=Z.useState()[0];return G=typeof G.then==="function"?B1(G):G,Z=Z.useState()[0],(KZ!==null?KZ.memoizedState:null)!==Z&&(V7.flags|=1024),G}function _Q(){var Z=$z!==0;return $z=0,Z}function LQ(Z,G,B){G.updateQueue=Z.updateQueue,G.flags=(G.mode&Q6)!==_7?G.flags&-402655237:G.flags&-2053,Z.lanes&=~B}function UQ(Z){if(Bz){for(Z=Z.memoizedState;Z!==null;){var G=Z.queue;G!==null&&(G.pending=null),Z=Z.next}Bz=!1}U8=0,o5=Q2=KZ=V7=null,O8=-1,c=null,j0=!1,r1=$z=0,V8=null}function u2(){var Z={memoizedState:null,baseState:null,baseQueue:null,queue:null,next:null};return Q2===null?V7.memoizedState=Q2=Z:Q2=Q2.next=Z,Q2}function QZ(){if(KZ===null){var Z=V7.alternate;Z=Z!==null?Z.memoizedState:null}else Z=KZ.next;var G=Q2===null?V7.memoizedState:Q2.next;if(G!==null)Q2=G,KZ=Z;else{if(Z===null){if(V7.alternate===null)throw Error("Update hook called on initial render. This is likely a bug in React. Please file an issue.");throw Error("Rendered more hooks than during the previous render.")}KZ=Z,Z={memoizedState:KZ.memoizedState,baseState:KZ.baseState,baseQueue:KZ.baseQueue,queue:KZ.queue,next:null},Q2===null?V7.memoizedState=Q2=Z:Q2=Q2.next=Z}return Q2}function aB(){return{lastEffect:null,events:null,stores:null,memoCache:null}}function B1(Z){var G=r1;return r1+=1,V8===null&&(V8=mH()),Z=uH(V8,Z,G),G=V7,(Q2===null?G.memoizedState:Q2.next)===null&&(G=G.alternate,l.H=G!==null&&G.memoizedState!==null?Sq:xq),Z}function f8(Z){if(Z!==null&&typeof Z==="object"){if(typeof Z.then==="function")return B1(Z);if(Z.$$typeof===w6)return r7(Z)}throw Error("An unsupported type was passed to use(): "+String(Z))}function E9(Z){var G=null,B=V7.updateQueue;if(B!==null&&(G=B.memoCache),G==null){var $=V7.alternate;$!==null&&($=$.updateQueue,$!==null&&($=$.memoCache,$!=null&&(G={data:$.data.map(function(z){return z.slice()}),index:0})))}if(G==null&&(G={data:[],index:0}),B===null&&(B=aB(),V7.updateQueue=B),B.memoCache=G,B=G.data[G.index],B===void 0||n1)for(B=G.data[G.index]=Array(Z),$=0;$<Z;$++)B[$]=sL;else B.length!==Z&&console.error("Expected a constant size argument for each invocation of useMemoCache. The previous cache was allocated with size %s but size %s was requested.",B.length,Z);return G.index++,B}function G6(Z,G){return typeof G==="function"?G(Z):G}function VQ(Z,G,B){var $=u2();if(B!==void 0){var z=B(G);if(l9){D4(!0);try{B(G)}finally{D4(!1)}}}else z=G;return $.memoizedState=$.baseState=z,Z={pending:null,lanes:0,dispatch:null,lastRenderedReducer:Z,lastRenderedState:z},$.queue=Z,Z=Z.dispatch=y3.bind(null,V7,Z),[$.memoizedState,Z]}function EG(Z){var G=QZ();return OQ(G,KZ,Z)}function OQ(Z,G,B){var $=Z.queue;if($===null)throw Error("Should have a queue. You are likely calling Hooks conditionally, which is not allowed. (https://react.dev/link/invalid-hook-call)");$.lastRenderedReducer=B;var z=Z.baseQueue,Q=$.pending;if(Q!==null){if(z!==null){var q=z.next;z.next=Q.next,Q.next=q}G.baseQueue!==z&&console.error("Internal error: Expected work-in-progress queue to be a clone. This is a bug in React."),G.baseQueue=z=Q,$.pending=null}if(Q=Z.baseState,z===null)Z.memoizedState=Q;else{G=z.next;var X=q=null,j=null,U=G,k=!1;do{var y=U.lane&-536870913;if(y!==U.lane?(I7&y)===y:(U8&y)===y){var P=U.revertLane;if(P===0)j!==null&&(j=j.next={lane:0,revertLane:0,gesture:null,action:U.action,hasEagerState:U.hasEagerState,eagerState:U.eagerState,next:null}),y===h9&&(k=!0);else if((U8&P)===P){U=U.next,P===h9&&(k=!0);continue}else y={lane:0,revertLane:U.revertLane,gesture:null,action:U.action,hasEagerState:U.hasEagerState,eagerState:U.eagerState,next:null},j===null?(X=j=y,q=Q):j=j.next=y,V7.lanes|=P,Q9|=P;y=U.action,l9&&B(Q,y),Q=U.hasEagerState?U.eagerState:B(Q,y)}else P={lane:y,revertLane:U.revertLane,gesture:U.gesture,action:U.action,hasEagerState:U.hasEagerState,eagerState:U.eagerState,next:null},j===null?(X=j=P,q=Q):j=j.next=P,V7.lanes|=y,Q9|=y;U=U.next}while(U!==null&&U!==G);if(j===null?q=Q:j.next=X,!l2(Q,Z.memoizedState)&&(J2=!0,k&&(B=Q0,B!==null)))throw B;Z.memoizedState=Q,Z.baseState=q,Z.baseQueue=j,$.lastRenderedState=Q}return z===null&&($.lanes=0),[Z.memoizedState,$.dispatch]}function $1(Z){var G=QZ(),B=G.queue;if(B===null)throw Error("Should have a queue. You are likely calling Hooks conditionally, which is not allowed. (https://react.dev/link/invalid-hook-call)");B.lastRenderedReducer=Z;var{dispatch:$,pending:z}=B,Q=G.memoizedState;if(z!==null){B.pending=null;var q=z=z.next;do Q=Z(Q,q.action),q=q.next;while(q!==z);l2(Q,G.memoizedState)||(J2=!0),G.memoizedState=Q,G.baseQueue===null&&(G.baseState=Q),B.lastRenderedState=Q}return[Q,$]}function FQ(Z,G,B){var $=V7,z=u2();if(d7){if(B===void 0)throw Error("Missing getServerSnapshot, which is required for server-rendered content. Will revert to client rendering.");var Q=B();Y0||Q===B()||(console.error("The result of getServerSnapshot should be cached to avoid an infinite loop"),Y0=!0)}else{if(Q=G(),Y0||(B=G(),l2(Q,B)||(console.error("The result of getSnapshot should be cached to avoid an infinite loop"),Y0=!0)),WZ===null)throw Error("Expected a work-in-progress root. This is a bug in React. Please file an issue.");(I7&127)!==0||ZX($,G,Q)}return z.memoizedState=Q,B={value:Q,getSnapshot:G},z.queue=B,nB(BX.bind(null,$,B,Z),[Z]),$.flags|=2048,IG(i5|i2,{destroy:void 0},GX.bind(null,$,B,Q,G),null),Q}function iB(Z,G,B){var $=V7,z=QZ(),Q=d7;if(Q){if(B===void 0)throw Error("Missing getServerSnapshot, which is required for server-rendered content. Will revert to client rendering.");B=B()}else if(B=G(),!Y0){var q=G();l2(B,q)||(console.error("The result of getSnapshot should be cached to avoid an infinite loop"),Y0=!0)}if(q=!l2((KZ||z).memoizedState,B))z.memoizedState=B,J2=!0;z=z.queue;var X=BX.bind(null,$,z,Z);if(z5(2048,i2,X,[Z]),z.getSnapshot!==G||q||Q2!==null&&Q2.memoizedState.tag&i5){if($.flags|=2048,IG(i5|i2,{destroy:void 0},GX.bind(null,$,z,B,G),null),WZ===null)throw Error("Expected a work-in-progress root. This is a bug in React. Please file an issue.");Q||(U8&127)!==0||ZX($,G,B)}return B}function ZX(Z,G,B){Z.flags|=16384,Z={getSnapshot:G,value:B},G=V7.updateQueue,G===null?(G=aB(),V7.updateQueue=G,G.stores=[Z]):(B=G.stores,B===null?G.stores=[Z]:B.push(Z))}function GX(Z,G,B,$){G.value=B,G.getSnapshot=$,$X(G)&&zX(Z)}function BX(Z,G,B){return B(function(){$X(G)&&(L6(2,"updateSyncExternalStore()",Z),zX(Z))})}function $X(Z){var G=Z.getSnapshot;Z=Z.value;try{var B=G();return!l2(Z,B)}catch($){return!0}}function zX(Z){var G=Z2(Z,2);G!==null&&bZ(G,Z,2)}function RQ(Z){var G=u2();if(typeof Z==="function"){var B=Z;if(Z=B(),l9){D4(!0);try{B()}finally{D4(!1)}}}return G.memoizedState=G.baseState=Z,G.queue={pending:null,lanes:0,dispatch:null,lastRenderedReducer:G6,lastRenderedState:Z},G}function MQ(Z){Z=RQ(Z);var G=Z.queue,B=DX.bind(null,V7,G);return G.dispatch=B,[Z.memoizedState,B]}function NQ(Z){var G=u2();G.memoizedState=G.baseState=Z;var B={pending:null,lanes:0,dispatch:null,lastRenderedReducer:null,lastRenderedState:null};return G.queue=B,G=gQ.bind(null,V7,!0,B),B.dispatch=G,[Z,G]}function QX(Z,G){var B=QZ();return JX(B,KZ,Z,G)}function JX(Z,G,B,$){return Z.baseState=B,OQ(Z,KZ,typeof $==="function"?$:G6)}function qX(Z,G){var B=QZ();if(KZ!==null)return JX(B,KZ,Z,G);return B.baseState=Z,[Z,B.queue.dispatch]}function x3(Z,G,B,$,z){if($$(Z))throw Error("Cannot update form state while rendering.");if(Z=G.action,Z!==null){var Q={payload:z,action:Z,next:null,isTransition:!0,status:"pending",value:null,reason:null,listeners:[],then:function(q){Q.listeners.push(q)}};l.T!==null?B(!0):Q.isTransition=!1,$(Q),B=G.pending,B===null?(Q.next=G.pending=Q,HX(G,Q)):(Q.next=B.next,G.pending=B.next=Q)}}function HX(Z,G){var{action:B,payload:$}=G,z=Z.state;if(G.isTransition){var Q=l.T,q={};q._updatedFibers=new Set,l.T=q;try{var X=B(z,$),j=l.S;j!==null&&j(q,X),XX(Z,G,X)}catch(U){DQ(Z,G,U)}finally{Q!==null&&q.types!==null&&(Q.types!==null&&Q.types!==q.types&&console.error("We expected inner Transitions to have transferred the outer types set and that you cannot add to the outer Transition while inside the inner.This is a bug in React."),Q.types=q.types),l.T=Q,Q===null&&q._updatedFibers&&(Z=q._updatedFibers.size,q._updatedFibers.clear(),10<Z&&console.warn("Detected a large number of updates inside startTransition. If this is due to a subscription please re-write it to use React provided hooks. Otherwise concurrent mode guarantees are off the table."))}}else try{q=B(z,$),XX(Z,G,q)}catch(U){DQ(Z,G,U)}}function XX(Z,G,B){B!==null&&typeof B==="object"&&typeof B.then==="function"?(l.asyncTransitions++,B.then(B$,B$),B.then(function($){YX(Z,G,$)},function($){return DQ(Z,G,$)}),G.isTransition||console.error("An async function with useActionState was called outside of a transition. This is likely not what you intended (for example, isPending will not update correctly). Either call the returned function inside startTransition, or pass it to an `action` or `formAction` prop.")):YX(Z,G,B)}function YX(Z,G,B){G.status="fulfilled",G.value=B,jX(G),Z.state=B,G=Z.pending,G!==null&&(B=G.next,B===G?Z.pending=null:(B=B.next,G.next=B,HX(Z,B)))}function DQ(Z,G,B){var $=Z.pending;if(Z.pending=null,$!==null){$=$.next;do G.status="rejected",G.reason=B,jX(G),G=G.next;while(G!==$)}Z.action=null}function jX(Z){Z=Z.listeners;for(var G=0;G<Z.length;G++)(0,Z[G])()}function KX(Z,G){return G}function wG(Z,G){if(d7){var B=WZ.formState;if(B!==null){Z:{var $=V7;if(d7){if(NZ){G:{var z=NZ;for(var Q=l5;z.nodeType!==8;){if(!Q){z=null;break G}if(z=F5(z.nextSibling),z===null){z=null;break G}}Q=z.data,z=Q===GH||Q===rW?z:null}if(z){NZ=F5(z.nextSibling),$=z.data===GH;break Z}}zZ($)}$=!1}$&&(G=B[0])}}return B=u2(),B.memoizedState=B.baseState=G,$={pending:null,lanes:0,dispatch:null,lastRenderedReducer:KX,lastRenderedState:G},B.queue=$,B=DX.bind(null,V7,$),$.dispatch=B,$=RQ(!1),Q=gQ.bind(null,V7,!1,$.queue),$=u2(),z={state:G,dispatch:null,action:Z,pending:null},$.queue=z,B=x3.bind(null,V7,z,Q,B),z.dispatch=B,$.memoizedState=Z,[G,B,!1]}function oB(Z){var G=QZ();return WX(G,KZ,Z)}function WX(Z,G,B){if(G=OQ(Z,G,KX)[0],Z=EG(G6)[0],typeof G==="object"&&G!==null&&typeof G.then==="function")try{var $=B1(G)}catch(q){if(q===J0)throw t$;throw q}else $=G;G=QZ();var z=G.queue,Q=z.dispatch;return B!==G.memoizedState&&(V7.flags|=2048,IG(i5|i2,{destroy:void 0},S3.bind(null,z,B),null)),[$,Q,Z]}function S3(Z,G){Z.action=G}function rB(Z){var G=QZ(),B=KZ;if(B!==null)return WX(G,B,Z);QZ(),G=G.memoizedState,B=QZ();var $=B.queue.dispatch;return B.memoizedState=Z,[G,$,!1]}function IG(Z,G,B,$){return Z={tag:Z,create:B,deps:$,inst:G,next:null},G=V7.updateQueue,G===null&&(G=aB(),V7.updateQueue=G),B=G.lastEffect,B===null?G.lastEffect=Z.next=Z:($=B.next,B.next=Z,Z.next=$,G.lastEffect=Z),Z}function PQ(Z){var G=u2();return Z={current:Z},G.memoizedState=Z}function w9(Z,G,B,$){var z=u2();V7.flags|=Z,z.memoizedState=IG(i5|G,{destroy:void 0},B,$===void 0?null:$)}function z5(Z,G,B,$){var z=QZ();$=$===void 0?null:$;var Q=z.memoizedState.inst;KZ!==null&&$!==null&&jQ($,KZ.memoizedState.deps)?z.memoizedState=IG(G,Q,B,$):(V7.flags|=Z,z.memoizedState=IG(i5|G,Q,B,$))}function nB(Z,G){(V7.mode&Q6)!==_7?w9(276826112,i2,Z,G):w9(8390656,i2,Z,G)}function v3(Z){V7.flags|=4;var G=V7.updateQueue;if(G===null)G=aB(),V7.updateQueue=G,G.events=[Z];else{var B=G.events;B===null?G.events=[Z]:B.push(Z)}}function AQ(Z){var G=u2(),B={impl:Z};return G.memoizedState=B,function(){if((i7&W2)!==R2)throw Error("A function wrapped in useEffectEvent can't be called during rendering.");return B.impl.apply(void 0,arguments)}}function tB(Z){var G=QZ().memoizedState;return v3({ref:G,nextImpl:Z}),function(){if((i7&W2)!==R2)throw Error("A function wrapped in useEffectEvent can't be called during rendering.");return G.impl.apply(void 0,arguments)}}function CQ(Z,G){var B=4194308;return(V7.mode&Q6)!==_7&&(B|=134217728),w9(B,A5,Z,G)}function _X(Z,G){if(typeof G==="function"){Z=Z();var B=G(Z);return function(){typeof B==="function"?B():G(null)}}if(G!==null&&G!==void 0)return G.hasOwnProperty("current")||console.error("Expected useImperativeHandle() first argument to either be a ref callback or React.createRef() object. Instead received: %s.","an object with keys {"+Object.keys(G).join(", ")+"}"),Z=Z(),G.current=Z,function(){G.current=null}}function TQ(Z,G,B){typeof G!=="function"&&console.error("Expected useImperativeHandle() second argument to be a function that creates a handle. Instead received: %s.",G!==null?typeof G:"null"),B=B!==null&&B!==void 0?B.concat([Z]):null;var $=4194308;(V7.mode&Q6)!==_7&&($|=134217728),w9($,A5,_X.bind(null,G,Z),B)}function eB(Z,G,B){typeof G!=="function"&&console.error("Expected useImperativeHandle() second argument to be a function that creates a handle. Instead received: %s.",G!==null?typeof G:"null"),B=B!==null&&B!==void 0?B.concat([Z]):null,z5(4,A5,_X.bind(null,G,Z),B)}function EQ(Z,G){return u2().memoizedState=[Z,G===void 0?null:G],Z}function Z$(Z,G){var B=QZ();G=G===void 0?null:G;var $=B.memoizedState;if(G!==null&&jQ(G,$[1]))return $[0];return B.memoizedState=[Z,G],Z}function wQ(Z,G){var B=u2();G=G===void 0?null:G;var $=Z();if(l9){D4(!0);try{Z()}finally{D4(!1)}}return B.memoizedState=[$,G],$}function G$(Z,G){var B=QZ();G=G===void 0?null:G;var $=B.memoizedState;if(G!==null&&jQ(G,$[1]))return $[0];if($=Z(),l9){D4(!0);try{Z()}finally{D4(!1)}}return B.memoizedState=[$,G],$}function IQ(Z,G){var B=u2();return xQ(B,Z,G)}function LX(Z,G){var B=QZ();return VX(B,KZ.memoizedState,Z,G)}function UX(Z,G){var B=QZ();return KZ===null?xQ(B,Z,G):VX(B,KZ.memoizedState,Z,G)}function xQ(Z,G,B){if(B===void 0||(U8&1073741824)!==0&&(I7&261930)===0)return Z.memoizedState=G;return Z.memoizedState=B,Z=OY(),V7.lanes|=Z,Q9|=Z,B}function VX(Z,G,B,$){if(l2(B,G))return B;if(H0.current!==null)return Z=xQ(Z,B,$),l2(Z,G)||(J2=!0),Z;if((U8&42)===0||(U8&1073741824)!==0&&(I7&261930)===0)return J2=!0,Z.memoizedState=B;return Z=OY(),V7.lanes|=Z,Q9|=Z,G}function B$(){l.asyncTransitions--}function OX(Z,G,B,$,z){var Q=BZ.p;BZ.p=Q!==0&&Q<z6?Q:z6;var q=l.T,X={};X._updatedFibers=new Set,l.T=X,gQ(Z,!1,G,B);try{var j=z(),U=l.S;if(U!==null&&U(X,j),j!==null&&typeof j==="object"&&typeof j.then==="function"){l.asyncTransitions++,j.then(B$,B$);var k=E3(j,$);z1(Z,G,k,O5(Z))}else z1(Z,G,$,O5(Z))}catch(y){z1(Z,G,{then:function(){},status:"rejected",reason:y},O5(Z))}finally{BZ.p=Q,q!==null&&X.types!==null&&(q.types!==null&&q.types!==X.types&&console.error("We expected inner Transitions to have transferred the outer types set and that you cannot add to the outer Transition while inside the inner.This is a bug in React."),q.types=X.types),l.T=q,q===null&&X._updatedFibers&&(Z=X._updatedFibers.size,X._updatedFibers.clear(),10<Z&&console.warn("Detected a large number of updates inside startTransition. If this is due to a subscription please re-write it to use React provided hooks. Otherwise concurrent mode guarantees are off the table."))}}function SQ(Z,G,B,$){if(Z.tag!==5)throw Error("Expected the form instance to be a HostComponent. This is a bug in React.");var z=FX(Z).queue;C3(Z),OX(Z,z,G,BG,B===null?J4:function(){return RX(Z),B($)})}function FX(Z){var G=Z.memoizedState;if(G!==null)return G;G={memoizedState:BG,baseState:BG,baseQueue:null,queue:{pending:null,lanes:0,dispatch:null,lastRenderedReducer:G6,lastRenderedState:BG},next:null};var B={};return G.next={memoizedState:B,baseState:B,baseQueue:null,queue:{pending:null,lanes:0,dispatch:null,lastRenderedReducer:G6,lastRenderedState:B},next:null},Z.memoizedState=G,Z=Z.alternate,Z!==null&&(Z.memoizedState=G),G}function RX(Z){l.T===null&&console.error("requestFormReset was called outside a transition or action. To fix, move to an action, or wrap with startTransition.");var G=FX(Z);G.next===null&&(G=Z.alternate.memoizedState),z1(Z,G.next.queue,{},O5(Z))}function vQ(){var Z=RQ(!1);return Z=OX.bind(null,V7,Z.queue,!0,!1),u2().memoizedState=Z,[!1,Z]}function MX(){var Z=EG(G6)[0],G=QZ().memoizedState;return[typeof Z==="boolean"?Z:B1(Z),G]}function NX(){var Z=$1(G6)[0],G=QZ().memoizedState;return[typeof Z==="boolean"?Z:B1(Z),G]}function I9(){return r7(WB)}function kQ(){var Z=u2(),G=WZ.identifierPrefix;if(d7){var B=j8,$=Y8;B=($&~(1<<32-d2($)-1)).toString(32)+B,G="_"+G+"R_"+B,B=$z++,0<B&&(G+="H"+B.toString(32)),G+="_"}else B=WV++,G="_"+G+"r_"+B.toString(32)+"_";return Z.memoizedState=G}function yQ(){return u2().memoizedState=k3.bind(null,V7)}function k3(Z,G){for(var B=Z.return;B!==null;){switch(B.tag){case 24:case 3:var $=O5(B),z=k8($),Q=y8(B,z,$);Q!==null&&(L6($,"refresh()",Z),bZ(Q,B,$),e0(Q,B,$)),Z=o0(),G!==null&&G!==void 0&&Q!==null&&console.error("The seed argument is not enabled outside experimental channels."),z.payload={cache:Z};return}B=B.return}}function y3(Z,G,B){var $=arguments;typeof $[3]==="function"&&console.error("State updates from the useState() and useReducer() Hooks don't support the second callback argument. To execute a side effect after rendering, declare it in the component body with useEffect()."),$=O5(Z);var z={lane:$,revertLane:0,gesture:null,action:B,hasEagerState:!1,eagerState:null,next:null};$$(Z)?PX(G,z):(z=a0(Z,G,z,$),z!==null&&(L6($,"dispatch()",Z),bZ(z,Z,$),AX(z,G,$)))}function DX(Z,G,B){var $=arguments;typeof $[3]==="function"&&console.error("State updates from the useState() and useReducer() Hooks don't support the second callback argument. To execute a side effect after rendering, declare it in the component body with useEffect()."),$=O5(Z),z1(Z,G,B,$)&&L6($,"setState()",Z)}function z1(Z,G,B,$){var z={lane:$,revertLane:0,gesture:null,action:B,hasEagerState:!1,eagerState:null,next:null};if($$(Z))PX(G,z);else{var Q=Z.alternate;if(Z.lanes===0&&(Q===null||Q.lanes===0)&&(Q=G.lastRenderedReducer,Q!==null)){var q=l.H;l.H=q6;try{var X=G.lastRenderedState,j=Q(X,B);if(z.hasEagerState=!0,z.eagerState=j,l2(j,X))return h2(Z,G,z,0),WZ===null&&n6(),!1}catch(U){}finally{l.H=q}}if(B=a0(Z,G,z,$),B!==null)return bZ(B,Z,$),AX(B,G,$),!0}return!1}function gQ(Z,G,B,$){if(l.T===null&&h9===0&&console.error("An optimistic state update occurred outside a transition or action. To fix, move the update to an action, or wrap with startTransition."),$={lane:2,revertLane:KJ(),gesture:null,action:$,hasEagerState:!1,eagerState:null,next:null},$$(Z)){if(G)throw Error("Cannot update optimistic state while rendering.");console.error("Cannot call startTransition while rendering.")}else G=a0(Z,B,$,2),G!==null&&(L6(2,"setOptimistic()",Z),bZ(G,Z,2))}function $$(Z){var G=Z.alternate;return Z===V7||G!==null&&G===V7}function PX(Z,G){j0=Bz=!0;var B=Z.pending;B===null?G.next=G:(G.next=B.next,B.next=G),Z.pending=G}function AX(Z,G,B){if((B&4194048)!==0){var $=G.lanes;$&=Z.pendingLanes,B|=$,G.lanes=B,G4(Z,B)}}function bQ(Z){if(Z!==null&&typeof Z!=="function"){var G=String(Z);NW.has(G)||(NW.add(G),console.error("Expected the last optional `callback` argument to be a function. Instead received: %s.",Z))}}function fQ(Z,G,B,$){var z=Z.memoizedState,Q=B($,z);if(Z.mode&g2){D4(!0);try{Q=B($,z)}finally{D4(!1)}}Q===void 0&&(G=p4(G)||"Component",OW.has(G)||(OW.add(G),console.error("%s.getDerivedStateFromProps(): A valid state object (or null) must be returned. You have returned undefined.",G))),z=Q===null||Q===void 0?z:k7({},z,Q),Z.memoizedState=z,Z.lanes===0&&(Z.updateQueue.baseState=z)}function CX(Z,G,B,$,z,Q,q){var X=Z.stateNode;if(typeof X.shouldComponentUpdate==="function"){if(B=X.shouldComponentUpdate($,Q,q),Z.mode&g2){D4(!0);try{B=X.shouldComponentUpdate($,Q,q)}finally{D4(!1)}}return B===void 0&&console.error("%s.shouldComponentUpdate(): Returned undefined instead of a boolean value. Make sure to return true or false.",p4(G)||"Component"),B}return G.prototype&&G.prototype.isPureReactComponent?!v5(B,$)||!v5(z,Q):!0}function TX(Z,G,B,$){var z=G.state;typeof G.componentWillReceiveProps==="function"&&G.componentWillReceiveProps(B,$),typeof G.UNSAFE_componentWillReceiveProps==="function"&&G.UNSAFE_componentWillReceiveProps(B,$),G.state!==z&&(Z=Y4(Z)||"Component",WW.has(Z)||(WW.add(Z),console.error("%s.componentWillReceiveProps(): Assigning directly to this.state is deprecated (except inside a component's constructor). Use setState instead.",Z)),vq.enqueueReplaceState(G,G.state,null))}function x9(Z,G){var B=G;if("ref"in G){B={};for(var $ in G)$!=="ref"&&(B[$]=G[$])}if(Z=Z.defaultProps){B===G&&(B=k7({},B));for(var z in Z)B[z]===void 0&&(B[z]=Z[z])}return B}function EX(Z){Yq(Z),console.warn(`%s

%s
`,K0?"An error occurred in the <"+K0+"> component.":"An error occurred in one of your React components.",`Consider adding an error boundary to your tree to customize error handling behavior.
Visit https://react.dev/link/error-boundaries to learn more about error boundaries.`)}function wX(Z){var G=K0?"The above error occurred in the <"+K0+"> component.":"The above error occurred in one of your React components.",B="React will try to recreate this component tree from scratch using the error boundary you provided, "+((kq||"Anonymous")+".");if(typeof Z==="object"&&Z!==null&&typeof Z.environmentName==="string"){var $=Z.environmentName;Z=[`%o

%s

%s
`,Z,G,B].slice(0),typeof Z[0]==="string"?Z.splice(0,1,z_+" "+Z[0],Q_,Ez+$+Ez,J_):Z.splice(0,0,z_,Q_,Ez+$+Ez,J_),Z.unshift(console),$=kV.apply(console.error,Z),$()}else console.error(`%o

%s

%s
`,Z,G,B)}function IX(Z){Yq(Z)}function z$(Z,G){try{K0=G.source?Y4(G.source):null,kq=null;var B=G.value;if(l.actQueue!==null)l.thrownErrors.push(B);else{var $=Z.onUncaughtError;$(B,{componentStack:G.stack})}}catch(z){setTimeout(function(){throw z})}}function xX(Z,G,B){try{K0=B.source?Y4(B.source):null,kq=Y4(G);var $=Z.onCaughtError;$(B.value,{componentStack:B.stack,errorBoundary:G.tag===1?G.stateNode:null})}catch(z){setTimeout(function(){throw z})}}function mQ(Z,G,B){return B=k8(B),B.tag=Tq,B.payload={element:null},B.callback=function(){M4(G.source,z$,Z,G)},B}function hQ(Z){return Z=k8(Z),Z.tag=Tq,Z}function uQ(Z,G,B,$){var z=B.type.getDerivedStateFromError;if(typeof z==="function"){var Q=$.value;Z.payload=function(){return z(Q)},Z.callback=function(){PG(B),M4($.source,xX,G,B,$)}}var q=B.stateNode;q!==null&&typeof q.componentDidCatch==="function"&&(Z.callback=function(){PG(B),M4($.source,xX,G,B,$),typeof z!=="function"&&(q9===null?q9=new Set([this]):q9.add(this)),XV(this,$),typeof z==="function"||(B.lanes&2)===0&&console.error("%s: Error boundaries should implement getDerivedStateFromError(). In that method, return a state update to display an error message or fallback UI.",Y4(B)||"Unknown")})}function g3(Z,G,B,$,z){if(B.flags|=32768,S6&&K1(Z,z),$!==null&&typeof $==="object"&&typeof $.then==="function"){if(G=B.alternate,G!==null&&$5(G,B,z,!0),d7&&(y6=!0),B=P5.current,B!==null){switch(B.tag){case 31:case 13:return a5===null?W$():B.alternate===null&&xZ===R8&&(xZ=Jz),B.flags&=-257,B.flags|=65536,B.lanes=z,$===e$?B.flags|=16384:(G=B.updateQueue,G===null?B.updateQueue=new Set([$]):G.add($),HJ(Z,$,z)),!1;case 22:return B.flags|=65536,$===e$?B.flags|=16384:(G=B.updateQueue,G===null?(G={transitions:null,markerInstances:null,retryQueue:new Set([$])},B.updateQueue=G):(B=G.retryQueue,B===null?G.retryQueue=new Set([$]):B.add($)),HJ(Z,$,z)),!1}throw Error("Unexpected Suspense handler tag ("+B.tag+"). This is a bug in React.")}return HJ(Z,$,z),W$(),!1}if(d7)return y6=!0,G=P5.current,G!==null?((G.flags&65536)===0&&(G.flags|=256),G.flags|=65536,G.lanes=z,$!==Uq&&L7(v(Error("There was an error while hydrating but React was able to recover by instead client rendering from the nearest Suspense boundary.",{cause:$}),B))):($!==Uq&&L7(v(Error("There was an error while hydrating but React was able to recover by instead client rendering the entire root.",{cause:$}),B)),Z=Z.current.alternate,Z.flags|=65536,z&=-z,Z.lanes|=z,$=v($,B),z=mQ(Z.stateNode,$,z),cB(Z,z),xZ!==$9&&(xZ=s9)),!1;var Q=v(Error("There was an error during concurrent rendering but React was able to recover by instead synchronously rendering the entire root.",{cause:$}),B);if(zB===null?zB=[Q]:zB.push(Q),xZ!==$9&&(xZ=s9),G===null)return!0;$=v($,B),B=G;do{switch(B.tag){case 3:return B.flags|=65536,Z=z&-z,B.lanes|=Z,Z=mQ(B.stateNode,$,Z),cB(B,Z),!1;case 1:if(G=B.type,Q=B.stateNode,(B.flags&128)===0&&(typeof G.getDerivedStateFromError==="function"||Q!==null&&typeof Q.componentDidCatch==="function"&&(q9===null||!q9.has(Q))))return B.flags|=65536,z&=-z,B.lanes|=z,z=hQ(z),uQ(z,Z,B,$),cB(B,z),!1}B=B.return}while(B!==null);return!1}function C2(Z,G,B,$){G.child=Z===null?BW(G,null,B,$):c9(G,Z.child,B,$)}function SX(Z,G,B,$,z){B=B.render;var Q=G.ref;if("ref"in $){var q={};for(var X in $)X!=="ref"&&(q[X]=$[X])}else q=$;if(YZ(G),$=KQ(Z,G,B,q,Q,z),X=_Q(),Z!==null&&!J2)return LQ(Z,G,z),z8(Z,G,z);return d7&&X&&P4(G),G.flags|=1,C2(Z,G,$,z),G.child}function vX(Z,G,B,$,z){if(Z===null){var Q=B.type;if(typeof Q==="function"&&!Z8(Q)&&Q.defaultProps===void 0&&B.compare===null)return B=e6(Q),G.tag=15,G.type=B,pQ(G,Q),kX(Z,G,B,$,z);return Z=CG(B.type,null,$,G,G.mode,z),Z.ref=G.ref,Z.return=G,G.child=Z}if(Q=Z.child,!oQ(Z,z)){var q=Q.memoizedProps;if(B=B.compare,B=B!==null?B:v5,B(q,$)&&Z.ref===G.ref)return z8(Z,G,z)}return G.flags|=1,Z=k2(Q,$),Z.ref=G.ref,Z.return=G,G.child=Z}function kX(Z,G,B,$,z){if(Z!==null){var Q=Z.memoizedProps;if(v5(Q,$)&&Z.ref===G.ref&&G.type===Z.type)if(J2=!1,G.pendingProps=$=Q,oQ(Z,z))(Z.flags&131072)!==0&&(J2=!0);else return G.lanes=Z.lanes,z8(Z,G,z)}return dQ(Z,G,B,$,z)}function yX(Z,G,B,$){var z=$.children,Q=Z!==null?Z.memoizedState:null;if(Z===null&&G.stateNode===null&&(G.stateNode={_visibility:v1,_pendingMarkers:null,_retryCache:null,_transitions:null}),$.mode==="hidden"){if((G.flags&128)!==0){if(Q=Q!==null?Q.baseLanes|B:B,Z!==null){$=G.child=Z.child;for(z=0;$!==null;)z=z|$.lanes|$.childLanes,$=$.sibling;$=z&~Q}else $=0,G.child=null;return gX(Z,G,Q,B,$)}if((B&536870912)!==0)G.memoizedState={baseLanes:0,cachePool:null},Z!==null&&fB(G,Q!==null?Q.cachePool:null),Q!==null?nH(G,Q):HQ(G),tH(G);else return $=G.lanes=536870912,gX(Z,G,Q!==null?Q.baseLanes|B:B,B,$)}else Q!==null?(fB(G,Q.cachePool),nH(G,Q),b8(G),G.memoizedState=null):(Z!==null&&fB(G,null),HQ(G),b8(G));return C2(Z,G,z,B),G.child}function Q1(Z,G){return Z!==null&&Z.tag===22||G.stateNode!==null||(G.stateNode={_visibility:v1,_pendingMarkers:null,_retryCache:null,_transitions:null}),G.sibling}function gX(Z,G,B,$,z){var Q=zQ();return Q=Q===null?null:{parent:$2._currentValue,pool:Q},G.memoizedState={baseLanes:B,cachePool:Q},Z!==null&&fB(G,null),HQ(G),tH(G),Z!==null&&$5(Z,G,$,!0),G.childLanes=z,null}function Q$(Z,G){var B=G.hidden;return B!==void 0&&console.error(`<Activity> doesn't accept a hidden prop. Use mode="hidden" instead.
- <Activity %s>
+ <Activity %s>`,B===!0?"hidden":B===!1?"hidden={false}":"hidden={...}",B?'mode="hidden"':'mode="visible"'),G=q$({mode:G.mode,children:G.children},Z.mode),G.ref=Z.ref,Z.child=G,G.return=Z,G}function bX(Z,G,B){return c9(G,Z.child,null,B),Z=Q$(G,G.pendingProps),Z.flags|=2,V5(G),G.memoizedState=null,Z}function b3(Z,G,B){var $=G.pendingProps,z=(G.flags&128)!==0;if(G.flags&=-129,Z===null){if(d7){if($.mode==="hidden")return Z=Q$(G,$),G.lanes=536870912,Q1(null,Z);if(YQ(G),(Z=NZ)?(B=Hj(Z,l5),B=B!==null&&B.data===t9?B:null,B!==null&&($={dehydrated:B,treeContext:s4(),retryLane:536870912,hydrationErrors:null},G.memoizedState=$,$=I(B),$.return=G,G.child=$,w2=G,NZ=null)):B=null,B===null)throw k4(G,Z),zZ(G);return G.lanes=536870912,null}return Q$(G,$)}var Q=Z.memoizedState;if(Q!==null){var q=Q.dehydrated;if(YQ(G),z)if(G.flags&256)G.flags&=-257,G=bX(Z,G,B);else if(G.memoizedState!==null)G.child=Z.child,G.flags|=128,G=null;else throw Error("Client rendering an Activity suspended it again. This is a bug in React.");else if(Z7(),(B&536870912)!==0&&K$(G),J2||$5(Z,G,B,!1),z=(B&Z.childLanes)!==0,J2||z){if($=WZ,$!==null&&(q=z4($,B),q!==0&&q!==Q.retryLane))throw Q.retryLane=q,Z2(Z,q),bZ($,Z,q),yq;W$(),G=bX(Z,G,B)}else Z=Q.treeContext,NZ=F5(q.nextSibling),w2=G,d7=!0,r8=null,y6=!1,D5=null,l5=!1,Z!==null&&r4(G,Z),G=Q$(G,$),G.flags|=4096;return G}return Q=Z.child,$={mode:$.mode,children:$.children},(B&536870912)!==0&&(B&Z.lanes)!==0&&K$(G),Z=k2(Q,$),Z.ref=G.ref,G.child=Z,Z.return=G,Z}function J$(Z,G){var B=G.ref;if(B===null)Z!==null&&Z.ref!==null&&(G.flags|=4194816);else{if(typeof B!=="function"&&typeof B!=="object")throw Error("Expected ref to be a function, an object returned by React.createRef(), or undefined/null.");if(Z===null||Z.ref!==B)G.flags|=4194816}}function dQ(Z,G,B,$,z){if(B.prototype&&typeof B.prototype.render==="function"){var Q=p4(B)||"Unknown";DW[Q]||(console.error("The <%s /> component appears to have a render method, but doesn't extend React.Component. This is likely to cause errors. Change %s to extend React.Component instead.",Q,Q),DW[Q]=!0)}if(G.mode&g2&&J6.recordLegacyContextWarning(G,null),Z===null&&(pQ(G,G.type),B.contextTypes&&(Q=p4(B)||"Unknown",AW[Q]||(AW[Q]=!0,console.error("%s uses the legacy contextTypes API which was removed in React 19. Use React.createContext() with React.useContext() instead. (https://react.dev/link/legacy-context)",Q)))),YZ(G),B=KQ(Z,G,B,$,void 0,z),$=_Q(),Z!==null&&!J2)return LQ(Z,G,z),z8(Z,G,z);return d7&&$&&P4(G),G.flags|=1,C2(Z,G,B,z),G.child}function fX(Z,G,B,$,z,Q){if(YZ(G),O8=-1,n1=Z!==null&&Z.type!==G.type,G.updateQueue=null,B=WQ(G,$,B,z),eH(Z,G),$=_Q(),Z!==null&&!J2)return LQ(Z,G,Q),z8(Z,G,Q);return d7&&$&&P4(G),G.flags|=1,C2(Z,G,B,Q),G.child}function mX(Z,G,B,$,z){switch(A(G)){case!1:var Q=G.stateNode,q=new G.type(G.memoizedProps,Q.context).state;Q.updater.enqueueSetState(Q,q,null);break;case!0:G.flags|=128,G.flags|=65536,Q=Error("Simulated error coming from DevTools");var X=z&-z;if(G.lanes|=X,q=WZ,q===null)throw Error("Expected a work-in-progress root. This is a bug in React. Please file an issue.");X=hQ(X),uQ(X,q,G,v(Q,G)),cB(G,X)}if(YZ(G),G.stateNode===null){if(q=o8,Q=B.contextType,"contextType"in B&&Q!==null&&(Q===void 0||Q.$$typeof!==w6)&&!MW.has(B)&&(MW.add(B),X=Q===void 0?" However, it is set to undefined. This can be caused by a typo or by mixing up named and default imports. This can also happen due to a circular dependency, so try moving the createContext() call to a separate file.":typeof Q!=="object"?" However, it is set to a "+typeof Q+".":Q.$$typeof===gJ?" Did you accidentally pass the Context.Consumer instead?":" However, it is set to an object with keys {"+Object.keys(Q).join(", ")+"}.",console.error("%s defines an invalid contextType. contextType should point to the Context object returned by React.createContext().%s",p4(B)||"Component",X)),typeof Q==="object"&&Q!==null&&(q=r7(Q)),Q=new B($,q),G.mode&g2){D4(!0);try{Q=new B($,q)}finally{D4(!1)}}if(q=G.memoizedState=Q.state!==null&&Q.state!==void 0?Q.state:null,Q.updater=vq,G.stateNode=Q,Q._reactInternals=G,Q._reactInternalInstance=KW,typeof B.getDerivedStateFromProps==="function"&&q===null&&(q=p4(B)||"Component",_W.has(q)||(_W.add(q),console.error("`%s` uses `getDerivedStateFromProps` but its initial state is %s. This is not recommended. Instead, define the initial state by assigning an object to `this.state` in the constructor of `%s`. This ensures that `getDerivedStateFromProps` arguments have a consistent shape.",q,Q.state===null?"null":"undefined",q))),typeof B.getDerivedStateFromProps==="function"||typeof Q.getSnapshotBeforeUpdate==="function"){var j=X=q=null;if(typeof Q.componentWillMount==="function"&&Q.componentWillMount.__suppressDeprecationWarning!==!0?q="componentWillMount":typeof Q.UNSAFE_componentWillMount==="function"&&(q="UNSAFE_componentWillMount"),typeof Q.componentWillReceiveProps==="function"&&Q.componentWillReceiveProps.__suppressDeprecationWarning!==!0?X="componentWillReceiveProps":typeof Q.UNSAFE_componentWillReceiveProps==="function"&&(X="UNSAFE_componentWillReceiveProps"),typeof Q.componentWillUpdate==="function"&&Q.componentWillUpdate.__suppressDeprecationWarning!==!0?j="componentWillUpdate":typeof Q.UNSAFE_componentWillUpdate==="function"&&(j="UNSAFE_componentWillUpdate"),q!==null||X!==null||j!==null){Q=p4(B)||"Component";var U=typeof B.getDerivedStateFromProps==="function"?"getDerivedStateFromProps()":"getSnapshotBeforeUpdate()";UW.has(Q)||(UW.add(Q),console.error(`Unsafe legacy lifecycles will not be called for components using new component APIs.

%s uses %s but also contains the following legacy lifecycles:%s%s%s

The above lifecycles should be removed. Learn more about this warning here:
https://react.dev/link/unsafe-component-lifecycles`,Q,U,q!==null?`
  `+q:"",X!==null?`
  `+X:"",j!==null?`
  `+j:""))}}Q=G.stateNode,q=p4(B)||"Component",Q.render||(B.prototype&&typeof B.prototype.render==="function"?console.error("No `render` method found on the %s instance: did you accidentally return an object from the constructor?",q):console.error("No `render` method found on the %s instance: you may have forgotten to define `render`.",q)),!Q.getInitialState||Q.getInitialState.isReactClassApproved||Q.state||console.error("getInitialState was defined on %s, a plain JavaScript class. This is only supported for classes created using React.createClass. Did you mean to define a state property instead?",q),Q.getDefaultProps&&!Q.getDefaultProps.isReactClassApproved&&console.error("getDefaultProps was defined on %s, a plain JavaScript class. This is only supported for classes created using React.createClass. Use a static property to define defaultProps instead.",q),Q.contextType&&console.error("contextType was defined as an instance property on %s. Use a static property to define contextType instead.",q),B.childContextTypes&&!RW.has(B)&&(RW.add(B),console.error("%s uses the legacy childContextTypes API which was removed in React 19. Use React.createContext() instead. (https://react.dev/link/legacy-context)",q)),B.contextTypes&&!FW.has(B)&&(FW.add(B),console.error("%s uses the legacy contextTypes API which was removed in React 19. Use React.createContext() with static contextType instead. (https://react.dev/link/legacy-context)",q)),typeof Q.componentShouldUpdate==="function"&&console.error("%s has a method called componentShouldUpdate(). Did you mean shouldComponentUpdate()? The name is phrased as a question because the function is expected to return a value.",q),B.prototype&&B.prototype.isPureReactComponent&&typeof Q.shouldComponentUpdate<"u"&&console.error("%s has a method called shouldComponentUpdate(). shouldComponentUpdate should not be used when extending React.PureComponent. Please extend React.Component if shouldComponentUpdate is used.",p4(B)||"A pure component"),typeof Q.componentDidUnmount==="function"&&console.error("%s has a method called componentDidUnmount(). But there is no such lifecycle method. Did you mean componentWillUnmount()?",q),typeof Q.componentDidReceiveProps==="function"&&console.error("%s has a method called componentDidReceiveProps(). But there is no such lifecycle method. If you meant to update the state in response to changing props, use componentWillReceiveProps(). If you meant to fetch data or run side-effects or mutations after React has updated the UI, use componentDidUpdate().",q),typeof Q.componentWillRecieveProps==="function"&&console.error("%s has a method called componentWillRecieveProps(). Did you mean componentWillReceiveProps()?",q),typeof Q.UNSAFE_componentWillRecieveProps==="function"&&console.error("%s has a method called UNSAFE_componentWillRecieveProps(). Did you mean UNSAFE_componentWillReceiveProps()?",q),X=Q.props!==$,Q.props!==void 0&&X&&console.error("When calling super() in `%s`, make sure to pass up the same props that your component's constructor was passed.",q),Q.defaultProps&&console.error("Setting defaultProps as an instance property on %s is not supported and will be ignored. Instead, define defaultProps as a static property on %s.",q,q),typeof Q.getSnapshotBeforeUpdate!=="function"||typeof Q.componentDidUpdate==="function"||LW.has(B)||(LW.add(B),console.error("%s: getSnapshotBeforeUpdate() should be used with componentDidUpdate(). This component defines getSnapshotBeforeUpdate() only.",p4(B))),typeof Q.getDerivedStateFromProps==="function"&&console.error("%s: getDerivedStateFromProps() is defined as an instance method and will be ignored. Instead, declare it as a static method.",q),typeof Q.getDerivedStateFromError==="function"&&console.error("%s: getDerivedStateFromError() is defined as an instance method and will be ignored. Instead, declare it as a static method.",q),typeof B.getSnapshotBeforeUpdate==="function"&&console.error("%s: getSnapshotBeforeUpdate() is defined as a static method and will be ignored. Instead, declare it as an instance method.",q),(X=Q.state)&&(typeof X!=="object"||j2(X))&&console.error("%s.state: must be set to an object or null",q),typeof Q.getChildContext==="function"&&typeof B.childContextTypes!=="object"&&console.error("%s.getChildContext(): childContextTypes must be defined in order to use getChildContext().",q),Q=G.stateNode,Q.props=$,Q.state=G.memoizedState,Q.refs={},JQ(G),q=B.contextType,Q.context=typeof q==="object"&&q!==null?r7(q):o8,Q.state===$&&(q=p4(B)||"Component",VW.has(q)||(VW.add(q),console.error("%s: It is not recommended to assign props directly to state because updates to props won't be reflected in state. In most cases, it is better to use props directly.",q))),G.mode&g2&&J6.recordLegacyContextWarning(G,Q),J6.recordUnsafeLifecycleWarnings(G,Q),Q.state=G.memoizedState,q=B.getDerivedStateFromProps,typeof q==="function"&&(fQ(G,B,q,$),Q.state=G.memoizedState),typeof B.getDerivedStateFromProps==="function"||typeof Q.getSnapshotBeforeUpdate==="function"||typeof Q.UNSAFE_componentWillMount!=="function"&&typeof Q.componentWillMount!=="function"||(q=Q.state,typeof Q.componentWillMount==="function"&&Q.componentWillMount(),typeof Q.UNSAFE_componentWillMount==="function"&&Q.UNSAFE_componentWillMount(),q!==Q.state&&(console.error("%s.componentWillMount(): Assigning directly to this.state is deprecated (except inside a component's constructor). Use setState instead.",Y4(G)||"Component"),vq.enqueueReplaceState(Q,Q.state,null)),G1(G,$,Q,z),Z1(),Q.state=G.memoizedState),typeof Q.componentDidMount==="function"&&(G.flags|=4194308),(G.mode&Q6)!==_7&&(G.flags|=134217728),Q=!0}else if(Z===null){Q=G.stateNode;var k=G.memoizedProps;X=x9(B,k),Q.props=X;var y=Q.context;j=B.contextType,q=o8,typeof j==="object"&&j!==null&&(q=r7(j)),U=B.getDerivedStateFromProps,j=typeof U==="function"||typeof Q.getSnapshotBeforeUpdate==="function",k=G.pendingProps!==k,j||typeof Q.UNSAFE_componentWillReceiveProps!=="function"&&typeof Q.componentWillReceiveProps!=="function"||(k||y!==q)&&TX(G,Q,$,q),B9=!1;var P=G.memoizedState;Q.state=P,G1(G,$,Q,z),Z1(),y=G.memoizedState,k||P!==y||B9?(typeof U==="function"&&(fQ(G,B,U,$),y=G.memoizedState),(X=B9||CX(G,B,X,$,P,y,q))?(j||typeof Q.UNSAFE_componentWillMount!=="function"&&typeof Q.componentWillMount!=="function"||(typeof Q.componentWillMount==="function"&&Q.componentWillMount(),typeof Q.UNSAFE_componentWillMount==="function"&&Q.UNSAFE_componentWillMount()),typeof Q.componentDidMount==="function"&&(G.flags|=4194308),(G.mode&Q6)!==_7&&(G.flags|=134217728)):(typeof Q.componentDidMount==="function"&&(G.flags|=4194308),(G.mode&Q6)!==_7&&(G.flags|=134217728),G.memoizedProps=$,G.memoizedState=y),Q.props=$,Q.state=y,Q.context=q,Q=X):(typeof Q.componentDidMount==="function"&&(G.flags|=4194308),(G.mode&Q6)!==_7&&(G.flags|=134217728),Q=!1)}else{Q=G.stateNode,qQ(Z,G),q=G.memoizedProps,j=x9(B,q),Q.props=j,U=G.pendingProps,P=Q.context,y=B.contextType,X=o8,typeof y==="object"&&y!==null&&(X=r7(y)),k=B.getDerivedStateFromProps,(y=typeof k==="function"||typeof Q.getSnapshotBeforeUpdate==="function")||typeof Q.UNSAFE_componentWillReceiveProps!=="function"&&typeof Q.componentWillReceiveProps!=="function"||(q!==U||P!==X)&&TX(G,Q,$,X),B9=!1,P=G.memoizedState,Q.state=P,G1(G,$,Q,z),Z1();var d=G.memoizedState;q!==U||P!==d||B9||Z!==null&&Z.dependencies!==null&&_5(Z.dependencies)?(typeof k==="function"&&(fQ(G,B,k,$),d=G.memoizedState),(j=B9||CX(G,B,j,$,P,d,X)||Z!==null&&Z.dependencies!==null&&_5(Z.dependencies))?(y||typeof Q.UNSAFE_componentWillUpdate!=="function"&&typeof Q.componentWillUpdate!=="function"||(typeof Q.componentWillUpdate==="function"&&Q.componentWillUpdate($,d,X),typeof Q.UNSAFE_componentWillUpdate==="function"&&Q.UNSAFE_componentWillUpdate($,d,X)),typeof Q.componentDidUpdate==="function"&&(G.flags|=4),typeof Q.getSnapshotBeforeUpdate==="function"&&(G.flags|=1024)):(typeof Q.componentDidUpdate!=="function"||q===Z.memoizedProps&&P===Z.memoizedState||(G.flags|=4),typeof Q.getSnapshotBeforeUpdate!=="function"||q===Z.memoizedProps&&P===Z.memoizedState||(G.flags|=1024),G.memoizedProps=$,G.memoizedState=d),Q.props=$,Q.state=d,Q.context=X,Q=j):(typeof Q.componentDidUpdate!=="function"||q===Z.memoizedProps&&P===Z.memoizedState||(G.flags|=4),typeof Q.getSnapshotBeforeUpdate!=="function"||q===Z.memoizedProps&&P===Z.memoizedState||(G.flags|=1024),Q=!1)}if(X=Q,J$(Z,G),q=(G.flags&128)!==0,X||q){if(X=G.stateNode,_2(G),q&&typeof B.getDerivedStateFromError!=="function")B=null,s2=-1;else if(B=dK(X),G.mode&g2){D4(!0);try{dK(X)}finally{D4(!1)}}G.flags|=1,Z!==null&&q?(G.child=c9(G,Z.child,null,z),G.child=c9(G,null,B,z)):C2(Z,G,B,z),G.memoizedState=X.state,Z=G.child}else Z=z8(Z,G,z);return z=G.stateNode,Q&&z.props!==$&&(W0||console.error("It looks like %s is reassigning its own `this.props` while rendering. This is not supported and can lead to confusing bugs.",Y4(G)||"a component"),W0=!0),Z}function hX(Z,G,B,$){return HZ(),G.flags|=256,C2(Z,G,B,$),G.child}function pQ(Z,G){G&&G.childContextTypes&&console.error(`childContextTypes cannot be defined on a function component.
  %s.childContextTypes = ...`,G.displayName||G.name||"Component"),typeof G.getDerivedStateFromProps==="function"&&(Z=p4(G)||"Unknown",CW[Z]||(console.error("%s: Function components do not support getDerivedStateFromProps.",Z),CW[Z]=!0)),typeof G.contextType==="object"&&G.contextType!==null&&(G=p4(G)||"Unknown",PW[G]||(console.error("%s: Function components do not support contextType.",G),PW[G]=!0))}function cQ(Z){return{baseLanes:Z,cachePool:fH()}}function lQ(Z,G,B){return Z=Z!==null?Z.childLanes&~B:0,G&&(Z|=X5),Z}function uX(Z,G,B){var $,z=G.pendingProps;O(G)&&(G.flags|=128);var Q=!1,q=(G.flags&128)!==0;if(($=q)||($=Z!==null&&Z.memoizedState===null?!1:(rZ.current&o1)!==0),$&&(Q=!0,G.flags&=-129),$=(G.flags&32)!==0,G.flags&=-33,Z===null){if(d7){if(Q?g8(G):b8(G),(Z=NZ)?(B=Hj(Z,l5),B=B!==null&&B.data!==t9?B:null,B!==null&&($={dehydrated:B,treeContext:s4(),retryLane:536870912,hydrationErrors:null},G.memoizedState=$,$=I(B),$.return=G,G.child=$,w2=G,NZ=null)):B=null,B===null)throw k4(G,Z),zZ(G);return PJ(B)?G.lanes=32:G.lanes=536870912,null}var X=z.children;if(z=z.fallback,Q){b8(G);var j=G.mode;return X=q$({mode:"hidden",children:X},j),z=F(z,j,B,null),X.return=G,z.return=G,X.sibling=z,G.child=X,z=G.child,z.memoizedState=cQ(B),z.childLanes=lQ(Z,$,B),G.memoizedState=gq,Q1(null,z)}return g8(G),sQ(G,X)}var U=Z.memoizedState;if(U!==null){var k=U.dehydrated;if(k!==null){if(q)G.flags&256?(g8(G),G.flags&=-257,G=aQ(Z,G,B)):G.memoizedState!==null?(b8(G),G.child=Z.child,G.flags|=128,G=null):(b8(G),X=z.fallback,j=G.mode,z=q$({mode:"visible",children:z.children},j),X=F(X,j,B,null),X.flags|=2,z.return=G,X.return=G,z.sibling=X,G.child=z,c9(G,Z.child,null,B),z=G.child,z.memoizedState=cQ(B),z.childLanes=lQ(Z,$,B),G.memoizedState=gq,G=Q1(null,z));else if(g8(G),Z7(),(B&536870912)!==0&&K$(G),PJ(k)){if($=k.nextSibling&&k.nextSibling.dataset,$){X=$.dgst;var y=$.msg;j=$.stck;var P=$.cstck}Q=y,$=X,z=j,k=P,X=Q,j=k,X=X?Error(X):Error("The server could not finish this Suspense boundary, likely due to an error during server rendering. Switched to client rendering."),X.stack=z||"",X.digest=$,$=j===void 0?null:j,z={value:X,source:null,stack:$},typeof $==="string"&&Lq.set(X,z),L7(z),G=aQ(Z,G,B)}else if(J2||$5(Z,G,B,!1),$=(B&Z.childLanes)!==0,J2||$){if($=WZ,$!==null&&(z=z4($,B),z!==0&&z!==U.retryLane))throw U.retryLane=z,Z2(Z,z),bZ($,Z,z),yq;DJ(k)||W$(),G=aQ(Z,G,B)}else DJ(k)?(G.flags|=192,G.child=Z.child,G=null):(Z=U.treeContext,NZ=F5(k.nextSibling),w2=G,d7=!0,r8=null,y6=!1,D5=null,l5=!1,Z!==null&&r4(G,Z),G=sQ(G,z.children),G.flags|=4096);return G}}if(Q)return b8(G),X=z.fallback,j=G.mode,P=Z.child,k=P.sibling,z=k2(P,{mode:"hidden",children:z.children}),z.subtreeFlags=P.subtreeFlags&65011712,k!==null?X=k2(k,X):(X=F(X,j,B,null),X.flags|=2),X.return=G,z.return=G,z.sibling=X,G.child=z,Q1(null,z),z=G.child,X=Z.child.memoizedState,X===null?X=cQ(B):(j=X.cachePool,j!==null?(P=$2._currentValue,j=j.parent!==P?{parent:P,pool:P}:j):j=fH(),X={baseLanes:X.baseLanes|B,cachePool:j}),z.memoizedState=X,z.childLanes=lQ(Z,$,B),G.memoizedState=gq,Q1(Z.child,z);return U!==null&&(B&62914560)===B&&(B&Z.lanes)!==0&&K$(G),g8(G),B=Z.child,Z=B.sibling,B=k2(B,{mode:"visible",children:z.children}),B.return=G,B.sibling=null,Z!==null&&($=G.deletions,$===null?(G.deletions=[Z],G.flags|=16):$.push(Z)),G.child=B,G.memoizedState=null,B}function sQ(Z,G){return G=q$({mode:"visible",children:G},Z.mode),G.return=Z,Z.child=G}function q$(Z,G){return Z=R(22,Z,null,G),Z.lanes=0,Z}function aQ(Z,G,B){return c9(G,Z.child,null,B),Z=sQ(G,G.pendingProps.children),Z.flags|=2,G.memoizedState=null,Z}function dX(Z,G,B){Z.lanes|=G;var $=Z.alternate;$!==null&&($.lanes|=G),oZ(Z.return,G,B)}function iQ(Z,G,B,$,z,Q){var q=Z.memoizedState;q===null?Z.memoizedState={isBackwards:G,rendering:null,renderingStartTime:0,last:$,tail:B,tailMode:z,treeForkCount:Q}:(q.isBackwards=G,q.rendering=null,q.renderingStartTime=0,q.last=$,q.tail=B,q.tailMode=z,q.treeForkCount=Q)}function pX(Z,G,B){var $=G.pendingProps,z=$.revealOrder,Q=$.tail,q=$.children,X=rZ.current;if(($=(X&o1)!==0)?(X=X&X0|o1,G.flags|=128):X&=X0,b4(rZ,X,G),X=z==null?"null":z,z!=="forwards"&&z!=="unstable_legacy-backwards"&&z!=="together"&&z!=="independent"&&!TW[X])if(TW[X]=!0,z==null)console.error('The default for the <SuspenseList revealOrder="..."> prop is changing. To be future compatible you must explictly specify either "independent" (the current default), "together", "forwards" or "legacy_unstable-backwards".');else if(z==="backwards")console.error('The rendering order of <SuspenseList revealOrder="backwards"> is changing. To be future compatible you must specify revealOrder="legacy_unstable-backwards" instead.');else if(typeof z==="string")switch(z.toLowerCase()){case"together":case"forwards":case"backwards":case"independent":console.error('"%s" is not a valid value for revealOrder on <SuspenseList />. Use lowercase "%s" instead.',z,z.toLowerCase());break;case"forward":case"backward":console.error('"%s" is not a valid value for revealOrder on <SuspenseList />. React uses the -s suffix in the spelling. Use "%ss" instead.',z,z.toLowerCase());break;default:console.error('"%s" is not a supported revealOrder on <SuspenseList />. Did you mean "independent", "together", "forwards" or "backwards"?',z)}else console.error('%s is not a supported value for revealOrder on <SuspenseList />. Did you mean "independent", "together", "forwards" or "backwards"?',z);if(X=Q==null?"null":Q,!Qz[X])if(Q==null){if(z==="forwards"||z==="backwards"||z==="unstable_legacy-backwards")Qz[X]=!0,console.error('The default for the <SuspenseList tail="..."> prop is changing. To be future compatible you must explictly specify either "visible" (the current default), "collapsed" or "hidden".')}else Q!=="visible"&&Q!=="collapsed"&&Q!=="hidden"?(Qz[X]=!0,console.error('"%s" is not a supported value for tail on <SuspenseList />. Did you mean "visible", "collapsed" or "hidden"?',Q)):z!=="forwards"&&z!=="backwards"&&z!=="unstable_legacy-backwards"&&(Qz[X]=!0,console.error('<SuspenseList tail="%s" /> is only valid if revealOrder is "forwards" or "backwards". Did you mean to specify revealOrder="forwards"?',Q));Z:if((z==="forwards"||z==="backwards"||z==="unstable_legacy-backwards")&&q!==void 0&&q!==null&&q!==!1)if(j2(q)){for(X=0;X<q.length;X++)if(!iH(q[X],X))break Z}else if(X=T4(q),typeof X==="function"){if(X=X.call(q))for(var j=X.next(),U=0;!j.done;j=X.next()){if(!iH(j.value,U))break Z;U++}}else console.error('A single row was passed to a <SuspenseList revealOrder="%s" />. This is not useful since it needs multiple rows. Did you mean to pass multiple children or an array?',z);if(C2(Z,G,q,B),d7?($7(),q=k1):q=0,!$&&Z!==null&&(Z.flags&128)!==0)Z:for(Z=G.child;Z!==null;){if(Z.tag===13)Z.memoizedState!==null&&dX(Z,B,G);else if(Z.tag===19)dX(Z,B,G);else if(Z.child!==null){Z.child.return=Z,Z=Z.child;continue}if(Z===G)break Z;for(;Z.sibling===null;){if(Z.return===null||Z.return===G)break Z;Z=Z.return}Z.sibling.return=Z.return,Z=Z.sibling}switch(z){case"forwards":B=G.child;for(z=null;B!==null;)Z=B.alternate,Z!==null&&lB(Z)===null&&(z=B),B=B.sibling;B=z,B===null?(z=G.child,G.child=null):(z=B.sibling,B.sibling=null),iQ(G,!1,z,B,Q,q);break;case"backwards":case"unstable_legacy-backwards":B=null,z=G.child;for(G.child=null;z!==null;){if(Z=z.alternate,Z!==null&&lB(Z)===null){G.child=z;break}Z=z.sibling,z.sibling=B,B=z,z=Z}iQ(G,!0,B,null,Q,q);break;case"together":iQ(G,!1,null,null,void 0,q);break;default:G.memoizedState=null}return G.child}function z8(Z,G,B){if(Z!==null&&(G.dependencies=Z.dependencies),s2=-1,Q9|=G.lanes,(B&G.childLanes)===0)if(Z!==null){if($5(Z,G,B,!1),(B&G.childLanes)===0)return null}else return null;if(Z!==null&&G.child!==Z.child)throw Error("Resuming work not yet implemented.");if(G.child!==null){Z=G.child,B=k2(Z,Z.pendingProps),G.child=B;for(B.return=G;Z.sibling!==null;)Z=Z.sibling,B=B.sibling=k2(Z,Z.pendingProps),B.return=G;B.sibling=null}return G.child}function oQ(Z,G){if((Z.lanes&G)!==0)return!0;return Z=Z.dependencies,Z!==null&&_5(Z)?!0:!1}function f3(Z,G,B){switch(G.tag){case 3:B4(G,G.stateNode.containerInfo),G2(G,$2,Z.memoizedState.cache),HZ();break;case 27:case 5:$4(G);break;case 4:B4(G,G.stateNode.containerInfo);break;case 10:G2(G,G.type,G.memoizedProps.value);break;case 12:(B&G.childLanes)!==0&&(G.flags|=4),G.flags|=2048;var $=G.stateNode;$.effectDuration=-0,$.passiveEffectDuration=-0;break;case 31:if(G.memoizedState!==null)return G.flags|=128,YQ(G),null;break;case 13:if($=G.memoizedState,$!==null){if($.dehydrated!==null)return g8(G),G.flags|=128,null;if((B&G.child.childLanes)!==0)return uX(Z,G,B);return g8(G),Z=z8(Z,G,B),Z!==null?Z.sibling:null}g8(G);break;case 19:var z=(Z.flags&128)!==0;if($=(B&G.childLanes)!==0,$||($5(Z,G,B,!1),$=(B&G.childLanes)!==0),z){if($)return pX(Z,G,B);G.flags|=128}if(z=G.memoizedState,z!==null&&(z.rendering=null,z.tail=null,z.lastEffect=null),b4(rZ,rZ.current,G),$)break;else return null;case 22:return G.lanes=0,yX(Z,G,B,G.pendingProps);case 24:G2(G,$2,Z.memoizedState.cache)}return z8(Z,G,B)}function rQ(Z,G,B){if(G._debugNeedsRemount&&Z!==null){B=CG(G.type,G.key,G.pendingProps,G._debugOwner||null,G.mode,G.lanes),B._debugStack=G._debugStack,B._debugTask=G._debugTask;var $=G.return;if($===null)throw Error("Cannot swap the root fiber.");if(Z.alternate=null,G.alternate=null,B.index=G.index,B.sibling=G.sibling,B.return=G.return,B.ref=G.ref,B._debugInfo=G._debugInfo,G===$.child)$.child=B;else{var z=$.child;if(z===null)throw Error("Expected parent to have a child.");for(;z.sibling!==G;)if(z=z.sibling,z===null)throw Error("Expected to find the previous sibling.");z.sibling=B}return G=$.deletions,G===null?($.deletions=[Z],$.flags|=16):G.push(Z),B.flags|=2,B}if(Z!==null)if(Z.memoizedProps!==G.pendingProps||G.type!==Z.type)J2=!0;else{if(!oQ(Z,B)&&(G.flags&128)===0)return J2=!1,f3(Z,G,B);J2=(Z.flags&131072)!==0?!0:!1}else{if(J2=!1,$=d7)$7(),$=(G.flags&1048576)!==0;$&&($=G.index,$7(),V4(G,k1,$))}switch(G.lanes=0,G.tag){case 16:Z:if($=G.pendingProps,Z=v8(G.elementType),G.type=Z,typeof Z==="function")Z8(Z)?($=x9(Z,$),G.tag=1,G.type=Z=e6(Z),G=mX(null,G,Z,$,B)):(G.tag=0,pQ(G,Z),G.type=Z=e6(Z),G=dQ(null,G,Z,$,B));else{if(Z!==void 0&&Z!==null){if(z=Z.$$typeof,z===M1){G.tag=11,G.type=Z=i0(Z),G=SX(null,G,Z,$,B);break Z}else if(z===T$){G.tag=14,G=vX(null,G,Z,$,B);break Z}}throw G="",Z!==null&&typeof Z==="object"&&Z.$$typeof===R5&&(G=" Did you wrap a component in React.lazy() more than once?"),B=p4(Z)||Z,Error("Element type is invalid. Received a promise that resolves to: "+B+". Lazy element type must resolve to a class or function."+G)}return G;case 0:return dQ(Z,G,G.type,G.pendingProps,B);case 1:return $=G.type,z=x9($,G.pendingProps),mX(Z,G,$,z,B);case 3:Z:{if(B4(G,G.stateNode.containerInfo),Z===null)throw Error("Should have a current fiber. This is a bug in React.");$=G.pendingProps;var Q=G.memoizedState;z=Q.element,qQ(Z,G),G1(G,$,null,B);var q=G.memoizedState;if($=q.cache,G2(G,$2,$),$!==Q.cache&&G8(G,[$2],B,!0),Z1(),$=q.element,Q.isDehydrated)if(Q={element:$,isDehydrated:!1,cache:q.cache},G.updateQueue.baseState=Q,G.memoizedState=Q,G.flags&256){G=hX(Z,G,$,B);break Z}else if($!==z){z=v(Error("This root received an early update, before anything was able hydrate. Switched the entire root to client rendering."),G),L7(z),G=hX(Z,G,$,B);break Z}else{switch(Z=G.stateNode.containerInfo,Z.nodeType){case 9:Z=Z.body;break;default:Z=Z.nodeName==="HTML"?Z.ownerDocument.body:Z}NZ=F5(Z.firstChild),w2=G,d7=!0,r8=null,y6=!1,D5=null,l5=!0,B=BW(G,null,$,B);for(G.child=B;B;)B.flags=B.flags&-3|4096,B=B.sibling}else{if(HZ(),$===z){G=z8(Z,G,B);break Z}C2(Z,G,$,B)}G=G.child}return G;case 26:return J$(Z,G),Z===null?(B=_j(G.type,null,G.pendingProps,null))?G.memoizedState=B:d7||(B=G.type,Z=G.pendingProps,$=n4(p8.current),$=V$($).createElement(B),$[E2]=G,$[p2]=Z,T2($,B,Z),Q4($),G.stateNode=$):G.memoizedState=_j(G.type,Z.memoizedProps,G.pendingProps,Z.memoizedState),null;case 27:return $4(G),Z===null&&d7&&($=n4(p8.current),z=O4(),$=G.stateNode=Kj(G.type,G.pendingProps,$,z,!1),y6||(z=Zj($,G.type,G.pendingProps,z),z!==null&&(D7(G,0).serverProps=z)),w2=G,l5=!0,z=NZ,u8(G.type)?(QH=z,NZ=F5($.firstChild)):NZ=z),C2(Z,G,G.pendingProps.children,B),J$(Z,G),Z===null&&(G.flags|=4194304),G.child;case 5:return Z===null&&d7&&(Q=O4(),$=wB(G.type,Q.ancestorInfo),z=NZ,(q=!z)||(q=CL(z,G.type,G.pendingProps,l5),q!==null?(G.stateNode=q,y6||(Q=Zj(q,G.type,G.pendingProps,Q),Q!==null&&(D7(G,0).serverProps=Q)),w2=G,NZ=F5(q.firstChild),l5=!1,Q=!0):Q=!1,q=!Q),q&&($&&k4(G,z),zZ(G))),$4(G),z=G.type,Q=G.pendingProps,q=Z!==null?Z.memoizedProps:null,$=Q.children,MJ(z,Q)?$=null:q!==null&&MJ(z,q)&&(G.flags|=32),G.memoizedState!==null&&(z=KQ(Z,G,I3,null,null,B),WB._currentValue=z),J$(Z,G),C2(Z,G,$,B),G.child;case 6:return Z===null&&d7&&(B=G.pendingProps,Z=O4(),$=Z.ancestorInfo.current,B=$!=null?g0(B,$.tag,Z.ancestorInfo.implicitRootScope):!0,Z=NZ,($=!Z)||($=TL(Z,G.pendingProps,l5),$!==null?(G.stateNode=$,w2=G,NZ=null,$=!0):$=!1,$=!$),$&&(B&&k4(G,Z),zZ(G))),null;case 13:return uX(Z,G,B);case 4:return B4(G,G.stateNode.containerInfo),$=G.pendingProps,Z===null?G.child=c9(G,null,$,B):C2(Z,G,$,B),G.child;case 11:return SX(Z,G,G.type,G.pendingProps,B);case 7:return C2(Z,G,G.pendingProps,B),G.child;case 8:return C2(Z,G,G.pendingProps.children,B),G.child;case 12:return G.flags|=4,G.flags|=2048,$=G.stateNode,$.effectDuration=-0,$.passiveEffectDuration=-0,C2(Z,G,G.pendingProps.children,B),G.child;case 10:return $=G.type,z=G.pendingProps,Q=z.value,"value"in z||EW||(EW=!0,console.error("The `value` prop is required for the `<Context.Provider>`. Did you misspell it or forget to pass it?")),G2(G,$,Q),C2(Z,G,z.children,B),G.child;case 9:return z=G.type._context,$=G.pendingProps.children,typeof $!=="function"&&console.error("A context consumer was rendered with multiple children, or a child that isn't a function. A context consumer expects a single child that is a function. If you did pass a function, make sure there is no trailing or leading whitespace around it."),YZ(G),z=r7(z),$=Dq($,z,void 0),G.flags|=1,C2(Z,G,$,B),G.child;case 14:return vX(Z,G,G.type,G.pendingProps,B);case 15:return kX(Z,G,G.type,G.pendingProps,B);case 19:return pX(Z,G,B);case 31:return b3(Z,G,B);case 22:return yX(Z,G,B,G.pendingProps);case 24:return YZ(G),$=r7($2),Z===null?(z=zQ(),z===null&&(z=WZ,Q=o0(),z.pooledCache=Q,B8(Q),Q!==null&&(z.pooledCacheLanes|=B),z=Q),G.memoizedState={parent:$,cache:z},JQ(G),G2(G,$2,z)):((Z.lanes&B)!==0&&(qQ(Z,G),G1(G,null,null,B),Z1()),z=Z.memoizedState,Q=G.memoizedState,z.parent!==$?(z={parent:$,cache:$},G.memoizedState=z,G.lanes===0&&(G.memoizedState=G.updateQueue.baseState=z),G2(G,$2,$)):($=Q.cache,G2(G,$2,$),$!==z.cache&&G8(G,[$2],B,!0))),C2(Z,G,G.pendingProps.children,B),G.child;case 29:throw G.pendingProps}throw Error("Unknown unit of work tag ("+G.tag+"). This error is likely caused by a bug in React. Please file an issue.")}function Q8(Z){Z.flags|=4}function nQ(Z,G,B,$,z){if(G=(Z.mode&QV)!==_7)G=!1;if(G){if(Z.flags|=16777216,(z&335544128)===z)if(Z.stateNode.complete)Z.flags|=8192;else if(NY())Z.flags|=8192;else throw p9=e$,Aq}else Z.flags&=-16777217}function cX(Z,G){if(G.type!=="stylesheet"||(G.state.loading&r5)!==GG)Z.flags&=-16777217;else if(Z.flags|=16777216,!Fj(G))if(NY())Z.flags|=8192;else throw p9=e$,Aq}function H$(Z,G){G!==null&&(Z.flags|=4),Z.flags&16384&&(G=Z.tag!==22?S7():536870912,Z.lanes|=G,o9|=G)}function J1(Z,G){if(!d7)switch(Z.tailMode){case"hidden":G=Z.tail;for(var B=null;G!==null;)G.alternate!==null&&(B=G),G=G.sibling;B===null?Z.tail=null:B.sibling=null;break;case"collapsed":B=Z.tail;for(var $=null;B!==null;)B.alternate!==null&&($=B),B=B.sibling;$===null?G||Z.tail===null?Z.tail=null:Z.tail.sibling=null:$.sibling=null}}function VZ(Z){var G=Z.alternate!==null&&Z.alternate.child===Z.child,B=0,$=0;if(G)if((Z.mode&E7)!==_7){for(var{selfBaseDuration:z,child:Q}=Z;Q!==null;)B|=Q.lanes|Q.childLanes,$|=Q.subtreeFlags&65011712,$|=Q.flags&65011712,z+=Q.treeBaseDuration,Q=Q.sibling;Z.treeBaseDuration=z}else for(z=Z.child;z!==null;)B|=z.lanes|z.childLanes,$|=z.subtreeFlags&65011712,$|=z.flags&65011712,z.return=Z,z=z.sibling;else if((Z.mode&E7)!==_7){z=Z.actualDuration,Q=Z.selfBaseDuration;for(var q=Z.child;q!==null;)B|=q.lanes|q.childLanes,$|=q.subtreeFlags,$|=q.flags,z+=q.actualDuration,Q+=q.treeBaseDuration,q=q.sibling;Z.actualDuration=z,Z.treeBaseDuration=Q}else for(z=Z.child;z!==null;)B|=z.lanes|z.childLanes,$|=z.subtreeFlags,$|=z.flags,z.return=Z,z=z.sibling;return Z.subtreeFlags|=$,Z.childLanes=B,G}function m3(Z,G,B){var $=G.pendingProps;switch(g4(G),G.tag){case 16:case 15:case 0:case 11:case 7:case 8:case 12:case 9:case 14:return VZ(G),null;case 1:return VZ(G),null;case 3:if(B=G.stateNode,$=null,Z!==null&&($=Z.memoizedState.cache),G.memoizedState.cache!==$&&(G.flags|=2048),lZ($2,G),L4(G),B.pendingContext&&(B.context=B.pendingContext,B.pendingContext=null),Z===null||Z.child===null)a7(G)?(LZ(),Q8(G)):Z===null||Z.memoizedState.isDehydrated&&(G.flags&256)===0||(G.flags|=1024,Y7());return VZ(G),null;case 26:var{type:z,memoizedState:Q}=G;return Z===null?(Q8(G),Q!==null?(VZ(G),cX(G,Q)):(VZ(G),nQ(G,z,null,$,B))):Q?Q!==Z.memoizedState?(Q8(G),VZ(G),cX(G,Q)):(VZ(G),G.flags&=-16777217):(Z=Z.memoizedProps,Z!==$&&Q8(G),VZ(G),nQ(G,z,Z,$,B)),null;case 27:if(C4(G),B=n4(p8.current),z=G.type,Z!==null&&G.stateNode!=null)Z.memoizedProps!==$&&Q8(G);else{if(!$){if(G.stateNode===null)throw Error("We must have new props for new mounts. This error is likely caused by a bug in React. Please file an issue.");return VZ(G),null}Z=O4(),a7(G)?ZZ(G,Z):(Z=Kj(z,$,B,Z,!0),G.stateNode=Z,Q8(G))}return VZ(G),null;case 5:if(C4(G),z=G.type,Z!==null&&G.stateNode!=null)Z.memoizedProps!==$&&Q8(G);else{if(!$){if(G.stateNode===null)throw Error("We must have new props for new mounts. This error is likely caused by a bug in React. Please file an issue.");return VZ(G),null}var q=O4();if(a7(G))ZZ(G,q);else{switch(Q=n4(p8.current),wB(z,q.ancestorInfo),q=q.context,Q=V$(Q),q){case M0:Q=Q.createElementNS(lG,z);break;case Az:Q=Q.createElementNS(k$,z);break;default:switch(z){case"svg":Q=Q.createElementNS(lG,z);break;case"math":Q=Q.createElementNS(k$,z);break;case"script":Q=Q.createElement("div"),Q.innerHTML="<script></script>",Q=Q.removeChild(Q.firstChild);break;case"select":Q=typeof $.is==="string"?Q.createElement("select",{is:$.is}):Q.createElement("select"),$.multiple?Q.multiple=!0:$.size&&(Q.size=$.size);break;default:Q=typeof $.is==="string"?Q.createElement(z,{is:$.is}):Q.createElement(z),z.indexOf("-")===-1&&(z!==z.toLowerCase()&&console.error("<%s /> is using incorrect casing. Use PascalCase for React components, or lowercase for HTML elements.",z),Object.prototype.toString.call(Q)!=="[object HTMLUnknownElement]"||$6.call(tW,z)||(tW[z]=!0,console.error("The tag <%s> is unrecognized in this browser. If you meant to render a React component, start its name with an uppercase letter.",z)))}}Q[E2]=G,Q[p2]=$;Z:for(q=G.child;q!==null;){if(q.tag===5||q.tag===6)Q.appendChild(q.stateNode);else if(q.tag!==4&&q.tag!==27&&q.child!==null){q.child.return=q,q=q.child;continue}if(q===G)break Z;for(;q.sibling===null;){if(q.return===null||q.return===G)break Z;q=q.return}q.sibling.return=q.return,q=q.sibling}G.stateNode=Q;Z:switch(T2(Q,z,$),z){case"button":case"input":case"select":case"textarea":$=!!$.autoFocus;break Z;case"img":$=!0;break Z;default:$=!1}$&&Q8(G)}}return VZ(G),nQ(G,G.type,Z===null?null:Z.memoizedProps,G.pendingProps,B),null;case 6:if(Z&&G.stateNode!=null)Z.memoizedProps!==$&&Q8(G);else{if(typeof $!=="string"&&G.stateNode===null)throw Error("We must have new props for new mounts. This error is likely caused by a bug in React. Please file an issue.");if(Z=n4(p8.current),B=O4(),a7(G)){if(Z=G.stateNode,B=G.memoizedProps,z=!y6,$=null,Q=w2,Q!==null)switch(Q.tag){case 3:z&&(z=Yj(Z,B,$),z!==null&&(D7(G,0).serverProps=z));break;case 27:case 5:$=Q.memoizedProps,z&&(z=Yj(Z,B,$),z!==null&&(D7(G,0).serverProps=z))}Z[E2]=G,Z=Z.nodeValue===B||$!==null&&$.suppressHydrationWarning===!0||oY(Z.nodeValue,B)?!0:!1,Z||zZ(G,!0)}else z=B.ancestorInfo.current,z!=null&&g0($,z.tag,B.ancestorInfo.implicitRootScope),Z=V$(Z).createTextNode($),Z[E2]=G,G.stateNode=Z}return VZ(G),null;case 31:if(B=G.memoizedState,Z===null||Z.memoizedState!==null){if($=a7(G),B!==null){if(Z===null){if(!$)throw Error("A dehydrated suspense component was completed without a hydrated node. This is probably a bug in React.");if(Z=G.memoizedState,Z=Z!==null?Z.dehydrated:null,!Z)throw Error("Expected to have a hydrated activity instance. This error is likely caused by a bug in React. Please file an issue.");Z[E2]=G,VZ(G),(G.mode&E7)!==_7&&B!==null&&(Z=G.child,Z!==null&&(G.treeBaseDuration-=Z.treeBaseDuration))}else LZ(),HZ(),(G.flags&128)===0&&(B=G.memoizedState=null),G.flags|=4,VZ(G),(G.mode&E7)!==_7&&B!==null&&(Z=G.child,Z!==null&&(G.treeBaseDuration-=Z.treeBaseDuration));Z=!1}else B=Y7(),Z!==null&&Z.memoizedState!==null&&(Z.memoizedState.hydrationErrors=B),Z=!0;if(!Z){if(G.flags&256)return V5(G),G;return V5(G),null}if((G.flags&128)!==0)throw Error("Client rendering an Activity suspended it again. This is a bug in React.")}return VZ(G),null;case 13:if($=G.memoizedState,Z===null||Z.memoizedState!==null&&Z.memoizedState.dehydrated!==null){if(z=$,Q=a7(G),z!==null&&z.dehydrated!==null){if(Z===null){if(!Q)throw Error("A dehydrated suspense component was completed without a hydrated node. This is probably a bug in React.");if(Q=G.memoizedState,Q=Q!==null?Q.dehydrated:null,!Q)throw Error("Expected to have a hydrated suspense instance. This error is likely caused by a bug in React. Please file an issue.");Q[E2]=G,VZ(G),(G.mode&E7)!==_7&&z!==null&&(z=G.child,z!==null&&(G.treeBaseDuration-=z.treeBaseDuration))}else LZ(),HZ(),(G.flags&128)===0&&(z=G.memoizedState=null),G.flags|=4,VZ(G),(G.mode&E7)!==_7&&z!==null&&(z=G.child,z!==null&&(G.treeBaseDuration-=z.treeBaseDuration));z=!1}else z=Y7(),Z!==null&&Z.memoizedState!==null&&(Z.memoizedState.hydrationErrors=z),z=!0;if(!z){if(G.flags&256)return V5(G),G;return V5(G),null}}if(V5(G),(G.flags&128)!==0)return G.lanes=B,(G.mode&E7)!==_7&&n0(G),G;return B=$!==null,Z=Z!==null&&Z.memoizedState!==null,B&&($=G.child,z=null,$.alternate!==null&&$.alternate.memoizedState!==null&&$.alternate.memoizedState.cachePool!==null&&(z=$.alternate.memoizedState.cachePool.pool),Q=null,$.memoizedState!==null&&$.memoizedState.cachePool!==null&&(Q=$.memoizedState.cachePool.pool),Q!==z&&($.flags|=2048)),B!==Z&&B&&(G.child.flags|=8192),H$(G,G.updateQueue),VZ(G),(G.mode&E7)!==_7&&B&&(Z=G.child,Z!==null&&(G.treeBaseDuration-=Z.treeBaseDuration)),null;case 4:return L4(G),Z===null&&_J(G.stateNode.containerInfo),VZ(G),null;case 10:return lZ(G.type,G),VZ(G),null;case 19:if(d4(rZ,G),$=G.memoizedState,$===null)return VZ(G),null;if(z=(G.flags&128)!==0,Q=$.rendering,Q===null)if(z)J1($,!1);else{if(xZ!==R8||Z!==null&&(Z.flags&128)!==0)for(Z=G.child;Z!==null;){if(Q=lB(Z),Q!==null){G.flags|=128,J1($,!1),Z=Q.updateQueue,G.updateQueue=Z,H$(G,Z),G.subtreeFlags=0,Z=B;for(B=G.child;B!==null;)kB(B,Z),B=B.sibling;return b4(rZ,rZ.current&X0|o1,G),d7&&i(G,$.treeForkCount),G.child}Z=Z.sibling}$.tail!==null&&V2()>Kz&&(G.flags|=128,z=!0,J1($,!1),G.lanes=4194304)}else{if(!z)if(Z=lB(Q),Z!==null){if(G.flags|=128,z=!0,Z=Z.updateQueue,G.updateQueue=Z,H$(G,Z),J1($,!0),$.tail===null&&$.tailMode==="hidden"&&!Q.alternate&&!d7)return VZ(G),null}else 2*V2()-$.renderingStartTime>Kz&&B!==536870912&&(G.flags|=128,z=!0,J1($,!1),G.lanes=4194304);$.isBackwards?(Q.sibling=G.child,G.child=Q):(Z=$.last,Z!==null?Z.sibling=Q:G.child=Q,$.last=Q)}if($.tail!==null)return Z=$.tail,$.rendering=Z,$.tail=Z.sibling,$.renderingStartTime=V2(),Z.sibling=null,B=rZ.current,B=z?B&X0|o1:B&X0,b4(rZ,B,G),d7&&i(G,$.treeForkCount),Z;return VZ(G),null;case 22:case 23:return V5(G),XQ(G),$=G.memoizedState!==null,Z!==null?Z.memoizedState!==null!==$&&(G.flags|=8192):$&&(G.flags|=8192),$?(B&536870912)!==0&&(G.flags&128)===0&&(VZ(G),G.subtreeFlags&6&&(G.flags|=8192)):VZ(G),B=G.updateQueue,B!==null&&H$(G,B.retryQueue),B=null,Z!==null&&Z.memoizedState!==null&&Z.memoizedState.cachePool!==null&&(B=Z.memoizedState.cachePool.pool),$=null,G.memoizedState!==null&&G.memoizedState.cachePool!==null&&($=G.memoizedState.cachePool.pool),$!==B&&(G.flags|=2048),Z!==null&&d4(u9,G),null;case 24:return B=null,Z!==null&&(B=Z.memoizedState.cache),G.memoizedState.cache!==B&&(G.flags|=2048),lZ($2,G),VZ(G),null;case 25:return null;case 30:return null}throw Error("Unknown unit of work tag ("+G.tag+"). This error is likely caused by a bug in React. Please file an issue.")}function h3(Z,G){switch(g4(G),G.tag){case 1:return Z=G.flags,Z&65536?(G.flags=Z&-65537|128,(G.mode&E7)!==_7&&n0(G),G):null;case 3:return lZ($2,G),L4(G),Z=G.flags,(Z&65536)!==0&&(Z&128)===0?(G.flags=Z&-65537|128,G):null;case 26:case 27:case 5:return C4(G),null;case 31:if(G.memoizedState!==null){if(V5(G),G.alternate===null)throw Error("Threw in newly mounted dehydrated component. This is likely a bug in React. Please file an issue.");HZ()}return Z=G.flags,Z&65536?(G.flags=Z&-65537|128,(G.mode&E7)!==_7&&n0(G),G):null;case 13:if(V5(G),Z=G.memoizedState,Z!==null&&Z.dehydrated!==null){if(G.alternate===null)throw Error("Threw in newly mounted dehydrated component. This is likely a bug in React. Please file an issue.");HZ()}return Z=G.flags,Z&65536?(G.flags=Z&-65537|128,(G.mode&E7)!==_7&&n0(G),G):null;case 19:return d4(rZ,G),null;case 4:return L4(G),null;case 10:return lZ(G.type,G),null;case 22:case 23:return V5(G),XQ(G),Z!==null&&d4(u9,G),Z=G.flags,Z&65536?(G.flags=Z&-65537|128,(G.mode&E7)!==_7&&n0(G),G):null;case 24:return lZ($2,G),null;case 25:return null;default:return null}}function lX(Z,G){switch(g4(G),G.tag){case 3:lZ($2,G),L4(G);break;case 26:case 27:case 5:C4(G);break;case 4:L4(G);break;case 31:G.memoizedState!==null&&V5(G);break;case 13:V5(G);break;case 19:d4(rZ,G);break;case 10:lZ(G.type,G);break;case 22:case 23:V5(G),XQ(G),Z!==null&&d4(u9,G);break;case 24:lZ($2,G)}}function N6(Z){return(Z.mode&E7)!==_7}function sX(Z,G){N6(Z)?(M6(),q1(G,Z),R6()):q1(G,Z)}function tQ(Z,G,B){N6(Z)?(M6(),xG(B,Z,G),R6()):xG(B,Z,G)}function q1(Z,G){try{var B=G.updateQueue,$=B!==null?B.lastEffect:null;if($!==null){var z=$.next;B=z;do{if((B.tag&Z)===Z&&($=void 0,(Z&a2)!==Gz&&(O0=!0),$=M4(G,YV,B),(Z&a2)!==Gz&&(O0=!1),$!==void 0&&typeof $!=="function")){var Q=void 0;Q=(B.tag&A5)!==0?"useLayoutEffect":(B.tag&a2)!==0?"useInsertionEffect":"useEffect";var q=void 0;q=$===null?" You returned null. If your effect does not require clean up, return undefined (or nothing).":typeof $.then==="function"?`

It looks like you wrote `+Q+`(async () => ...) or returned a Promise. Instead, write the async function inside your effect and call it immediately:

`+Q+`(() => {
  async function fetchData() {
    // You can await here
    const response = await MyAPI.getData(someId);
    // ...
  }
  fetchData();
}, [someId]); // Or [] if effect doesn't need props or state

Learn more about data fetching with Hooks: https://react.dev/link/hooks-data-fetching`:" You returned: "+$,M4(G,function(X,j){console.error("%s must not return anything besides a function, which is used for clean-up.%s",X,j)},Q,q)}B=B.next}while(B!==z)}}catch(X){GZ(G,G.return,X)}}function xG(Z,G,B){try{var $=G.updateQueue,z=$!==null?$.lastEffect:null;if(z!==null){var Q=z.next;$=Q;do{if(($.tag&Z)===Z){var q=$.inst,X=q.destroy;X!==void 0&&(q.destroy=void 0,(Z&a2)!==Gz&&(O0=!0),z=G,M4(z,jV,z,B,X),(Z&a2)!==Gz&&(O0=!1))}$=$.next}while($!==Q)}}catch(j){GZ(G,G.return,j)}}function aX(Z,G){N6(Z)?(M6(),q1(G,Z),R6()):q1(G,Z)}function eQ(Z,G,B){N6(Z)?(M6(),xG(B,Z,G),R6()):xG(B,Z,G)}function iX(Z){var G=Z.updateQueue;if(G!==null){var B=Z.stateNode;Z.type.defaultProps||"ref"in Z.memoizedProps||W0||(B.props!==Z.memoizedProps&&console.error("Expected %s props to match memoized props before processing the update queue. This might either be because of a bug in React, or because a component reassigns its own `this.props`. Please file an issue.",Y4(Z)||"instance"),B.state!==Z.memoizedState&&console.error("Expected %s state to match memoized state before processing the update queue. This might either be because of a bug in React, or because a component reassigns its own `this.state`. Please file an issue.",Y4(Z)||"instance"));try{M4(Z,rH,G,B)}catch($){GZ(Z,Z.return,$)}}}function u3(Z,G,B){return Z.getSnapshotBeforeUpdate(G,B)}function d3(Z,G){var{memoizedProps:B,memoizedState:$}=G;G=Z.stateNode,Z.type.defaultProps||"ref"in Z.memoizedProps||W0||(G.props!==Z.memoizedProps&&console.error("Expected %s props to match memoized props before getSnapshotBeforeUpdate. This might either be because of a bug in React, or because a component reassigns its own `this.props`. Please file an issue.",Y4(Z)||"instance"),G.state!==Z.memoizedState&&console.error("Expected %s state to match memoized state before getSnapshotBeforeUpdate. This might either be because of a bug in React, or because a component reassigns its own `this.state`. Please file an issue.",Y4(Z)||"instance"));try{var z=x9(Z.type,B),Q=M4(Z,u3,G,z,$);B=wW,Q!==void 0||B.has(Z.type)||(B.add(Z.type),M4(Z,function(){console.error("%s.getSnapshotBeforeUpdate(): A snapshot value (or null) must be returned. You have returned undefined.",Y4(Z))})),G.__reactInternalSnapshotBeforeUpdate=Q}catch(q){GZ(Z,Z.return,q)}}function oX(Z,G,B){B.props=x9(Z.type,Z.memoizedProps),B.state=Z.memoizedState,N6(Z)?(M6(),M4(Z,iK,Z,G,B),R6()):M4(Z,iK,Z,G,B)}function p3(Z){var G=Z.ref;if(G!==null){switch(Z.tag){case 26:case 27:case 5:var B=Z.stateNode;break;case 30:B=Z.stateNode;break;default:B=Z.stateNode}if(typeof G==="function")if(N6(Z))try{M6(),Z.refCleanup=G(B)}finally{R6()}else Z.refCleanup=G(B);else typeof G==="string"?console.error("String refs are no longer supported."):G.hasOwnProperty("current")||console.error("Unexpected ref object provided for %s. Use either a ref-setter function or React.createRef().",Y4(Z)),G.current=B}}function H1(Z,G){try{M4(Z,p3,Z)}catch(B){GZ(Z,G,B)}}function D6(Z,G){var{ref:B,refCleanup:$}=Z;if(B!==null)if(typeof $==="function")try{if(N6(Z))try{M6(),M4(Z,$)}finally{R6(Z)}else M4(Z,$)}catch(z){GZ(Z,G,z)}finally{Z.refCleanup=null,Z=Z.alternate,Z!=null&&(Z.refCleanup=null)}else if(typeof B==="function")try{if(N6(Z))try{M6(),M4(Z,B,null)}finally{R6(Z)}else M4(Z,B,null)}catch(z){GZ(Z,G,z)}else B.current=null}function rX(Z,G,B,$){var z=Z.memoizedProps,Q=z.id,q=z.onCommit;z=z.onRender,G=G===null?"mount":"update",o$&&(G="nested-update"),typeof z==="function"&&z(Q,G,Z.actualDuration,Z.treeBaseDuration,Z.actualStartTime,B),typeof q==="function"&&q(Q,G,$,B)}function c3(Z,G,B,$){var z=Z.memoizedProps;Z=z.id,z=z.onPostCommit,G=G===null?"mount":"update",o$&&(G="nested-update"),typeof z==="function"&&z(Z,G,$,B)}function nX(Z){var{type:G,memoizedProps:B,stateNode:$}=Z;try{M4(Z,_L,$,G,B,Z)}catch(z){GZ(Z,Z.return,z)}}function ZJ(Z,G,B){try{M4(Z,UL,Z.stateNode,Z.type,B,G,Z)}catch($){GZ(Z,Z.return,$)}}function tX(Z){return Z.tag===5||Z.tag===3||Z.tag===26||Z.tag===27&&u8(Z.type)||Z.tag===4}function GJ(Z){Z:for(;;){for(;Z.sibling===null;){if(Z.return===null||tX(Z.return))return null;Z=Z.return}Z.sibling.return=Z.return;for(Z=Z.sibling;Z.tag!==5&&Z.tag!==6&&Z.tag!==18;){if(Z.tag===27&&u8(Z.type))continue Z;if(Z.flags&2)continue Z;if(Z.child===null||Z.tag===4)continue Z;else Z.child.return=Z,Z=Z.child}if(!(Z.flags&2))return Z.stateNode}}function BJ(Z,G,B){var $=Z.tag;if($===5||$===6)Z=Z.stateNode,G?(Qj(B),(B.nodeType===9?B.body:B.nodeName==="HTML"?B.ownerDocument.body:B).insertBefore(Z,G)):(Qj(B),G=B.nodeType===9?B.body:B.nodeName==="HTML"?B.ownerDocument.body:B,G.appendChild(Z),B=B._reactRootContainer,B!==null&&B!==void 0||G.onclick!==null||(G.onclick=Z6));else if($!==4&&($===27&&u8(Z.type)&&(B=Z.stateNode,G=null),Z=Z.child,Z!==null))for(BJ(Z,G,B),Z=Z.sibling;Z!==null;)BJ(Z,G,B),Z=Z.sibling}function X$(Z,G,B){var $=Z.tag;if($===5||$===6)Z=Z.stateNode,G?B.insertBefore(Z,G):B.appendChild(Z);else if($!==4&&($===27&&u8(Z.type)&&(B=Z.stateNode),Z=Z.child,Z!==null))for(X$(Z,G,B),Z=Z.sibling;Z!==null;)X$(Z,G,B),Z=Z.sibling}function l3(Z){for(var G,B=Z.return;B!==null;){if(tX(B)){G=B;break}B=B.return}if(G==null)throw Error("Expected to find a host parent. This error is likely caused by a bug in React. Please file an issue.");switch(G.tag){case 27:G=G.stateNode,B=GJ(Z),X$(Z,B,G);break;case 5:B=G.stateNode,G.flags&32&&(zj(B),G.flags&=-33),G=GJ(Z),X$(Z,G,B);break;case 3:case 4:G=G.stateNode.containerInfo,B=GJ(Z),BJ(Z,B,G);break;default:throw Error("Invalid host parent fiber. This error is likely caused by a bug in React. Please file an issue.")}}function eX(Z){var{stateNode:G,memoizedProps:B}=Z;try{M4(Z,SL,Z.type,B,G,Z)}catch($){GZ(Z,Z.return,$)}}function ZY(Z,G){return G.tag===31?(G=G.memoizedState,Z.memoizedState!==null&&G===null):G.tag===13?(Z=Z.memoizedState,G=G.memoizedState,Z!==null&&Z.dehydrated!==null&&(G===null||G.dehydrated===null)):G.tag===3?Z.memoizedState.isDehydrated&&(G.flags&256)===0:!1}function s3(Z,G){if(Z=Z.containerInfo,BH=wz,Z=W5(Z),o6(Z)){if("selectionStart"in Z)var B={start:Z.selectionStart,end:Z.selectionEnd};else Z:{B=(B=Z.ownerDocument)&&B.defaultView||window;var $=B.getSelection&&B.getSelection();if($&&$.rangeCount!==0){B=$.anchorNode;var{anchorOffset:z,focusNode:Q}=$;$=$.focusOffset;try{B.nodeType,Q.nodeType}catch(R4){B=null;break Z}var q=0,X=-1,j=-1,U=0,k=0,y=Z,P=null;G:for(;;){for(var d;;){if(y!==B||z!==0&&y.nodeType!==3||(X=q+z),y!==Q||$!==0&&y.nodeType!==3||(j=q+$),y.nodeType===3&&(q+=y.nodeValue.length),(d=y.firstChild)===null)break;P=y,y=d}for(;;){if(y===Z)break G;if(P===B&&++U===z&&(X=q),P===Q&&++k===$&&(j=q),(d=y.nextSibling)!==null)break;y=P,P=y.parentNode}y=d}B=X===-1||j===-1?null:{start:X,end:j}}else B=null}B=B||{start:0,end:0}}else B=null;$H={focusedElem:Z,selectionRange:B},wz=!1;for(F2=G;F2!==null;)if(G=F2,Z=G.child,(G.subtreeFlags&1028)!==0&&Z!==null)Z.return=G,F2=Z;else for(;F2!==null;){switch(Z=G=F2,B=Z.alternate,z=Z.flags,Z.tag){case 0:if((z&4)!==0&&(Z=Z.updateQueue,Z=Z!==null?Z.events:null,Z!==null))for(B=0;B<Z.length;B++)z=Z[B],z.ref.impl=z.nextImpl;break;case 11:case 15:break;case 1:(z&1024)!==0&&B!==null&&d3(Z,B);break;case 3:if((z&1024)!==0){if(Z=Z.stateNode.containerInfo,B=Z.nodeType,B===9)NJ(Z);else if(B===1)switch(Z.nodeName){case"HEAD":case"HTML":case"BODY":NJ(Z);break;default:Z.textContent=""}}break;case 5:case 26:case 27:case 6:case 4:case 17:break;default:if((z&1024)!==0)throw Error("This unit of work tag should not have side-effects. This error is likely caused by a bug in React. Please file an issue.")}if(Z=G.sibling,Z!==null){Z.return=G.return,F2=Z;break}F2=G.return}}function GY(Z,G,B){var $=L5(),z=U6(),Q=O6(),q=F6(),X=B.flags;switch(B.tag){case 0:case 11:case 15:P6(Z,B),X&4&&sX(B,A5|i5);break;case 1:if(P6(Z,B),X&4)if(Z=B.stateNode,G===null)B.type.defaultProps||"ref"in B.memoizedProps||W0||(Z.props!==B.memoizedProps&&console.error("Expected %s props to match memoized props before componentDidMount. This might either be because of a bug in React, or because a component reassigns its own `this.props`. Please file an issue.",Y4(B)||"instance"),Z.state!==B.memoizedState&&console.error("Expected %s state to match memoized state before componentDidMount. This might either be because of a bug in React, or because a component reassigns its own `this.state`. Please file an issue.",Y4(B)||"instance")),N6(B)?(M6(),M4(B,Pq,B,Z),R6()):M4(B,Pq,B,Z);else{var j=x9(B.type,G.memoizedProps);G=G.memoizedState,B.type.defaultProps||"ref"in B.memoizedProps||W0||(Z.props!==B.memoizedProps&&console.error("Expected %s props to match memoized props before componentDidUpdate. This might either be because of a bug in React, or because a component reassigns its own `this.props`. Please file an issue.",Y4(B)||"instance"),Z.state!==B.memoizedState&&console.error("Expected %s state to match memoized state before componentDidUpdate. This might either be because of a bug in React, or because a component reassigns its own `this.state`. Please file an issue.",Y4(B)||"instance")),N6(B)?(M6(),M4(B,lK,B,Z,j,G,Z.__reactInternalSnapshotBeforeUpdate),R6()):M4(B,lK,B,Z,j,G,Z.__reactInternalSnapshotBeforeUpdate)}X&64&&iX(B),X&512&&H1(B,B.return);break;case 3:if(G=$8(),P6(Z,B),X&64&&(X=B.updateQueue,X!==null)){if(j=null,B.child!==null)switch(B.child.tag){case 27:case 5:j=B.child.stateNode;break;case 1:j=B.child.stateNode}try{M4(B,rH,X,j)}catch(k){GZ(B,B.return,k)}}Z.effectDuration+=gB(G);break;case 27:G===null&&X&4&&eX(B);case 26:case 5:if(P6(Z,B),G===null){if(X&4)nX(B);else if(X&64){Z=B.type,G=B.memoizedProps,j=B.stateNode;try{M4(B,LL,j,Z,G,B)}catch(k){GZ(B,B.return,k)}}}X&512&&H1(B,B.return);break;case 12:if(X&4){X=$8(),P6(Z,B),Z=B.stateNode,Z.effectDuration+=r0(X);try{M4(B,rX,B,G,n8,Z.effectDuration)}catch(k){GZ(B,B.return,k)}}else P6(Z,B);break;case 31:P6(Z,B),X&4&&zY(Z,B);break;case 13:P6(Z,B),X&4&&QY(Z,B),X&64&&(Z=B.memoizedState,Z!==null&&(Z=Z.dehydrated,Z!==null&&(X=GL.bind(null,B),EL(Z,X))));break;case 22:if(X=B.memoizedState!==null||F8,!X){G=G!==null&&G.memoizedState!==null||q2,j=F8;var U=q2;F8=X,(q2=G)&&!U?(A6(Z,B,(B.subtreeFlags&8772)!==0),(B.mode&E7)!==_7&&0<=G7&&0<=j7&&0.05<j7-G7&&B7(B,G7,j7)):P6(Z,B),F8=j,q2=U}break;case 30:break;default:P6(Z,B)}(B.mode&E7)!==_7&&0<=G7&&0<=j7&&((fZ||0.05<IZ)&&b5(B,G7,j7,IZ,TZ),B.alternate===null&&B.return!==null&&B.return.alternate!==null&&0.05<j7-G7&&(ZY(B.return.alternate,B.return)||v2(B,G7,j7,"Mount"))),U5($),V6(z),TZ=Q,fZ=q}function BY(Z){var G=Z.alternate;G!==null&&(Z.alternate=null,BY(G)),Z.child=null,Z.deletions=null,Z.sibling=null,Z.tag===5&&(G=Z.stateNode,G!==null&&H4(G)),Z.stateNode=null,Z._debugOwner=null,Z.return=null,Z.dependencies=null,Z.memoizedProps=null,Z.memoizedState=null,Z.pendingProps=null,Z.stateNode=null,Z.updateQueue=null}function J8(Z,G,B){for(B=B.child;B!==null;)$Y(Z,G,B),B=B.sibling}function $Y(Z,G,B){if(y2&&typeof y2.onCommitFiberUnmount==="function")try{y2.onCommitFiberUnmount(pG,B)}catch(U){x6||(x6=!0,console.error("React instrumentation encountered an error: %o",U))}var $=L5(),z=U6(),Q=O6(),q=F6();switch(B.tag){case 26:q2||D6(B,G),J8(Z,G,B),B.memoizedState?B.memoizedState.count--:B.stateNode&&(Z=B.stateNode,Z.parentNode.removeChild(Z));break;case 27:q2||D6(B,G);var X=H2,j=q5;u8(B.type)&&(H2=B.stateNode,q5=!1),J8(Z,G,B),M4(B,V1,B.stateNode),H2=X,q5=j;break;case 5:q2||D6(B,G);case 6:if(X=H2,j=q5,H2=null,J8(Z,G,B),H2=X,q5=j,H2!==null)if(q5)try{M4(B,FL,H2,B.stateNode)}catch(U){GZ(B,G,U)}else try{M4(B,OL,H2,B.stateNode)}catch(U){GZ(B,G,U)}break;case 18:H2!==null&&(q5?(Z=H2,Jj(Z.nodeType===9?Z.body:Z.nodeName==="HTML"?Z.ownerDocument.body:Z,B.stateNode),mG(Z)):Jj(H2,B.stateNode));break;case 4:X=H2,j=q5,H2=B.stateNode.containerInfo,q5=!0,J8(Z,G,B),H2=X,q5=j;break;case 0:case 11:case 14:case 15:xG(a2,B,G),q2||tQ(B,G,A5),J8(Z,G,B);break;case 1:q2||(D6(B,G),X=B.stateNode,typeof X.componentWillUnmount==="function"&&oX(B,G,X)),J8(Z,G,B);break;case 21:J8(Z,G,B);break;case 22:q2=(X=q2)||B.memoizedState!==null,J8(Z,G,B),q2=X;break;default:J8(Z,G,B)}(B.mode&E7)!==_7&&0<=G7&&0<=j7&&(fZ||0.05<IZ)&&b5(B,G7,j7,IZ,TZ),U5($),V6(z),TZ=Q,fZ=q}function zY(Z,G){if(G.memoizedState===null&&(Z=G.alternate,Z!==null&&(Z=Z.memoizedState,Z!==null))){Z=Z.dehydrated;try{M4(G,IL,Z)}catch(B){GZ(G,G.return,B)}}}function QY(Z,G){if(G.memoizedState===null&&(Z=G.alternate,Z!==null&&(Z=Z.memoizedState,Z!==null&&(Z=Z.dehydrated,Z!==null))))try{M4(G,xL,Z)}catch(B){GZ(G,G.return,B)}}function a3(Z){switch(Z.tag){case 31:case 13:case 19:var G=Z.stateNode;return G===null&&(G=Z.stateNode=new IW),G;case 22:return Z=Z.stateNode,G=Z._retryCache,G===null&&(G=Z._retryCache=new IW),G;default:throw Error("Unexpected Suspense handler tag ("+Z.tag+"). This is a bug in React.")}}function Y$(Z,G){var B=a3(Z);G.forEach(function($){if(!B.has($)){if(B.add($),S6)if(_0!==null&&L0!==null)K1(L0,_0);else throw Error("Expected finished root and lanes to be set. This is a bug in React.");var z=BL.bind(null,Z,$);$.then(z,z)}})}function Q5(Z,G){var B=G.deletions;if(B!==null)for(var $=0;$<B.length;$++){var z=Z,Q=G,q=B[$],X=L5(),j=Q;Z:for(;j!==null;){switch(j.tag){case 27:if(u8(j.type)){H2=j.stateNode,q5=!1;break Z}break;case 5:H2=j.stateNode,q5=!1;break Z;case 3:case 4:H2=j.stateNode.containerInfo,q5=!0;break Z}j=j.return}if(H2===null)throw Error("Expected to find a host parent. This error is likely caused by a bug in React. Please file an issue.");$Y(z,Q,q),H2=null,q5=!1,(q.mode&E7)!==_7&&0<=G7&&0<=j7&&0.05<j7-G7&&v2(q,G7,j7,"Unmount"),U5(X),z=q,Q=z.alternate,Q!==null&&(Q.return=null),z.return=null}if(G.subtreeFlags&13886)for(G=G.child;G!==null;)JY(G,Z),G=G.sibling}function JY(Z,G){var B=L5(),$=U6(),z=O6(),Q=F6(),q=Z.alternate,X=Z.flags;switch(Z.tag){case 0:case 11:case 14:case 15:Q5(G,Z),J5(Z),X&4&&(xG(a2|i5,Z,Z.return),q1(a2|i5,Z),tQ(Z,Z.return,A5|i5));break;case 1:if(Q5(G,Z),J5(Z),X&512&&(q2||q===null||D6(q,q.return)),X&64&&F8&&(X=Z.updateQueue,X!==null&&(q=X.callbacks,q!==null))){var j=X.shared.hiddenCallbacks;X.shared.hiddenCallbacks=j===null?q:j.concat(q)}break;case 26:if(j=H6,Q5(G,Z),J5(Z),X&512&&(q2||q===null||D6(q,q.return)),X&4){var U=q!==null?q.memoizedState:null;if(X=Z.memoizedState,q===null)if(X===null)if(Z.stateNode===null){Z:{X=Z.type,q=Z.memoizedProps,j=j.ownerDocument||j;G:switch(X){case"title":if(U=j.getElementsByTagName("title")[0],!U||U[P1]||U[E2]||U.namespaceURI===lG||U.hasAttribute("itemprop"))U=j.createElement(X),j.head.insertBefore(U,j.querySelector("head > title"));T2(U,X,q),U[E2]=Z,Q4(U),X=U;break Z;case"link":var k=Vj("link","href",j).get(X+(q.href||""));if(k){for(var y=0;y<k.length;y++)if(U=k[y],U.getAttribute("href")===(q.href==null||q.href===""?null:q.href)&&U.getAttribute("rel")===(q.rel==null?null:q.rel)&&U.getAttribute("title")===(q.title==null?null:q.title)&&U.getAttribute("crossorigin")===(q.crossOrigin==null?null:q.crossOrigin)){k.splice(y,1);break G}}U=j.createElement(X),T2(U,X,q),j.head.appendChild(U);break;case"meta":if(k=Vj("meta","content",j).get(X+(q.content||""))){for(y=0;y<k.length;y++)if(U=k[y],s7(q.content,"content"),U.getAttribute("content")===(q.content==null?null:""+q.content)&&U.getAttribute("name")===(q.name==null?null:q.name)&&U.getAttribute("property")===(q.property==null?null:q.property)&&U.getAttribute("http-equiv")===(q.httpEquiv==null?null:q.httpEquiv)&&U.getAttribute("charset")===(q.charSet==null?null:q.charSet)){k.splice(y,1);break G}}U=j.createElement(X),T2(U,X,q),j.head.appendChild(U);break;default:throw Error('getNodesForType encountered a type it did not expect: "'+X+'". This is a bug in React.')}U[E2]=Z,Q4(U),X=U}Z.stateNode=X}else Oj(j,Z.type,Z.stateNode);else Z.stateNode=Uj(j,X,Z.memoizedProps);else U!==X?(U===null?q.stateNode!==null&&(q=q.stateNode,q.parentNode.removeChild(q)):U.count--,X===null?Oj(j,Z.type,Z.stateNode):Uj(j,X,Z.memoizedProps)):X===null&&Z.stateNode!==null&&ZJ(Z,Z.memoizedProps,q.memoizedProps)}break;case 27:Q5(G,Z),J5(Z),X&512&&(q2||q===null||D6(q,q.return)),q!==null&&X&4&&ZJ(Z,Z.memoizedProps,q.memoizedProps);break;case 5:if(Q5(G,Z),J5(Z),X&512&&(q2||q===null||D6(q,q.return)),Z.flags&32){j=Z.stateNode;try{M4(Z,zj,j)}catch(v4){GZ(Z,Z.return,v4)}}X&4&&Z.stateNode!=null&&(j=Z.memoizedProps,ZJ(Z,j,q!==null?q.memoizedProps:j)),X&1024&&(bq=!0,Z.type!=="form"&&console.error("Unexpected host component type. Expected a form. This is a bug in React."));break;case 6:if(Q5(G,Z),J5(Z),X&4){if(Z.stateNode===null)throw Error("This should have a text node initialized. This error is likely caused by a bug in React. Please file an issue.");X=Z.memoizedProps,q=q!==null?q.memoizedProps:X,j=Z.stateNode;try{M4(Z,VL,j,q,X)}catch(v4){GZ(Z,Z.return,v4)}}break;case 3:if(j=$8(),Cz=null,U=H6,H6=O$(G.containerInfo),Q5(G,Z),H6=U,J5(Z),X&4&&q!==null&&q.memoizedState.isDehydrated)try{M4(Z,wL,G.containerInfo)}catch(v4){GZ(Z,Z.return,v4)}bq&&(bq=!1,qY(Z)),G.effectDuration+=gB(j);break;case 4:X=H6,H6=O$(Z.stateNode.containerInfo),Q5(G,Z),J5(Z),H6=X;break;case 12:X=$8(),Q5(G,Z),J5(Z),Z.stateNode.effectDuration+=r0(X);break;case 31:Q5(G,Z),J5(Z),X&4&&(X=Z.updateQueue,X!==null&&(Z.updateQueue=null,Y$(Z,X)));break;case 13:Q5(G,Z),J5(Z),Z.child.flags&8192&&Z.memoizedState!==null!==(q!==null&&q.memoizedState!==null)&&(jz=V2()),X&4&&(X=Z.updateQueue,X!==null&&(Z.updateQueue=null,Y$(Z,X)));break;case 22:j=Z.memoizedState!==null;var P=q!==null&&q.memoizedState!==null,d=F8,R4=q2;if(F8=d||j,q2=R4||P,Q5(G,Z),q2=R4,F8=d,P&&!j&&!d&&!R4&&(Z.mode&E7)!==_7&&0<=G7&&0<=j7&&0.05<j7-G7&&B7(Z,G7,j7),J5(Z),X&8192)Z:for(G=Z.stateNode,G._visibility=j?G._visibility&~v1:G._visibility|v1,!j||q===null||P||F8||q2||(S9(Z),(Z.mode&E7)!==_7&&0<=G7&&0<=j7&&0.05<j7-G7&&v2(Z,G7,j7,"Disconnect")),q=null,G=Z;;){if(G.tag===5||G.tag===26){if(q===null){P=q=G;try{U=P.stateNode,j?M4(P,ML,U):M4(P,PL,P.stateNode,P.memoizedProps)}catch(v4){GZ(P,P.return,v4)}}}else if(G.tag===6){if(q===null){P=G;try{k=P.stateNode,j?M4(P,NL,k):M4(P,AL,k,P.memoizedProps)}catch(v4){GZ(P,P.return,v4)}}}else if(G.tag===18){if(q===null){P=G;try{y=P.stateNode,j?M4(P,RL,y):M4(P,DL,P.stateNode)}catch(v4){GZ(P,P.return,v4)}}}else if((G.tag!==22&&G.tag!==23||G.memoizedState===null||G===Z)&&G.child!==null){G.child.return=G,G=G.child;continue}if(G===Z)break Z;for(;G.sibling===null;){if(G.return===null||G.return===Z)break Z;q===G&&(q=null),G=G.return}q===G&&(q=null),G.sibling.return=G.return,G=G.sibling}X&4&&(X=Z.updateQueue,X!==null&&(q=X.retryQueue,q!==null&&(X.retryQueue=null,Y$(Z,q))));break;case 19:Q5(G,Z),J5(Z),X&4&&(X=Z.updateQueue,X!==null&&(Z.updateQueue=null,Y$(Z,X)));break;case 30:break;case 21:break;default:Q5(G,Z),J5(Z)}(Z.mode&E7)!==_7&&0<=G7&&0<=j7&&((fZ||0.05<IZ)&&b5(Z,G7,j7,IZ,TZ),Z.alternate===null&&Z.return!==null&&Z.return.alternate!==null&&0.05<j7-G7&&(ZY(Z.return.alternate,Z.return)||v2(Z,G7,j7,"Mount"))),U5(B),V6($),TZ=z,fZ=Q}function J5(Z){var G=Z.flags;if(G&2){try{M4(Z,l3,Z)}catch(B){GZ(Z,Z.return,B)}Z.flags&=-3}G&4096&&(Z.flags&=-4097)}function qY(Z){if(Z.subtreeFlags&1024)for(Z=Z.child;Z!==null;){var G=Z;qY(G),G.tag===5&&G.flags&1024&&G.stateNode.reset(),Z=Z.sibling}}function P6(Z,G){if(G.subtreeFlags&8772)for(G=G.child;G!==null;)GY(Z,G.alternate,G),G=G.sibling}function HY(Z){var G=L5(),B=U6(),$=O6(),z=F6();switch(Z.tag){case 0:case 11:case 14:case 15:tQ(Z,Z.return,A5),S9(Z);break;case 1:D6(Z,Z.return);var Q=Z.stateNode;typeof Q.componentWillUnmount==="function"&&oX(Z,Z.return,Q),S9(Z);break;case 27:M4(Z,V1,Z.stateNode);case 26:case 5:D6(Z,Z.return),S9(Z);break;case 22:Z.memoizedState===null&&S9(Z);break;case 30:S9(Z);break;default:S9(Z)}(Z.mode&E7)!==_7&&0<=G7&&0<=j7&&(fZ||0.05<IZ)&&b5(Z,G7,j7,IZ,TZ),U5(G),V6(B),TZ=$,fZ=z}function S9(Z){for(Z=Z.child;Z!==null;)HY(Z),Z=Z.sibling}function XY(Z,G,B,$){var z=L5(),Q=U6(),q=O6(),X=F6(),j=B.flags;switch(B.tag){case 0:case 11:case 15:A6(Z,B,$),sX(B,A5);break;case 1:if(A6(Z,B,$),G=B.stateNode,typeof G.componentDidMount==="function"&&M4(B,Pq,B,G),G=B.updateQueue,G!==null){Z=B.stateNode;try{M4(B,w3,G,Z)}catch(U){GZ(B,B.return,U)}}$&&j&64&&iX(B),H1(B,B.return);break;case 27:eX(B);case 26:case 5:A6(Z,B,$),$&&G===null&&j&4&&nX(B),H1(B,B.return);break;case 12:if($&&j&4){j=$8(),A6(Z,B,$),$=B.stateNode,$.effectDuration+=r0(j);try{M4(B,rX,B,G,n8,$.effectDuration)}catch(U){GZ(B,B.return,U)}}else A6(Z,B,$);break;case 31:A6(Z,B,$),$&&j&4&&zY(Z,B);break;case 13:A6(Z,B,$),$&&j&4&&QY(Z,B);break;case 22:B.memoizedState===null&&A6(Z,B,$),H1(B,B.return);break;case 30:break;default:A6(Z,B,$)}(B.mode&E7)!==_7&&0<=G7&&0<=j7&&(fZ||0.05<IZ)&&b5(B,G7,j7,IZ,TZ),U5(z),V6(Q),TZ=q,fZ=X}function A6(Z,G,B){B=B&&(G.subtreeFlags&8772)!==0;for(G=G.child;G!==null;)XY(Z,G.alternate,G,B),G=G.sibling}function $J(Z,G){var B=null;Z!==null&&Z.memoizedState!==null&&Z.memoizedState.cachePool!==null&&(B=Z.memoizedState.cachePool.pool),Z=null,G.memoizedState!==null&&G.memoizedState.cachePool!==null&&(Z=G.memoizedState.cachePool.pool),Z!==B&&(Z!=null&&B8(Z),B!=null&&T9(B))}function zJ(Z,G){Z=null,G.alternate!==null&&(Z=G.alternate.memoizedState.cache),G=G.memoizedState.cache,G!==Z&&(B8(G),Z!=null&&T9(Z))}function B6(Z,G,B,$,z){if(G.subtreeFlags&10256||G.actualDuration!==0&&(G.alternate===null||G.alternate.child!==G.child))for(G=G.child;G!==null;){var Q=G.sibling;YY(Z,G,B,$,Q!==null?Q.actualStartTime:z),G=Q}}function YY(Z,G,B,$,z){var Q=L5(),q=U6(),X=O6(),j=F6(),U=a8,k=G.flags;switch(G.tag){case 0:case 11:case 15:(G.mode&E7)!==_7&&0<G.actualStartTime&&(G.flags&1)!==0&&x8(G,G.actualStartTime,z,K2,B),B6(Z,G,B,$,z),k&2048&&aX(G,i2|i5);break;case 1:(G.mode&E7)!==_7&&0<G.actualStartTime&&((G.flags&128)!==0?FG(G,G.actualStartTime,z,[]):(G.flags&1)!==0&&x8(G,G.actualStartTime,z,K2,B)),B6(Z,G,B,$,z);break;case 3:var y=$8(),P=K2;K2=G.alternate!==null&&G.alternate.memoizedState.isDehydrated&&(G.flags&256)===0,B6(Z,G,B,$,z),K2=P,k&2048&&(B=null,G.alternate!==null&&(B=G.alternate.memoizedState.cache),$=G.memoizedState.cache,$!==B&&(B8($),B!=null&&T9(B))),Z.passiveEffectDuration+=gB(y);break;case 12:if(k&2048){k=$8(),B6(Z,G,B,$,z),Z=G.stateNode,Z.passiveEffectDuration+=r0(k);try{M4(G,c3,G,G.alternate,n8,Z.passiveEffectDuration)}catch(d){GZ(G,G.return,d)}}else B6(Z,G,B,$,z);break;case 31:k=K2,y=G.alternate!==null?G.alternate.memoizedState:null,P=G.memoizedState,y!==null&&P===null?(P=G.deletions,P!==null&&0<P.length&&P[0].tag===18?(K2=!1,y=y.hydrationErrors,y!==null&&FG(G,G.actualStartTime,z,y)):K2=!0):K2=!1,B6(Z,G,B,$,z),K2=k;break;case 13:k=K2,y=G.alternate!==null?G.alternate.memoizedState:null,P=G.memoizedState,y===null||y.dehydrated===null||P!==null&&P.dehydrated!==null?K2=!1:(P=G.deletions,P!==null&&0<P.length&&P[0].tag===18?(K2=!1,y=y.hydrationErrors,y!==null&&FG(G,G.actualStartTime,z,y)):K2=!0),B6(Z,G,B,$,z),K2=k;break;case 23:break;case 22:P=G.stateNode,y=G.alternate,G.memoizedState!==null?P._visibility&X8?B6(Z,G,B,$,z):X1(Z,G,B,$,z):P._visibility&X8?B6(Z,G,B,$,z):(P._visibility|=X8,SG(Z,G,B,$,(G.subtreeFlags&10256)!==0||G.actualDuration!==0&&(G.alternate===null||G.alternate.child!==G.child),z),(G.mode&E7)===_7||K2||(Z=G.actualStartTime,0<=Z&&0.05<z-Z&&B7(G,Z,z),0<=G7&&0<=j7&&0.05<j7-G7&&B7(G,G7,j7))),k&2048&&$J(y,G);break;case 24:B6(Z,G,B,$,z),k&2048&&zJ(G.alternate,G);break;default:B6(Z,G,B,$,z)}if((G.mode&E7)!==_7){if(Z=!K2&&G.alternate===null&&G.return!==null&&G.return.alternate!==null)B=G.actualStartTime,0<=B&&0.05<z-B&&v2(G,B,z,"Mount");0<=G7&&0<=j7&&((fZ||0.05<IZ)&&b5(G,G7,j7,IZ,TZ),Z&&0.05<j7-G7&&v2(G,G7,j7,"Mount"))}U5(Q),V6(q),TZ=X,fZ=j,a8=U}function SG(Z,G,B,$,z,Q){z=z&&((G.subtreeFlags&10256)!==0||G.actualDuration!==0&&(G.alternate===null||G.alternate.child!==G.child));for(G=G.child;G!==null;){var q=G.sibling;jY(Z,G,B,$,z,q!==null?q.actualStartTime:Q),G=q}}function jY(Z,G,B,$,z,Q){var q=L5(),X=U6(),j=O6(),U=F6(),k=a8;z&&(G.mode&E7)!==_7&&0<G.actualStartTime&&(G.flags&1)!==0&&x8(G,G.actualStartTime,Q,K2,B);var y=G.flags;switch(G.tag){case 0:case 11:case 15:SG(Z,G,B,$,z,Q),aX(G,i2);break;case 23:break;case 22:var P=G.stateNode;G.memoizedState!==null?P._visibility&X8?SG(Z,G,B,$,z,Q):X1(Z,G,B,$,Q):(P._visibility|=X8,SG(Z,G,B,$,z,Q)),z&&y&2048&&$J(G.alternate,G);break;case 24:SG(Z,G,B,$,z,Q),z&&y&2048&&zJ(G.alternate,G);break;default:SG(Z,G,B,$,z,Q)}(G.mode&E7)!==_7&&0<=G7&&0<=j7&&(fZ||0.05<IZ)&&b5(G,G7,j7,IZ,TZ),U5(q),V6(X),TZ=j,fZ=U,a8=k}function X1(Z,G,B,$,z){if(G.subtreeFlags&10256||G.actualDuration!==0&&(G.alternate===null||G.alternate.child!==G.child))for(var Q=G.child;Q!==null;){G=Q.sibling;var q=Z,X=B,j=$,U=G!==null?G.actualStartTime:z,k=a8;(Q.mode&E7)!==_7&&0<Q.actualStartTime&&(Q.flags&1)!==0&&x8(Q,Q.actualStartTime,U,K2,X);var y=Q.flags;switch(Q.tag){case 22:X1(q,Q,X,j,U),y&2048&&$J(Q.alternate,Q);break;case 24:X1(q,Q,X,j,U),y&2048&&zJ(Q.alternate,Q);break;default:X1(q,Q,X,j,U)}a8=k,Q=G}}function vG(Z,G,B){if(Z.subtreeFlags&e1)for(Z=Z.child;Z!==null;)KY(Z,G,B),Z=Z.sibling}function KY(Z,G,B){switch(Z.tag){case 26:vG(Z,G,B),Z.flags&e1&&Z.memoizedState!==null&&yL(B,H6,Z.memoizedState,Z.memoizedProps);break;case 5:vG(Z,G,B);break;case 3:case 4:var $=H6;H6=O$(Z.stateNode.containerInfo),vG(Z,G,B),H6=$;break;case 22:Z.memoizedState===null&&($=Z.alternate,$!==null&&$.memoizedState!==null?($=e1,e1=16777216,vG(Z,G,B),e1=$):vG(Z,G,B));break;default:vG(Z,G,B)}}function WY(Z){var G=Z.alternate;if(G!==null&&(Z=G.child,Z!==null)){G.child=null;do G=Z.sibling,Z.sibling=null,Z=G;while(Z!==null)}}function Y1(Z){var G=Z.deletions;if((Z.flags&16)!==0){if(G!==null)for(var B=0;B<G.length;B++){var $=G[B],z=L5();F2=$,UY($,Z),($.mode&E7)!==_7&&0<=G7&&0<=j7&&0.05<j7-G7&&v2($,G7,j7,"Unmount"),U5(z)}WY(Z)}if(Z.subtreeFlags&10256)for(Z=Z.child;Z!==null;)_Y(Z),Z=Z.sibling}function _Y(Z){var G=L5(),B=U6(),$=O6(),z=F6();switch(Z.tag){case 0:case 11:case 15:Y1(Z),Z.flags&2048&&eQ(Z,Z.return,i2|i5);break;case 3:var Q=$8();Y1(Z),Z.stateNode.passiveEffectDuration+=gB(Q);break;case 12:Q=$8(),Y1(Z),Z.stateNode.passiveEffectDuration+=r0(Q);break;case 22:Q=Z.stateNode,Z.memoizedState!==null&&Q._visibility&X8&&(Z.return===null||Z.return.tag!==13)?(Q._visibility&=~X8,j$(Z),(Z.mode&E7)!==_7&&0<=G7&&0<=j7&&0.05<j7-G7&&v2(Z,G7,j7,"Disconnect")):Y1(Z);break;default:Y1(Z)}(Z.mode&E7)!==_7&&0<=G7&&0<=j7&&(fZ||0.05<IZ)&&b5(Z,G7,j7,IZ,TZ),U5(G),V6(B),fZ=z,TZ=$}function j$(Z){var G=Z.deletions;if((Z.flags&16)!==0){if(G!==null)for(var B=0;B<G.length;B++){var $=G[B],z=L5();F2=$,UY($,Z),($.mode&E7)!==_7&&0<=G7&&0<=j7&&0.05<j7-G7&&v2($,G7,j7,"Unmount"),U5(z)}WY(Z)}for(Z=Z.child;Z!==null;)LY(Z),Z=Z.sibling}function LY(Z){var G=L5(),B=U6(),$=O6(),z=F6();switch(Z.tag){case 0:case 11:case 15:eQ(Z,Z.return,i2),j$(Z);break;case 22:var Q=Z.stateNode;Q._visibility&X8&&(Q._visibility&=~X8,j$(Z));break;default:j$(Z)}(Z.mode&E7)!==_7&&0<=G7&&0<=j7&&(fZ||0.05<IZ)&&b5(Z,G7,j7,IZ,TZ),U5(G),V6(B),fZ=z,TZ=$}function UY(Z,G){for(;F2!==null;){var B=F2,$=B,z=G,Q=L5(),q=U6(),X=O6(),j=F6();switch($.tag){case 0:case 11:case 15:eQ($,z,i2);break;case 23:case 22:$.memoizedState!==null&&$.memoizedState.cachePool!==null&&(z=$.memoizedState.cachePool.pool,z!=null&&B8(z));break;case 24:T9($.memoizedState.cache)}if(($.mode&E7)!==_7&&0<=G7&&0<=j7&&(fZ||0.05<IZ)&&b5($,G7,j7,IZ,TZ),U5(Q),V6(q),fZ=j,TZ=X,$=B.child,$!==null)$.return=B,F2=$;else Z:for(B=Z;F2!==null;){if($=F2,Q=$.sibling,q=$.return,BY($),$===B){F2=null;break Z}if(Q!==null){Q.return=q,F2=Q;break Z}F2=q}}}function i3(){UV.forEach(function(Z){return Z()})}function VY(){var Z=typeof IS_REACT_ACT_ENVIRONMENT<"u"?IS_REACT_ACT_ENVIRONMENT:void 0;return Z||l.actQueue===null||console.error("The current testing environment is not configured to support act(...)"),Z}function O5(Z){if((i7&W2)!==R2&&I7!==0)return I7&-I7;var G=l.T;return G!==null?(G._updatedFibers||(G._updatedFibers=new Set),G._updatedFibers.add(Z),KJ()):E()}function OY(){if(X5===0)if((I7&536870912)===0||d7){var Z=I$;I$<<=1,(I$&3932160)===0&&(I$=262144),X5=Z}else X5=536870912;return Z=P5.current,Z!==null&&(Z.flags|=32),X5}function bZ(Z,G,B){if(O0&&console.error("useInsertionEffect must not schedule updates."),iq&&(Lz=!0),Z===WZ&&(JZ===a9||JZ===i9)||Z.cancelPendingCommit!==null)yG(Z,0),m8(Z,I7,X5,!1);if(o4(Z,B),(i7&W2)!==R2&&Z===WZ){if(I6)switch(G.tag){case 0:case 11:case 15:Z=x7&&Y4(x7)||"Unknown",lW.has(Z)||(lW.add(Z),G=Y4(G)||"Unknown",console.error("Cannot update a component (`%s`) while rendering a different component (`%s`). To locate the bad setState() call inside `%s`, follow the stack trace as described in https://react.dev/link/setstate-in-render",G,Z,Z));break;case 1:cW||(console.error("Cannot update during an existing state transition (such as within `render`). Render methods should be a pure function of props and state."),cW=!0)}}else S6&&m4(Z,G,B),zL(G),Z===WZ&&((i7&W2)===R2&&(J9|=B),xZ===$9&&m8(Z,I7,X5,!1)),C6(Z)}function FY(Z,G,B){if((i7&(W2|C5))!==R2)throw Error("Should not already be working.");if(I7!==0&&x7!==null){var $=x7,z=V2();switch(bK){case BB:case a9:var Q=m1;MZ&&(($=$._debugTask)?$.run(console.timeStamp.bind(console,"Suspended",Q,z,h5,void 0,"primary-light")):console.timeStamp("Suspended",Q,z,h5,void 0,"primary-light"));break;case i9:Q=m1,MZ&&(($=$._debugTask)?$.run(console.timeStamp.bind(console,"Action",Q,z,h5,void 0,"primary-light")):console.timeStamp("Action",Q,z,h5,void 0,"primary-light"));break;default:MZ&&($=z-m1,3>$||console.timeStamp("Blocked",m1,z,h5,void 0,5>$?"primary-light":10>$?"primary":100>$?"primary-dark":"error"))}}Q=(B=!B&&(G&127)===0&&(G&Z.expiredLanes)===0||b7(Z,G))?r3(Z,G):JJ(Z,G,!0);var q=B;do{if(Q===R8){U0&&!B&&m8(Z,G,0,!1),G=JZ,m1=z2(),bK=G;break}else{if($=V2(),z=Z.current.alternate,q&&!o3(z)){S2(G),z=O2,Q=$,!MZ||Q<=z||(aZ?aZ.run(console.timeStamp.bind(console,"Teared Render",z,Q,m7,y7,"error")):console.timeStamp("Teared Render",z,Q,m7,y7,"error")),v9(G,$),Q=JJ(Z,G,!1),q=!1;continue}if(Q===s9){if(q=G,Z.errorRecoveryDisabledLanes&q)var X=0;else X=Z.pendingLanes&-536870913,X=X!==0?X:X&536870912?536870912:0;if(X!==0){S2(G),RG(O2,$,G,aZ),v9(G,$),G=X;Z:{$=Z,Q=q,q=zB;var j=$.current.memoizedState.isDehydrated;if(j&&(yG($,X).flags|=256),X=JJ($,X,!1),X!==s9){if(hq&&!j){$.errorRecoveryDisabledLanes|=Q,J9|=Q,Q=$9;break Z}$=o2,o2=q,$!==null&&(o2===null?o2=$:o2.push.apply(o2,$))}Q=X}if(q=!1,Q!==s9)continue;else $=V2()}}if(Q===GB){S2(G),RG(O2,$,G,aZ),v9(G,$),yG(Z,0),m8(Z,G,0,!0);break}Z:{switch(B=Z,Q){case R8:case GB:throw Error("Root did not complete. This is a bug in React.");case $9:if((G&4194048)!==G)break;case qz:S2(G),r6(O2,$,G,aZ),v9(G,$),z=G,(z&127)!==0?s$=$:(z&4194048)!==0&&(a$=$),m8(B,G,X5,!z9);break Z;case s9:o2=null;break;case Jz:case xW:break;default:throw Error("Unknown root exit status.")}if(l.actQueue!==null)qJ(B,z,G,o2,QB,Yz,X5,J9,o9,Q,null,null,O2,$);else{if((G&62914560)===G&&(q=jz+kW-V2(),10<q)){if(m8(B,G,X5,!z9),t4(B,0,!0)!==0)break Z;X6=G,B.timeoutHandle=eW(RY.bind(null,B,z,o2,QB,Yz,G,X5,J9,o9,z9,Q,"Throttled",O2,$),q);break Z}RY(B,z,o2,QB,Yz,G,X5,J9,o9,z9,Q,null,O2,$)}}}break}while(1);C6(Z)}function RY(Z,G,B,$,z,Q,q,X,j,U,k,y,P,d){Z.timeoutHandle=ZG;var R4=G.subtreeFlags,v4=null;if(R4&8192||(R4&16785408)===16785408){if(v4={stylesheets:null,count:0,imgCount:0,imgBytes:0,suspenseyImages:[],waitingForImages:!0,waitingForViewTransition:!1,unsuspend:Z6},KY(G,Q,v4),R4=(Q&62914560)===Q?jz-V2():(Q&4194048)===Q?vW-V2():0,R4=gL(v4,R4),R4!==null){X6=Q,Z.cancelPendingCommit=R4(qJ.bind(null,Z,G,Q,B,$,z,q,X,j,k,v4,v4.waitingForViewTransition?"Waiting for the previous Animation":0<v4.count?0<v4.imgCount?"Suspended on CSS and Images":"Suspended on CSS":v4.imgCount===1?"Suspended on an Image":0<v4.imgCount?"Suspended on Images":null,P,d)),m8(Z,Q,q,!U);return}}qJ(Z,G,Q,B,$,z,q,X,j,k,v4,y,P,d)}function o3(Z){for(var G=Z;;){var B=G.tag;if((B===0||B===11||B===15)&&G.flags&16384&&(B=G.updateQueue,B!==null&&(B=B.stores,B!==null)))for(var $=0;$<B.length;$++){var z=B[$],Q=z.getSnapshot;z=z.value;try{if(!l2(Q(),z))return!1}catch(q){return!1}}if(B=G.child,G.subtreeFlags&16384&&B!==null)B.return=G,G=B;else{if(G===Z)break;for(;G.sibling===null;){if(G.return===null||G.return===Z)return!0;G=G.return}G.sibling.return=G.return,G=G.sibling}}return!0}function m8(Z,G,B,$){G&=~uq,G&=~J9,Z.suspendedLanes|=G,Z.pingedLanes&=~G,$&&(Z.warmLanes|=G),$=Z.expirationTimes;for(var z=G;0<z;){var Q=31-d2(z),q=1<<Q;$[Q]=-1,z&=~q}B!==0&&u(Z,B,G)}function kG(){return(i7&(W2|C5))===R2?(W1(0,!1),!1):!0}function QJ(){if(x7!==null){if(JZ===H5)var Z=x7.return;else Z=x7,UZ(),UQ(Z),q0=null,i1=0,Z=x7;for(;Z!==null;)lX(Z.alternate,Z),Z=Z.return;x7=null}}function v9(Z,G){(Z&127)!==0&&(t8=G),(Z&4194048)!==0&&(b6=G),(Z&62914560)!==0&&(yK=G),(Z&2080374784)!==0&&(gK=G)}function yG(Z,G){MZ&&(console.timeStamp("Blocking Track",0.003,0.003,"Blocking",y7,"primary-light"),console.timeStamp("Transition Track",0.003,0.003,"Transition",y7,"primary-light"),console.timeStamp("Suspense Track",0.003,0.003,"Suspense",y7,"primary-light"),console.timeStamp("Idle Track",0.003,0.003,"Idle",y7,"primary-light"));var B=O2;if(O2=z2(),I7!==0&&0<B){if(S2(I7),xZ===Jz||xZ===$9)r6(B,O2,G,aZ);else{var $=O2,z=aZ;if(MZ&&!($<=B)){var Q=(G&738197653)===G?"tertiary-dark":"primary-dark",q=(G&536870912)===G?"Prewarm":(G&201326741)===G?"Interrupted Hydration":"Interrupted Render";z?z.run(console.timeStamp.bind(console,q,B,$,m7,y7,Q)):console.timeStamp(q,B,$,m7,y7,Q)}}v9(I7,O2)}if(B=aZ,aZ=null,(G&127)!==0){aZ=g1,z=0<=g6&&g6<t8?t8:g6,$=0<=f9&&f9<t8?t8:f9,Q=0<=$?$:0<=z?z:O2,0<=s$?(S2(2),A9(s$,Q,G,B)):(i$&127)!==0&&(S2(2),S8(t8,Q,L8)),B=z;var X=$,j=b1,U=0<z0,k=e8===y1,y=e8===l$;if(z=O2,$=g1,Q=Fq,q=Rq,MZ){if(m7="Blocking",0<B?B>z&&(B=z):B=z,0<X?X>B&&(X=B):X=B,j!==null&&B>X){var P=U?"secondary-light":"warning";$?$.run(console.timeStamp.bind(console,U?"Consecutive":"Event: "+j,X,B,m7,y7,P)):console.timeStamp(U?"Consecutive":"Event: "+j,X,B,m7,y7,P)}z>B&&(X=k?"error":(G&738197653)===G?"tertiary-light":"primary-light",k=y?"Promise Resolved":k?"Cascading Update":5<z-B?"Update Blocked":"Update",y=[],q!=null&&y.push(["Component name",q]),Q!=null&&y.push(["Method name",Q]),B={start:B,end:z,detail:{devtools:{properties:y,track:m7,trackGroup:y7,color:X}}},$?$.run(performance.measure.bind(performance,k,B)):performance.measure(k,B))}g6=-1.1,e8=0,Rq=Fq=null,s$=-1.1,z0=f9,f9=-1.1,t8=z2()}if((G&4194048)!==0&&(aZ=f1,z=0<=_8&&_8<b6?b6:_8,B=0<=s5&&s5<b6?b6:s5,$=0<=Z9&&Z9<b6?b6:Z9,Q=0<=$?$:0<=B?B:O2,0<=a$?(S2(256),A9(a$,Q,G,aZ)):(i$&4194048)!==0&&(S2(256),S8(b6,Q,L8)),y=$,X=m9,j=0<G9,U=Mq===l$,Q=O2,$=f1,q=vK,k=kK,MZ&&(m7="Transition",0<B?B>Q&&(B=Q):B=Q,0<z?z>B&&(z=B):z=B,0<y?y>z&&(y=z):y=z,z>y&&X!==null&&(P=j?"secondary-light":"warning",$?$.run(console.timeStamp.bind(console,j?"Consecutive":"Event: "+X,y,z,m7,y7,P)):console.timeStamp(j?"Consecutive":"Event: "+X,y,z,m7,y7,P)),B>z&&($?$.run(console.timeStamp.bind(console,"Action",z,B,m7,y7,"primary-dark")):console.timeStamp("Action",z,B,m7,y7,"primary-dark")),Q>B&&(z=U?"Promise Resolved":5<Q-B?"Update Blocked":"Update",y=[],k!=null&&y.push(["Component name",k]),q!=null&&y.push(["Method name",q]),B={start:B,end:Q,detail:{devtools:{properties:y,track:m7,trackGroup:y7,color:"primary-light"}}},$?$.run(performance.measure.bind(performance,z,B)):performance.measure(z,B))),s5=_8=-1.1,Mq=0,a$=-1.1,G9=Z9,Z9=-1.1,b6=z2()),(G&62914560)!==0&&(i$&62914560)!==0&&(S2(4194304),S8(yK,O2,L8)),(G&2080374784)!==0&&(i$&2080374784)!==0&&(S2(268435456),S8(gK,O2,L8)),B=Z.timeoutHandle,B!==ZG&&(Z.timeoutHandle=ZG,wV(B)),B=Z.cancelPendingCommit,B!==null&&(Z.cancelPendingCommit=null,B()),X6=0,QJ(),WZ=Z,x7=B=k2(Z.current,null),I7=G,JZ=H5,T5=null,z9=!1,U0=b7(Z,G),hq=!1,xZ=R8,o9=X5=uq=J9=Q9=0,o2=zB=null,Yz=!1,(G&8)!==0&&(G|=G&32),$=Z.entangledLanes,$!==0)for(Z=Z.entanglements,$&=G;0<$;)z=31-d2($),Q=1<<z,G|=Z[z],$&=~Q;return m6=G,n6(),Z=TK(),1000<Z-CK&&(l.recentlyCreatedOwnerStacks=0,CK=Z),J6.discardPendingWarnings(),B}function MY(Z,G){V7=null,l.H=t1,l.getCurrentStack=null,I6=!1,M5=null,G===J0||G===t$?(G=dH(),JZ=BB):G===Aq?(G=dH(),JZ=SW):JZ=G===yq?mq:G!==null&&typeof G==="object"&&typeof G.then==="function"?$B:Hz,T5=G;var B=x7;B===null?(xZ=GB,z$(Z,v(G,Z.current))):B.mode&E7&&$Q(B)}function NY(){var Z=P5.current;return Z===null?!0:(I7&4194048)===I7?a5===null?!0:!1:(I7&62914560)===I7||(I7&536870912)!==0?Z===a5:!1}function DY(){var Z=l.H;return l.H=t1,Z===null?t1:Z}function PY(){var Z=l.A;return l.A=LV,Z}function K$(Z){aZ===null&&(aZ=Z._debugTask==null?null:Z._debugTask)}function W$(){xZ=$9,z9||(I7&4194048)!==I7&&P5.current!==null||(U0=!0),(Q9&134217727)===0&&(J9&134217727)===0||WZ===null||m8(WZ,I7,X5,!1)}function JJ(Z,G,B){var $=i7;i7|=W2;var z=DY(),Q=PY();if(WZ!==Z||I7!==G){if(S6){var q=Z.memoizedUpdaters;0<q.size&&(K1(Z,I7),q.clear()),j4(Z,G)}QB=null,yG(Z,G)}G=!1,q=xZ;Z:do try{if(JZ!==H5&&x7!==null){var X=x7,j=T5;switch(JZ){case mq:QJ(),q=qz;break Z;case BB:case a9:case i9:case $B:P5.current===null&&(G=!0);var U=JZ;if(JZ=H5,T5=null,gG(Z,X,j,U),B&&U0){q=R8;break Z}break;default:U=JZ,JZ=H5,T5=null,gG(Z,X,j,U)}}AY(),q=xZ;break}catch(k){MY(Z,k)}while(1);return G&&Z.shellSuspendCounter++,UZ(),i7=$,l.H=z,l.A=Q,x7===null&&(WZ=null,I7=0,n6()),q}function AY(){for(;x7!==null;)CY(x7)}function r3(Z,G){var B=i7;i7|=W2;var $=DY(),z=PY();if(WZ!==Z||I7!==G){if(S6){var Q=Z.memoizedUpdaters;0<Q.size&&(K1(Z,I7),Q.clear()),j4(Z,G)}QB=null,Kz=V2()+yW,yG(Z,G)}else U0=b7(Z,G);Z:do try{if(JZ!==H5&&x7!==null)G:switch(G=x7,Q=T5,JZ){case Hz:JZ=H5,T5=null,gG(Z,G,Q,Hz);break;case a9:case i9:if(hH(Q)){JZ=H5,T5=null,TY(G);break}G=function(){JZ!==a9&&JZ!==i9||WZ!==Z||(JZ=Xz),C6(Z)},Q.then(G,G);break Z;case BB:JZ=Xz;break Z;case SW:JZ=fq;break Z;case Xz:hH(Q)?(JZ=H5,T5=null,TY(G)):(JZ=H5,T5=null,gG(Z,G,Q,Xz));break;case fq:var q=null;switch(x7.tag){case 26:q=x7.memoizedState;case 5:case 27:var X=x7;if(q?Fj(q):X.stateNode.complete){JZ=H5,T5=null;var j=X.sibling;if(j!==null)x7=j;else{var U=X.return;U!==null?(x7=U,_$(U)):x7=null}break G}break;default:console.error("Unexpected type of fiber triggered a suspensey commit. This is a bug in React.")}JZ=H5,T5=null,gG(Z,G,Q,fq);break;case $B:JZ=H5,T5=null,gG(Z,G,Q,$B);break;case mq:QJ(),xZ=qz;break Z;default:throw Error("Unexpected SuspendedReason. This is a bug in React.")}l.actQueue!==null?AY():n3();break}catch(k){MY(Z,k)}while(1);if(UZ(),l.H=$,l.A=z,i7=B,x7!==null)return R8;return WZ=null,I7=0,n6(),xZ}function n3(){for(;x7!==null&&!rL();)CY(x7)}function CY(Z){var G=Z.alternate;(Z.mode&E7)!==_7?(BQ(Z),G=M4(Z,rQ,G,Z,m6),$Q(Z)):G=M4(Z,rQ,G,Z,m6),Z.memoizedProps=Z.pendingProps,G===null?_$(Z):x7=G}function TY(Z){var G=M4(Z,t3,Z);Z.memoizedProps=Z.pendingProps,G===null?_$(Z):x7=G}function t3(Z){var G=Z.alternate,B=(Z.mode&E7)!==_7;switch(B&&BQ(Z),Z.tag){case 15:case 0:G=fX(G,Z,Z.pendingProps,Z.type,void 0,I7);break;case 11:G=fX(G,Z,Z.pendingProps,Z.type.render,Z.ref,I7);break;case 5:UQ(Z);default:lX(G,Z),Z=x7=kB(Z,m6),G=rQ(G,Z,m6)}return B&&$Q(Z),G}function gG(Z,G,B,$){UZ(),UQ(G),q0=null,i1=0;var z=G.return;try{if(g3(Z,z,G,B,I7)){xZ=GB,z$(Z,v(B,Z.current)),x7=null;return}}catch(Q){if(z!==null)throw x7=z,Q;xZ=GB,z$(Z,v(B,Z.current)),x7=null;return}if(G.flags&32768){if(d7||$===Hz)Z=!0;else if(U0||(I7&536870912)!==0)Z=!1;else if(z9=Z=!0,$===a9||$===i9||$===BB||$===$B)$=P5.current,$!==null&&$.tag===13&&($.flags|=16384);EY(G,Z)}else _$(G)}function _$(Z){var G=Z;do{if((G.flags&32768)!==0){EY(G,z9);return}var B=G.alternate;if(Z=G.return,BQ(G),B=M4(G,m3,B,G,m6),(G.mode&E7)!==_7&&yH(G),B!==null){x7=B;return}if(G=G.sibling,G!==null){x7=G;return}x7=G=Z}while(G!==null);xZ===R8&&(xZ=xW)}function EY(Z,G){do{var B=h3(Z.alternate,Z);if(B!==null){B.flags&=32767,x7=B;return}if((Z.mode&E7)!==_7){yH(Z),B=Z.actualDuration;for(var $=Z.child;$!==null;)B+=$.actualDuration,$=$.sibling;Z.actualDuration=B}if(B=Z.return,B!==null&&(B.flags|=32768,B.subtreeFlags=0,B.deletions=null),!G&&(Z=Z.sibling,Z!==null)){x7=Z;return}x7=Z=B}while(Z!==null);xZ=qz,x7=null}function qJ(Z,G,B,$,z,Q,q,X,j,U,k,y,P,d){Z.cancelPendingCommit=null;do j1();while(X2!==H9);if(J6.flushLegacyContextWarning(),J6.flushPendingUnsafeLifecycleWarnings(),(i7&(W2|C5))!==R2)throw Error("Should not already be working.");if(S2(B),U===s9?RG(P,d,B,aZ):$!==null?vB(P,d,B,$,G!==null&&G.alternate!==null&&G.alternate.memoizedState.isDehydrated&&(G.flags&256)!==0,aZ):s0(P,d,B,aZ),G!==null){if(B===0&&console.error("finishedLanes should not be empty during a commit. This is a bug in React."),G===Z.current)throw Error("Cannot commit the same tree as before. This error is likely caused by a bug in React. Please file an issue.");if(Q=G.lanes|G.childLanes,Q|=_q,f(Z,B,Q,q,X,j),Z===WZ&&(x7=WZ=null,I7=0),V0=G,X9=Z,X6=B,cq=Q,sq=z,uW=$,lq=d,dW=y,Y6=Wz,pW=null,G.actualDuration!==0||(G.subtreeFlags&10256)!==0||(G.flags&10256)!==0?(Z.callbackNode=null,Z.callbackPriority=0,$L(dG,function(){return jB=window.event,Y6===Wz&&(Y6=pq),vY(),null})):(Z.callbackNode=null,Z.callbackPriority=0),W8=null,n8=z2(),y!==null&&MG(d,n8,y,aZ),$=(G.flags&13878)!==0,(G.subtreeFlags&13878)!==0||$){$=l.T,l.T=null,z=BZ.p,BZ.p=N5,q=i7,i7|=C5;try{s3(Z,G,B)}finally{i7=q,BZ.p=z,l.T=$}}X2=bW,wY(),IY(),xY()}}function wY(){if(X2===bW){X2=H9;var Z=X9,G=V0,B=X6,$=(G.flags&13878)!==0;if((G.subtreeFlags&13878)!==0||$){$=l.T,l.T=null;var z=BZ.p;BZ.p=N5;var Q=i7;i7|=C5;try{_0=B,L0=Z,bB(),JY(G,Z),L0=_0=null,B=$H;var q=W5(Z.containerInfo),X=B.focusedElem,j=B.selectionRange;if(q!==X&&X&&X.ownerDocument&&i6(X.ownerDocument.documentElement,X)){if(j!==null&&o6(X)){var{start:U,end:k}=j;if(k===void 0&&(k=U),"selectionStart"in X)X.selectionStart=U,X.selectionEnd=Math.min(k,X.value.length);else{var y=X.ownerDocument||document,P=y&&y.defaultView||window;if(P.getSelection){var d=P.getSelection(),R4=X.textContent.length,v4=Math.min(j.start,R4),OZ=j.end===void 0?v4:Math.min(j.end,R4);!d.extend&&v4>OZ&&(q=OZ,OZ=v4,v4=q);var l7=c0(X,v4),D=c0(X,OZ);if(l7&&D&&(d.rangeCount!==1||d.anchorNode!==l7.node||d.anchorOffset!==l7.offset||d.focusNode!==D.node||d.focusOffset!==D.offset)){var T=y.createRange();T.setStart(l7.node,l7.offset),d.removeAllRanges(),v4>OZ?(d.addRange(T),d.extend(D.node,D.offset)):(T.setEnd(D.node,D.offset),d.addRange(T))}}}}y=[];for(d=X;d=d.parentNode;)d.nodeType===1&&y.push({element:d,left:d.scrollLeft,top:d.scrollTop});typeof X.focus==="function"&&X.focus();for(X=0;X<y.length;X++){var S=y[X];S.element.scrollLeft=S.left,S.element.scrollTop=S.top}}wz=!!BH,$H=BH=null}finally{i7=Q,BZ.p=z,l.T=$}}Z.current=G,X2=fW}}function IY(){if(X2===fW){X2=H9;var Z=pW;if(Z!==null){n8=z2();var G=K8,B=n8;!MZ||B<=G||(L8?L8.run(console.timeStamp.bind(console,Z,G,B,m7,y7,"secondary-light")):console.timeStamp(Z,G,B,m7,y7,"secondary-light"))}Z=X9,G=V0,B=X6;var $=(G.flags&8772)!==0;if((G.subtreeFlags&8772)!==0||$){$=l.T,l.T=null;var z=BZ.p;BZ.p=N5;var Q=i7;i7|=C5;try{_0=B,L0=Z,bB(),GY(Z,G.alternate,G),L0=_0=null}finally{i7=Q,BZ.p=z,l.T=$}}Z=lq,G=dW,K8=z2(),Z=G===null?Z:n8,G=K8,B=Y6===dq,$=aZ,W8!==null?NG(Z,G,W8,!1,$):!MZ||G<=Z||($?$.run(console.timeStamp.bind(console,B?"Commit Interrupted View Transition":"Commit",Z,G,m7,y7,B?"error":"secondary-dark")):console.timeStamp(B?"Commit Interrupted View Transition":"Commit",Z,G,m7,y7,B?"error":"secondary-dark")),X2=mW}}function xY(){if(X2===hW||X2===mW){if(X2===hW){var Z=K8;K8=z2();var G=K8,B=Y6===dq;!MZ||G<=Z||(L8?L8.run(console.timeStamp.bind(console,B?"Interrupted View Transition":"Starting Animation",Z,G,m7,y7,B?"error":"secondary-light")):console.timeStamp(B?"Interrupted View Transition":"Starting Animation",Z,G,m7,y7,B?" error":"secondary-light")),Y6!==dq&&(Y6=gW)}X2=H9,nL(),Z=X9;var $=V0;G=X6,B=uW;var z=$.actualDuration!==0||($.subtreeFlags&10256)!==0||($.flags&10256)!==0;z?X2=_z:(X2=H9,V0=X9=null,SY(Z,Z.pendingLanes),r9=0,qB=null);var Q=Z.pendingLanes;if(Q===0&&(q9=null),z||bY(Z),Q=_(G),$=$.stateNode,y2&&typeof y2.onCommitFiberRoot==="function")try{var q=($.current.flags&128)===128;switch(Q){case N5:var X=sJ;break;case z6:X=aJ;break;case v6:X=dG;break;case S$:X=iJ;break;default:X=dG}y2.onCommitFiberRoot(pG,$,X,q)}catch(y){x6||(x6=!0,console.error("React instrumentation encountered an error: %o",y))}if(S6&&Z.memoizedUpdaters.clear(),i3(),B!==null){q=l.T,X=BZ.p,BZ.p=N5,l.T=null;try{var j=Z.onRecoverableError;for($=0;$<B.length;$++){var U=B[$],k=e3(U.stack);M4(U.source,j,U.value,k)}}finally{l.T=q,BZ.p=X}}(X6&3)!==0&&j1(),C6(Z),Q=Z.pendingLanes,(G&261930)!==0&&(Q&42)!==0?(r$=!0,Z===aq?JB++:(JB=0,aq=Z)):JB=0,z||v9(G,K8),W1(0,!1)}}function e3(Z){return Z={componentStack:Z},Object.defineProperty(Z,"digest",{get:function(){console.error('You are accessing "digest" from the errorInfo object passed to onRecoverableError. This property is no longer provided as part of errorInfo but can be accessed as a property of the Error instance itself.')}}),Z}function SY(Z,G){(Z.pooledCacheLanes&=G)===0&&(G=Z.pooledCache,G!=null&&(Z.pooledCache=null,T9(G)))}function j1(){return wY(),IY(),xY(),vY()}function vY(){if(X2!==_z)return!1;var Z=X9,G=cq;cq=0;var B=_(X6),$=v6===0||v6>B?v6:B;B=l.T;var z=BZ.p;try{BZ.p=$,l.T=null;var Q=sq;sq=null,$=X9;var q=X6;if(X2=H9,V0=X9=null,X6=0,(i7&(W2|C5))!==R2)throw Error("Cannot flush passive effects while already rendering.");S2(q),iq=!0,Lz=!1;var X=0;if(W8=null,X=V2(),Y6===gW)S8(K8,X,L8);else{var j=K8,U=X,k=Y6===pq;!MZ||U<=j||(aZ?aZ.run(console.timeStamp.bind(console,k?"Waiting for Paint":"Waiting",j,U,m7,y7,"secondary-light")):console.timeStamp(k?"Waiting for Paint":"Waiting",j,U,m7,y7,"secondary-light"))}j=i7,i7|=C5;var y=$.current;bB(),_Y(y);var P=$.current;y=lq,bB(),YY($,P,q,Q,y),bY($),i7=j;var d=V2();if(P=X,y=aZ,W8!==null?NG(P,d,W8,!0,y):!MZ||d<=P||(y?y.run(console.timeStamp.bind(console,"Remaining Effects",P,d,m7,y7,"secondary-dark")):console.timeStamp("Remaining Effects",P,d,m7,y7,"secondary-dark")),v9(q,d),W1(0,!1),Lz?$===qB?r9++:(r9=0,qB=$):r9=0,Lz=iq=!1,y2&&typeof y2.onPostCommitFiberRoot==="function")try{y2.onPostCommitFiberRoot(pG,$)}catch(v4){x6||(x6=!0,console.error("React instrumentation encountered an error: %o",v4))}var R4=$.current.stateNode;return R4.effectDuration=0,R4.passiveEffectDuration=0,!0}finally{BZ.p=z,l.T=B,SY(Z,G)}}function kY(Z,G,B){G=v(B,G),gH(G),G=mQ(Z.stateNode,G,2),Z=y8(Z,G,2),Z!==null&&(o4(Z,2),C6(Z))}function GZ(Z,G,B){if(O0=!1,Z.tag===3)kY(Z,Z,B);else{for(;G!==null;){if(G.tag===3){kY(G,Z,B);return}if(G.tag===1){var $=G.stateNode;if(typeof G.type.getDerivedStateFromError==="function"||typeof $.componentDidCatch==="function"&&(q9===null||!q9.has($))){Z=v(B,Z),gH(Z),B=hQ(2),$=y8(G,B,2),$!==null&&(uQ(B,$,G,Z),o4($,2),C6($));return}}G=G.return}console.error(`Internal React error: Attempted to capture a commit phase error inside a detached tree. This indicates a bug in React. Potential causes include deleting the same fiber more than once, committing an already-finished tree, or an inconsistent return pointer.

Error message:

%s`,B)}}function HJ(Z,G,B){var $=Z.pingCache;if($===null){$=Z.pingCache=new VV;var z=new Set;$.set(G,z)}else z=$.get(G),z===void 0&&(z=new Set,$.set(G,z));z.has(B)||(hq=!0,z.add(B),$=ZL.bind(null,Z,G,B),S6&&K1(Z,B),G.then($,$))}function ZL(Z,G,B){var $=Z.pingCache;$!==null&&$.delete(G),Z.pingedLanes|=Z.suspendedLanes&B,Z.warmLanes&=~B,(B&127)!==0?0>g6&&(t8=g6=z2(),g1=c$("Promise Resolved"),e8=l$):(B&4194048)!==0&&0>s5&&(b6=s5=z2(),f1=c$("Promise Resolved"),Mq=l$),VY()&&l.actQueue===null&&console.error(`A suspended resource finished loading inside a test, but the event was not wrapped in act(...).

When testing, code that resolves suspended data should be wrapped into act(...):

act(() => {
  /* finish loading suspended data */
});
/* assert on the output */

This ensures that you're testing the behavior the user would see in the browser. Learn more at https://react.dev/link/wrap-tests-with-act`),WZ===Z&&(I7&B)===B&&(xZ===$9||xZ===Jz&&(I7&62914560)===I7&&V2()-jz<kW?(i7&W2)===R2&&yG(Z,0):uq|=B,o9===I7&&(o9=0)),C6(Z)}function yY(Z,G){G===0&&(G=S7()),Z=Z2(Z,G),Z!==null&&(o4(Z,G),C6(Z))}function GL(Z){var G=Z.memoizedState,B=0;G!==null&&(B=G.retryLane),yY(Z,B)}function BL(Z,G){var B=0;switch(Z.tag){case 31:case 13:var{stateNode:$,memoizedState:z}=Z;z!==null&&(B=z.retryLane);break;case 19:$=Z.stateNode;break;case 22:$=Z.stateNode._retryCache;break;default:throw Error("Pinged unknown suspense boundary type. This is probably a bug in React.")}$!==null&&$.delete(G),yY(Z,B)}function XJ(Z,G,B){if((G.subtreeFlags&67117056)!==0)for(G=G.child;G!==null;){var $=Z,z=G,Q=z.type===C$;Q=B||Q,z.tag!==22?z.flags&67108864?Q&&M4(z,gY,$,z):XJ($,z,Q):z.memoizedState===null&&(Q&&z.flags&8192?M4(z,gY,$,z):z.subtreeFlags&67108864&&M4(z,XJ,$,z,Q)),G=G.sibling}}function gY(Z,G){D4(!0);try{HY(G),LY(G),XY(Z,G.alternate,G,!1),jY(Z,G,0,null,!1,0)}finally{D4(!1)}}function bY(Z){var G=!0;Z.current.mode&(g2|Q6)||(G=!1),XJ(Z,Z.current,G)}function fY(Z){if((i7&W2)===R2){var G=Z.tag;if(G===3||G===1||G===0||G===11||G===14||G===15){if(G=Y4(Z)||"ReactComponent",Uz!==null){if(Uz.has(G))return;Uz.add(G)}else Uz=new Set([G]);M4(Z,function(){console.error("Can't perform a React state update on a component that hasn't mounted yet. This indicates that you have a side-effect in your render function that asynchronously tries to update the component. Move this work to useEffect instead.")})}}}function K1(Z,G){S6&&Z.memoizedUpdaters.forEach(function(B){m4(Z,B,G)})}function $L(Z,G){var B=l.actQueue;return B!==null?(B.push(G),RV):lJ(Z,G)}function zL(Z){VY()&&l.actQueue===null&&M4(Z,function(){console.error(`An update to %s inside a test was not wrapped in act(...).

When testing, code that causes React state updates should be wrapped into act(...):

act(() => {
  /* fire events that update state */
});
/* assert on the output */

This ensures that you're testing the behavior the user would see in the browser. Learn more at https://react.dev/link/wrap-tests-with-act`,Y4(Z))})}function C6(Z){Z!==F0&&Z.next===null&&(F0===null?Vz=F0=Z:F0=F0.next=Z),Oz=!0,l.actQueue!==null?rq||(rq=!0,dY()):oq||(oq=!0,dY())}function W1(Z,G){if(!nq&&Oz){nq=!0;do{var B=!1;for(var $=Vz;$!==null;){if(!G)if(Z!==0){var z=$.pendingLanes;if(z===0)var Q=0;else{var{suspendedLanes:q,pingedLanes:X}=$;Q=(1<<31-d2(42|Z)+1)-1,Q&=z&~(q&~X),Q=Q&201326741?Q&201326741|1:Q?Q|2:0}Q!==0&&(B=!0,uY($,Q))}else Q=I7,Q=t4($,$===WZ?Q:0,$.cancelPendingCommit!==null||$.timeoutHandle!==ZG),(Q&3)===0||b7($,Q)||(B=!0,uY($,Q));$=$.next}}while(B);nq=!1}}function QL(){jB=window.event,YJ()}function YJ(){Oz=rq=oq=!1;var Z=0;Y9!==0&&KL()&&(Z=Y9);for(var G=V2(),B=null,$=Vz;$!==null;){var z=$.next,Q=mY($,G);if(Q===0)$.next=null,B===null?Vz=z:B.next=z,z===null&&(F0=B);else if(B=$,Z!==0||(Q&3)!==0)Oz=!0;$=z}X2!==H9&&X2!==_z||W1(Z,!1),Y9!==0&&(Y9=0)}function mY(Z,G){for(var{suspendedLanes:B,pingedLanes:$,expirationTimes:z}=Z,Q=Z.pendingLanes&-62914561;0<Q;){var q=31-d2(Q),X=1<<q,j=z[q];if(j===-1){if((X&B)===0||(X&$)!==0)z[q]=o7(X,G)}else j<=G&&(Z.expiredLanes|=X);Q&=~X}if(G=WZ,B=I7,B=t4(Z,Z===G?B:0,Z.cancelPendingCommit!==null||Z.timeoutHandle!==ZG),$=Z.callbackNode,B===0||Z===G&&(JZ===a9||JZ===i9)||Z.cancelPendingCommit!==null)return $!==null&&jJ($),Z.callbackNode=null,Z.callbackPriority=0;if((B&3)===0||b7(Z,B)){if(G=B&-B,G!==Z.callbackPriority||l.actQueue!==null&&$!==tq)jJ($);else return G;switch(_(B)){case N5:case z6:B=aJ;break;case v6:B=dG;break;case S$:B=iJ;break;default:B=dG}return $=hY.bind(null,Z),l.actQueue!==null?(l.actQueue.push($),B=tq):B=lJ(B,$),Z.callbackPriority=G,Z.callbackNode=B,G}return $!==null&&jJ($),Z.callbackPriority=2,Z.callbackNode=null,2}function hY(Z,G){if(r$=o$=!1,jB=window.event,X2!==H9&&X2!==_z)return Z.callbackNode=null,Z.callbackPriority=0,null;var B=Z.callbackNode;if(Y6===Wz&&(Y6=pq),j1()&&Z.callbackNode!==B)return null;var $=I7;if($=t4(Z,Z===WZ?$:0,Z.cancelPendingCommit!==null||Z.timeoutHandle!==ZG),$===0)return null;return FY(Z,$,G),mY(Z,V2()),Z.callbackNode!=null&&Z.callbackNode===B?hY.bind(null,Z):null}function uY(Z,G){if(j1())return null;o$=r$,r$=!1,FY(Z,G,!0)}function jJ(Z){Z!==tq&&Z!==null&&oL(Z)}function dY(){l.actQueue!==null&&l.actQueue.push(function(){return YJ(),null}),IV(function(){(i7&(W2|C5))!==R2?lJ(sJ,QL):YJ()})}function KJ(){if(Y9===0){var Z=h9;Z===0&&(Z=w$,w$<<=1,(w$&261888)===0&&(w$=256)),Y9=Z}return Y9}function pY(Z){if(Z==null||typeof Z==="symbol"||typeof Z==="boolean")return null;if(typeof Z==="function")return Z;return s7(Z,"action"),F9(""+Z)}function cY(Z,G){var B=G.ownerDocument.createElement("input");return B.name=G.name,B.value=G.value,Z.id&&B.setAttribute("form",Z.id),G.parentNode.insertBefore(B,G),Z=new FormData(Z),B.parentNode.removeChild(B),Z}function JL(Z,G,B,$,z){if(G==="submit"&&B&&B.stateNode===z){var Q=pY((z[p2]||null).action),q=$.submitter;q&&(G=(G=q[p2]||null)?pY(G.formAction):q.getAttribute("formAction"),G!==null&&(Q=G,q=null));var X=new b$("action","action",null,$,z);Z.push({event:X,listeners:[{instance:null,listener:function(){if($.defaultPrevented){if(Y9!==0){var j=q?cY(z,q):new FormData(z),U={pending:!0,data:j,method:z.method,action:Q};Object.freeze(U),SQ(B,U,null,j)}}else typeof Q==="function"&&(X.preventDefault(),j=q?cY(z,q):new FormData(z),U={pending:!0,data:j,method:z.method,action:Q},Object.freeze(U),SQ(B,U,Q,j))},currentTarget:z}]})}}function L$(Z,G,B){Z.currentTarget=B;try{G(Z)}catch($){Yq($)}Z.currentTarget=null}function lY(Z,G){G=(G&4)!==0;for(var B=0;B<Z.length;B++){var $=Z[B];Z:{var z=void 0,Q=$.event;if($=$.listeners,G)for(var q=$.length-1;0<=q;q--){var X=$[q],j=X.instance,U=X.currentTarget;if(X=X.listener,j!==z&&Q.isPropagationStopped())break Z;j!==null?M4(j,L$,Q,X,U):L$(Q,X,U),z=j}else for(q=0;q<$.length;q++){if(X=$[q],j=X.instance,U=X.currentTarget,X=X.listener,j!==z&&Q.isPropagationStopped())break Z;j!==null?M4(j,L$,Q,X,U):L$(Q,X,U),z=j}}}}function c7(Z,G){eq.has(Z)||console.error('Did not expect a listenToNonDelegatedEvent() call for "%s". This is a bug in React. Please file an issue.',Z);var B=G[oJ];B===void 0&&(B=G[oJ]=new Set);var $=Z+"__bubble";B.has($)||(sY(G,Z,2,!1),B.add($))}function WJ(Z,G,B){eq.has(Z)&&!G&&console.error('Did not expect a listenToNativeEvent() call for "%s" in the bubble phase. This is a bug in React. Please file an issue.',Z);var $=0;G&&($|=4),sY(B,Z,$,G)}function _J(Z){if(!Z[Fz]){Z[Fz]=!0,dj.forEach(function(B){B!=="selectionchange"&&(eq.has(B)||WJ(B,!1,Z),WJ(B,!0,Z))});var G=Z.nodeType===9?Z:Z.ownerDocument;G===null||G[Fz]||(G[Fz]=!0,WJ("selectionchange",!1,G))}}function sY(Z,G,B,$){switch(Aj(G)){case N5:var z=hL;break;case z6:z=uL;break;default:z=IJ}B=z.bind(null,G,B,Z),z=void 0,!Zq||G!=="touchstart"&&G!=="touchmove"&&G!=="wheel"||(z=!0),$?z!==void 0?Z.addEventListener(G,B,{capture:!0,passive:z}):Z.addEventListener(G,B,!0):z!==void 0?Z.addEventListener(G,B,{passive:z}):Z.addEventListener(G,B,!1)}function LJ(Z,G,B,$,z){var Q=$;if((G&1)===0&&(G&2)===0&&$!==null)Z:for(;;){if($===null)return;var q=$.tag;if(q===3||q===4){var X=$.stateNode.containerInfo;if(X===z)break;if(q===4)for(q=$.return;q!==null;){var j=q.tag;if((j===3||j===4)&&q.stateNode.containerInfo===z)return;q=q.return}for(;X!==null;){if(q=e(X),q===null)return;if(j=q.tag,j===5||j===6||j===26||j===27){$=Q=q;continue Z}X=X.parentNode}}$=$.return}K5(function(){var U=Q,k=T7(B),y=[];Z:{var P=AK.get(Z);if(P!==void 0){var d=b$,R4=Z;switch(Z){case"keypress":if(R9(B)===0)break Z;case"keydown":case"keyup":d=gU;break;case"focusin":R4="focus",d=zq;break;case"focusout":R4="blur",d=zq;break;case"beforeblur":case"afterblur":d=zq;break;case"click":if(B.button===2)break Z;case"auxclick":case"dblclick":case"mousedown":case"mousemove":case"mouseup":case"mouseout":case"mouseover":case"contextmenu":d=jK;break;case"drag":case"dragend":case"dragenter":case"dragexit":case"dragleave":case"dragover":case"dragstart":case"drop":d=PU;break;case"touchcancel":case"touchend":case"touchmove":case"touchstart":d=mU;break;case MK:case NK:case DK:d=TU;break;case PK:d=uU;break;case"scroll":case"scrollend":d=NU;break;case"wheel":d=pU;break;case"copy":case"cut":case"paste":d=wU;break;case"gotpointercapture":case"lostpointercapture":case"pointercancel":case"pointerdown":case"pointermove":case"pointerout":case"pointerover":case"pointerup":d=WK;break;case"toggle":case"beforetoggle":d=lU}var v4=(G&4)!==0,OZ=!v4&&(Z==="scroll"||Z==="scrollend"),l7=v4?P!==null?P+"Capture":null:P;v4=[];for(var D=U,T;D!==null;){var S=D;if(T=S.stateNode,S=S.tag,S!==5&&S!==26&&S!==27||T===null||l7===null||(S=T8(D,l7),S!=null&&v4.push(_1(D,S,T))),OZ)break;D=D.return}0<v4.length&&(P=new d(P,R4,null,B,k),y.push({event:P,listeners:v4}))}}if((G&7)===0){Z:{if(P=Z==="mouseover"||Z==="pointerover",d=Z==="mouseout"||Z==="pointerout",P&&B!==A1&&(R4=B.relatedTarget||B.fromElement)&&(e(R4)||R4[l8]))break Z;if(d||P){if(P=k.window===k?k:(P=k.ownerDocument)?P.defaultView||P.parentWindow:window,d){if(R4=B.relatedTarget||B.toElement,d=U,R4=R4?e(R4):null,R4!==null&&(OZ=t(R4),v4=R4.tag,R4!==OZ||v4!==5&&v4!==27&&v4!==6))R4=null}else d=null,R4=U;if(d!==R4){if(v4=jK,S="onMouseLeave",l7="onMouseEnter",D="mouse",Z==="pointerout"||Z==="pointerover")v4=WK,S="onPointerLeave",l7="onPointerEnter",D="pointer";if(OZ=d==null?P:F4(d),T=R4==null?P:F4(R4),P=new v4(S,D+"leave",d,B,k),P.target=OZ,P.relatedTarget=T,S=null,e(k)===U&&(v4=new v4(l7,D+"enter",R4,B,k),v4.target=T,v4.relatedTarget=OZ,S=v4),OZ=S,d&&R4)G:{v4=qL,l7=d,D=R4,T=0;for(S=l7;S;S=v4(S))T++;S=0;for(var r=D;r;r=v4(r))S++;for(;0<T-S;)l7=v4(l7),T--;for(;0<S-T;)D=v4(D),S--;for(;T--;){if(l7===D||D!==null&&l7===D.alternate){v4=l7;break G}l7=v4(l7),D=v4(D)}v4=null}else v4=null;d!==null&&aY(y,P,d,v4,!1),R4!==null&&OZ!==null&&aY(y,OZ,R4,v4,!0)}}}Z:{if(P=U?F4(U):window,d=P.nodeName&&P.nodeName.toLowerCase(),d==="select"||d==="input"&&P.type==="file")var w4=UG;else if(LG(P))if(FK)w4=OG;else{w4=VG;var O7=xB}else d=P.nodeName,!d||d.toLowerCase()!=="input"||P.type!=="checkbox"&&P.type!=="radio"?U&&x5(U.elementType)&&(w4=UG):w4=D9;if(w4&&(w4=w4(Z,U))){d0(y,w4,B,k);break Z}O7&&O7(Z,P,U),Z==="focusout"&&U&&P.type==="number"&&U.memoizedProps.value!=null&&V9(P,"number",P.value)}switch(O7=U?F4(U):window,Z){case"focusin":if(LG(O7)||O7.contentEditable==="true")rG=O7,Jq=U,S1=null;break;case"focusout":S1=Jq=rG=null;break;case"mousedown":qq=!0;break;case"contextmenu":case"mouseup":case"dragend":qq=!1,I8(y,B,k);break;case"selectionchange":if(oU)break;case"keydown":case"keyup":I8(y,B,k)}var e4;if(Qq)Z:{switch(Z){case"compositionstart":var a4="onCompositionStart";break Z;case"compositionend":a4="onCompositionEnd";break Z;case"compositionupdate":a4="onCompositionUpdate";break Z}a4=void 0}else oG?u0(Z,B)&&(a4="onCompositionEnd"):Z==="keydown"&&B.keyCode===_K&&(a4="onCompositionStart");if(a4&&(LK&&B.locale!=="ko"&&(oG||a4!=="onCompositionStart"?a4==="onCompositionEnd"&&oG&&(e4=m0()):(s8=k,Gq=("value"in s8)?s8.value:s8.textContent,oG=!0)),O7=U$(U,a4),0<O7.length&&(a4=new KK(a4,Z,null,B,k),y.push({event:a4,listeners:O7}),e4?a4.data=e4:(e4=B5(B),e4!==null&&(a4.data=e4)))),e4=aU?s6(Z,B):CZ(Z,B))a4=U$(U,"onBeforeInput"),0<a4.length&&(O7=new xU("onBeforeInput","beforeinput",null,B,k),y.push({event:O7,listeners:a4}),O7.data=e4);JL(y,Z,U,B,k)}lY(y,G)})}function _1(Z,G,B){return{instance:Z,listener:G,currentTarget:B}}function U$(Z,G){for(var B=G+"Capture",$=[];Z!==null;){var z=Z,Q=z.stateNode;if(z=z.tag,z!==5&&z!==26&&z!==27||Q===null||(z=T8(Z,B),z!=null&&$.unshift(_1(Z,z,Q)),z=T8(Z,G),z!=null&&$.push(_1(Z,z,Q))),Z.tag===3)return $;Z=Z.return}return[]}function qL(Z){if(Z===null)return null;do Z=Z.return;while(Z&&Z.tag!==5&&Z.tag!==27);return Z?Z:null}function aY(Z,G,B,$,z){for(var Q=G._reactName,q=[];B!==null&&B!==$;){var X=B,j=X.alternate,U=X.stateNode;if(X=X.tag,j!==null&&j===$)break;X!==5&&X!==26&&X!==27||U===null||(j=U,z?(U=T8(B,Q),U!=null&&q.unshift(_1(B,U,j))):z||(U=T8(B,Q),U!=null&&q.push(_1(B,U,j)))),B=B.return}q.length!==0&&Z.push({event:G,listeners:q})}function UJ(Z,G){S5(Z,G),Z!=="input"&&Z!=="textarea"&&Z!=="select"||G==null||G.value!==null||XK||(XK=!0,Z==="select"&&G.multiple?console.error("`value` prop on `%s` should not be null. Consider using an empty array when `multiple` is set to `true` to clear the component or `undefined` for uncontrolled components.",Z):console.error("`value` prop on `%s` should not be null. Consider using an empty string to clear the component or `undefined` for uncontrolled components.",Z));var B={registrationNameDependencies:k9,possibleRegistrationNames:rJ};x5(Z)||typeof G.is==="string"||ez(Z,G,B),G.contentEditable&&!G.suppressContentEditableWarning&&G.children!=null&&console.error("A component is `contentEditable` and contains `children` managed by React. It is now your responsibility to guarantee that none of those nodes are unexpectedly modified or duplicated. This is probably not intentional.")}function U2(Z,G,B,$){G!==B&&(B=h8(B),h8(G)!==B&&($[Z]=G))}function HL(Z,G,B){G.forEach(function($){B[rY($)]=$==="style"?OJ(Z):Z.getAttribute($)})}function T6(Z,G){G===!1?console.error("Expected `%s` listener to be a function, instead got `false`.\n\nIf you used to conditionally omit it with %s={condition && value}, pass %s={condition ? value : undefined} instead.",Z,Z,Z):console.error("Expected `%s` listener to be a function, instead got a value of `%s` type.",Z,typeof G)}function iY(Z,G){return Z=Z.namespaceURI===k$||Z.namespaceURI===lG?Z.ownerDocument.createElementNS(Z.namespaceURI,Z.tagName):Z.ownerDocument.createElement(Z.tagName),Z.innerHTML=G,Z.innerHTML}function h8(Z){return Y2(Z)&&(console.error("The provided HTML markup uses a value of unsupported type %s. This value must be coerced to a string before using it here.",uZ(Z)),qZ(Z)),(typeof Z==="string"?Z:""+Z).replace(MV,`
`).replace(NV,"")}function oY(Z,G){return G=h8(G),h8(Z)===G?!0:!1}function jZ(Z,G,B,$,z,Q){switch(B){case"children":if(typeof $==="string")g0($,G,!1),G==="body"||G==="textarea"&&$===""||WG(Z,$);else if(typeof $==="number"||typeof $==="bigint")g0(""+$,G,!1),G!=="body"&&WG(Z,""+$);break;case"className":kZ(Z,"class",$);break;case"tabIndex":kZ(Z,"tabindex",$);break;case"dir":case"role":case"viewBox":case"width":case"height":kZ(Z,B,$);break;case"style":f0(Z,$,Q);break;case"data":if(G!=="object"){kZ(Z,"data",$);break}case"src":case"href":if($===""&&(G!=="a"||B!=="href")){B==="src"?console.error('An empty string ("") was passed to the %s attribute. This may cause the browser to download the whole page again over the network. To fix this, either do not render the element at all or pass null to %s instead of an empty string.',B,B):console.error('An empty string ("") was passed to the %s attribute. To fix this, either do not render the element at all or pass null to %s instead of an empty string.',B,B),Z.removeAttribute(B);break}if($==null||typeof $==="function"||typeof $==="symbol"||typeof $==="boolean"){Z.removeAttribute(B);break}s7($,B),$=F9(""+$),Z.setAttribute(B,$);break;case"action":case"formAction":if($!=null&&(G==="form"?B==="formAction"?console.error("You can only pass the formAction prop to <input> or <button>. Use the action prop on <form>."):typeof $==="function"&&(z.encType==null&&z.method==null||Nz||(Nz=!0,console.error("Cannot specify a encType or method for a form that specifies a function as the action. React provides those automatically. They will get overridden.")),z.target==null||Mz||(Mz=!0,console.error("Cannot specify a target for a form that specifies a function as the action. The function will always be executed in the same window."))):G==="input"||G==="button"?B==="action"?console.error("You can only pass the action prop to <form>. Use the formAction prop on <input> or <button>."):G!=="input"||z.type==="submit"||z.type==="image"||Rz?G!=="button"||z.type==null||z.type==="submit"||Rz?typeof $==="function"&&(z.name==null||iW||(iW=!0,console.error('Cannot specify a "name" prop for a button that specifies a function as a formAction. React needs it to encode which action should be invoked. It will get overridden.')),z.formEncType==null&&z.formMethod==null||Nz||(Nz=!0,console.error("Cannot specify a formEncType or formMethod for a button that specifies a function as a formAction. React provides those automatically. They will get overridden.")),z.formTarget==null||Mz||(Mz=!0,console.error("Cannot specify a formTarget for a button that specifies a function as a formAction. The function will always be executed in the same window."))):(Rz=!0,console.error('A button can only specify a formAction along with type="submit" or no type.')):(Rz=!0,console.error('An input can only specify a formAction along with type="submit" or type="image".')):B==="action"?console.error("You can only pass the action prop to <form>."):console.error("You can only pass the formAction prop to <input> or <button>.")),typeof $==="function"){Z.setAttribute(B,"javascript:throw new Error('A React form was unexpectedly submitted. If you called form.submit() manually, consider using form.requestSubmit() instead. If you\\'re trying to use event.stopPropagation() in a submit event handler, consider also calling event.preventDefault().')");break}else typeof Q==="function"&&(B==="formAction"?(G!=="input"&&jZ(Z,G,"name",z.name,z,null),jZ(Z,G,"formEncType",z.formEncType,z,null),jZ(Z,G,"formMethod",z.formMethod,z,null),jZ(Z,G,"formTarget",z.formTarget,z,null)):(jZ(Z,G,"encType",z.encType,z,null),jZ(Z,G,"method",z.method,z,null),jZ(Z,G,"target",z.target,z,null)));if($==null||typeof $==="symbol"||typeof $==="boolean"){Z.removeAttribute(B);break}s7($,B),$=F9(""+$),Z.setAttribute(B,$);break;case"onClick":$!=null&&(typeof $!=="function"&&T6(B,$),Z.onclick=Z6);break;case"onScroll":$!=null&&(typeof $!=="function"&&T6(B,$),c7("scroll",Z));break;case"onScrollEnd":$!=null&&(typeof $!=="function"&&T6(B,$),c7("scrollend",Z));break;case"dangerouslySetInnerHTML":if($!=null){if(typeof $!=="object"||!("__html"in $))throw Error("`props.dangerouslySetInnerHTML` must be in the form `{__html: ...}`. Please visit https://react.dev/link/dangerously-set-inner-html for more information.");if(B=$.__html,B!=null){if(z.children!=null)throw Error("Can only set one of `children` or `props.dangerouslySetInnerHTML`.");Z.innerHTML=B}}break;case"multiple":Z.multiple=$&&typeof $!=="function"&&typeof $!=="symbol";break;case"muted":Z.muted=$&&typeof $!=="function"&&typeof $!=="symbol";break;case"suppressContentEditableWarning":case"suppressHydrationWarning":case"defaultValue":case"defaultChecked":case"innerHTML":case"ref":break;case"autoFocus":break;case"xlinkHref":if($==null||typeof $==="function"||typeof $==="boolean"||typeof $==="symbol"){Z.removeAttribute("xlink:href");break}s7($,B),B=F9(""+$),Z.setAttributeNS(n9,"xlink:href",B);break;case"contentEditable":case"spellCheck":case"draggable":case"value":case"autoReverse":case"externalResourcesRequired":case"focusable":case"preserveAlpha":$!=null&&typeof $!=="function"&&typeof $!=="symbol"?(s7($,B),Z.setAttribute(B,""+$)):Z.removeAttribute(B);break;case"inert":$!==""||Dz[B]||(Dz[B]=!0,console.error("Received an empty string for a boolean attribute `%s`. This will treat the attribute as if it were false. Either pass `false` to silence this warning, or pass `true` if you used an empty string in earlier versions of React to indicate this attribute is true.",B));case"allowFullScreen":case"async":case"autoPlay":case"controls":case"default":case"defer":case"disabled":case"disablePictureInPicture":case"disableRemotePlayback":case"formNoValidate":case"hidden":case"loop":case"noModule":case"noValidate":case"open":case"playsInline":case"readOnly":case"required":case"reversed":case"scoped":case"seamless":case"itemScope":$&&typeof $!=="function"&&typeof $!=="symbol"?Z.setAttribute(B,""):Z.removeAttribute(B);break;case"capture":case"download":$===!0?Z.setAttribute(B,""):$!==!1&&$!=null&&typeof $!=="function"&&typeof $!=="symbol"?(s7($,B),Z.setAttribute(B,$)):Z.removeAttribute(B);break;case"cols":case"rows":case"size":case"span":$!=null&&typeof $!=="function"&&typeof $!=="symbol"&&!isNaN($)&&1<=$?(s7($,B),Z.setAttribute(B,$)):Z.removeAttribute(B);break;case"rowSpan":case"start":$==null||typeof $==="function"||typeof $==="symbol"||isNaN($)?Z.removeAttribute(B):(s7($,B),Z.setAttribute(B,$));break;case"popover":c7("beforetoggle",Z),c7("toggle",Z),e7(Z,"popover",$);break;case"xlinkActuate":dZ(Z,n9,"xlink:actuate",$);break;case"xlinkArcrole":dZ(Z,n9,"xlink:arcrole",$);break;case"xlinkRole":dZ(Z,n9,"xlink:role",$);break;case"xlinkShow":dZ(Z,n9,"xlink:show",$);break;case"xlinkTitle":dZ(Z,n9,"xlink:title",$);break;case"xlinkType":dZ(Z,n9,"xlink:type",$);break;case"xmlBase":dZ(Z,ZH,"xml:base",$);break;case"xmlLang":dZ(Z,ZH,"xml:lang",$);break;case"xmlSpace":dZ(Z,ZH,"xml:space",$);break;case"is":Q!=null&&console.error('Cannot update the "is" prop after it has been initialized.'),e7(Z,"is",$);break;case"innerText":case"textContent":break;case"popoverTarget":oW||$==null||typeof $!=="object"||(oW=!0,console.error("The `popoverTarget` prop expects the ID of an Element as a string. Received %s instead.",$));default:!(2<B.length)||B[0]!=="o"&&B[0]!=="O"||B[1]!=="n"&&B[1]!=="N"?(B=gZ(B),e7(Z,B,$)):k9.hasOwnProperty(B)&&$!=null&&typeof $!=="function"&&T6(B,$)}}function VJ(Z,G,B,$,z,Q){switch(B){case"style":f0(Z,$,Q);break;case"dangerouslySetInnerHTML":if($!=null){if(typeof $!=="object"||!("__html"in $))throw Error("`props.dangerouslySetInnerHTML` must be in the form `{__html: ...}`. Please visit https://react.dev/link/dangerously-set-inner-html for more information.");if(B=$.__html,B!=null){if(z.children!=null)throw Error("Can only set one of `children` or `props.dangerouslySetInnerHTML`.");Z.innerHTML=B}}break;case"children":typeof $==="string"?WG(Z,$):(typeof $==="number"||typeof $==="bigint")&&WG(Z,""+$);break;case"onScroll":$!=null&&(typeof $!=="function"&&T6(B,$),c7("scroll",Z));break;case"onScrollEnd":$!=null&&(typeof $!=="function"&&T6(B,$),c7("scrollend",Z));break;case"onClick":$!=null&&(typeof $!=="function"&&T6(B,$),Z.onclick=Z6);break;case"suppressContentEditableWarning":case"suppressHydrationWarning":case"innerHTML":case"ref":break;case"innerText":case"textContent":break;default:if(k9.hasOwnProperty(B))$!=null&&typeof $!=="function"&&T6(B,$);else Z:{if(B[0]==="o"&&B[1]==="n"&&(z=B.endsWith("Capture"),G=B.slice(2,z?B.length-7:void 0),Q=Z[p2]||null,Q=Q!=null?Q[B]:null,typeof Q==="function"&&Z.removeEventListener(G,Q,z),typeof $==="function")){typeof Q!=="function"&&Q!==null&&(B in Z?Z[B]=null:Z.hasAttribute(B)&&Z.removeAttribute(B)),Z.addEventListener(G,$,z);break Z}B in Z?Z[B]=$:$===!0?Z.setAttribute(B,""):e7(Z,B,$)}}}function T2(Z,G,B){switch(UJ(G,B),G){case"div":case"span":case"svg":case"path":case"a":case"g":case"p":case"li":break;case"img":c7("error",Z),c7("load",Z);var $=!1,z=!1,Q;for(Q in B)if(B.hasOwnProperty(Q)){var q=B[Q];if(q!=null)switch(Q){case"src":$=!0;break;case"srcSet":z=!0;break;case"children":case"dangerouslySetInnerHTML":throw Error(G+" is a void element tag and must neither have `children` nor use `dangerouslySetInnerHTML`.");default:jZ(Z,G,Q,q,B,null)}}z&&jZ(Z,G,"srcSet",B.srcSet,B,null),$&&jZ(Z,G,"src",B.src,B,null);return;case"input":H7("input",B),c7("invalid",Z);var X=Q=q=z=null,j=null,U=null;for($ in B)if(B.hasOwnProperty($)){var k=B[$];if(k!=null)switch($){case"name":z=k;break;case"type":q=k;break;case"checked":j=k;break;case"defaultChecked":U=k;break;case"value":Q=k;break;case"defaultValue":X=k;break;case"children":case"dangerouslySetInnerHTML":if(k!=null)throw Error(G+" is a void element tag and must neither have `children` nor use `dangerouslySetInnerHTML`.");break;default:jZ(Z,G,$,k,B,null)}}AB(Z,B),b2(Z,Q,X,j,U,q,z,!1);return;case"select":H7("select",B),c7("invalid",Z),$=q=Q=null;for(z in B)if(B.hasOwnProperty(z)&&(X=B[z],X!=null))switch(z){case"value":Q=X;break;case"defaultValue":q=X;break;case"multiple":$=X;default:jZ(Z,G,z,X,B,null)}x0(Z,B),G=Q,B=q,Z.multiple=!!$,G!=null?A8(Z,!!$,G,!1):B!=null&&A8(Z,!!$,B,!0);return;case"textarea":H7("textarea",B),c7("invalid",Z),Q=z=$=null;for(q in B)if(B.hasOwnProperty(q)&&(X=B[q],X!=null))switch(q){case"value":$=X;break;case"defaultValue":z=X;break;case"children":Q=X;break;case"dangerouslySetInnerHTML":if(X!=null)throw Error("`dangerouslySetInnerHTML` does not make sense on <textarea>.");break;default:jZ(Z,G,q,X,B,null)}CB(Z,B),EB(Z,$,z,Q);return;case"option":XG(Z,B);for(j in B)if(B.hasOwnProperty(j)&&($=B[j],$!=null))switch(j){case"selected":Z.selected=$&&typeof $!=="function"&&typeof $!=="symbol";break;default:jZ(Z,G,j,$,B,null)}return;case"dialog":c7("beforetoggle",Z),c7("toggle",Z),c7("cancel",Z),c7("close",Z);break;case"iframe":case"object":c7("load",Z);break;case"video":case"audio":for($=0;$<HB.length;$++)c7(HB[$],Z);break;case"image":c7("error",Z),c7("load",Z);break;case"details":c7("toggle",Z);break;case"embed":case"source":case"link":c7("error",Z),c7("load",Z);case"area":case"base":case"br":case"col":case"hr":case"keygen":case"meta":case"param":case"track":case"wbr":case"menuitem":for(U in B)if(B.hasOwnProperty(U)&&($=B[U],$!=null))switch(U){case"children":case"dangerouslySetInnerHTML":throw Error(G+" is a void element tag and must neither have `children` nor use `dangerouslySetInnerHTML`.");default:jZ(Z,G,U,$,B,null)}return;default:if(x5(G)){for(k in B)B.hasOwnProperty(k)&&($=B[k],$!==void 0&&VJ(Z,G,k,$,B,void 0));return}}for(X in B)B.hasOwnProperty(X)&&($=B[X],$!=null&&jZ(Z,G,X,$,B,null))}function XL(Z,G,B,$){switch(UJ(G,$),G){case"div":case"span":case"svg":case"path":case"a":case"g":case"p":case"li":break;case"input":var z=null,Q=null,q=null,X=null,j=null,U=null,k=null;for(d in B){var y=B[d];if(B.hasOwnProperty(d)&&y!=null)switch(d){case"checked":break;case"value":break;case"defaultValue":j=y;default:$.hasOwnProperty(d)||jZ(Z,G,d,null,$,y)}}for(var P in $){var d=$[P];if(y=B[P],$.hasOwnProperty(P)&&(d!=null||y!=null))switch(P){case"type":Q=d;break;case"name":z=d;break;case"checked":U=d;break;case"defaultChecked":k=d;break;case"value":q=d;break;case"defaultValue":X=d;break;case"children":case"dangerouslySetInnerHTML":if(d!=null)throw Error(G+" is a void element tag and must neither have `children` nor use `dangerouslySetInnerHTML`.");break;default:d!==y&&jZ(Z,G,P,d,$,y)}}G=B.type==="checkbox"||B.type==="radio"?B.checked!=null:B.value!=null,$=$.type==="checkbox"||$.type==="radio"?$.checked!=null:$.value!=null,G||!$||aW||(console.error("A component is changing an uncontrolled input to be controlled. This is likely caused by the value changing from undefined to a defined value, which should not happen. Decide between using a controlled or uncontrolled input element for the lifetime of the component. More info: https://react.dev/link/controlled-components"),aW=!0),!G||$||sW||(console.error("A component is changing a controlled input to be uncontrolled. This is likely caused by the value changing from a defined to undefined, which should not happen. Decide between using a controlled or uncontrolled input element for the lifetime of the component. More info: https://react.dev/link/controlled-components"),sW=!0),K7(Z,q,X,j,U,k,Q,z);return;case"select":d=q=X=P=null;for(Q in B)if(j=B[Q],B.hasOwnProperty(Q)&&j!=null)switch(Q){case"value":break;case"multiple":d=j;default:$.hasOwnProperty(Q)||jZ(Z,G,Q,null,$,j)}for(z in $)if(Q=$[z],j=B[z],$.hasOwnProperty(z)&&(Q!=null||j!=null))switch(z){case"value":P=Q;break;case"defaultValue":X=Q;break;case"multiple":q=Q;default:Q!==j&&jZ(Z,G,z,Q,$,j)}$=X,G=q,B=d,P!=null?A8(Z,!!G,P,!1):!!B!==!!G&&($!=null?A8(Z,!!G,$,!0):A8(Z,!!G,G?[]:"",!1));return;case"textarea":d=P=null;for(X in B)if(z=B[X],B.hasOwnProperty(X)&&z!=null&&!$.hasOwnProperty(X))switch(X){case"value":break;case"children":break;default:jZ(Z,G,X,null,$,z)}for(q in $)if(z=$[q],Q=B[q],$.hasOwnProperty(q)&&(z!=null||Q!=null))switch(q){case"value":P=z;break;case"defaultValue":d=z;break;case"children":break;case"dangerouslySetInnerHTML":if(z!=null)throw Error("`dangerouslySetInnerHTML` does not make sense on <textarea>.");break;default:z!==Q&&jZ(Z,G,q,z,$,Q)}TB(Z,P,d);return;case"option":for(var R4 in B)if(P=B[R4],B.hasOwnProperty(R4)&&P!=null&&!$.hasOwnProperty(R4))switch(R4){case"selected":Z.selected=!1;break;default:jZ(Z,G,R4,null,$,P)}for(j in $)if(P=$[j],d=B[j],$.hasOwnProperty(j)&&P!==d&&(P!=null||d!=null))switch(j){case"selected":Z.selected=P&&typeof P!=="function"&&typeof P!=="symbol";break;default:jZ(Z,G,j,P,$,d)}return;case"img":case"link":case"area":case"base":case"br":case"col":case"embed":case"hr":case"keygen":case"meta":case"param":case"source":case"track":case"wbr":case"menuitem":for(var v4 in B)P=B[v4],B.hasOwnProperty(v4)&&P!=null&&!$.hasOwnProperty(v4)&&jZ(Z,G,v4,null,$,P);for(U in $)if(P=$[U],d=B[U],$.hasOwnProperty(U)&&P!==d&&(P!=null||d!=null))switch(U){case"children":case"dangerouslySetInnerHTML":if(P!=null)throw Error(G+" is a void element tag and must neither have `children` nor use `dangerouslySetInnerHTML`.");break;default:jZ(Z,G,U,P,$,d)}return;default:if(x5(G)){for(var OZ in B)P=B[OZ],B.hasOwnProperty(OZ)&&P!==void 0&&!$.hasOwnProperty(OZ)&&VJ(Z,G,OZ,void 0,$,P);for(k in $)P=$[k],d=B[k],!$.hasOwnProperty(k)||P===d||P===void 0&&d===void 0||VJ(Z,G,k,P,$,d);return}}for(var l7 in B)P=B[l7],B.hasOwnProperty(l7)&&P!=null&&!$.hasOwnProperty(l7)&&jZ(Z,G,l7,null,$,P);for(y in $)P=$[y],d=B[y],!$.hasOwnProperty(y)||P===d||P==null&&d==null||jZ(Z,G,y,P,$,d)}function rY(Z){switch(Z){case"class":return"className";case"for":return"htmlFor";default:return Z}}function OJ(Z){var G={};Z=Z.style;for(var B=0;B<Z.length;B++){var $=Z[B];G[$]=Z.getPropertyValue($)}return G}function nY(Z,G,B){if(G!=null&&typeof G!=="object")console.error("The `style` prop expects a mapping from style properties to values, not a string. For example, style={{marginRight: spacing + 'em'}} when using JSX.");else{var $,z=$="",Q;for(Q in G)if(G.hasOwnProperty(Q)){var q=G[Q];q!=null&&typeof q!=="boolean"&&q!==""&&(Q.indexOf("--")===0?(M2(q,Q),$+=z+Q+":"+(""+q).trim()):typeof q!=="number"||q===0||qK.has(Q)?(M2(q,Q),$+=z+Q.replace(BK,"-$1").toLowerCase().replace($K,"-ms-")+":"+(""+q).trim()):$+=z+Q.replace(BK,"-$1").toLowerCase().replace($K,"-ms-")+":"+q+"px",z=";")}$=$||null,G=Z.getAttribute("style"),G!==$&&($=h8($),h8(G)!==$&&(B.style=OJ(Z)))}}function m5(Z,G,B,$,z,Q){if(z.delete(B),Z=Z.getAttribute(B),Z===null)switch(typeof $){case"undefined":case"function":case"symbol":case"boolean":return}else if($!=null)switch(typeof $){case"function":case"symbol":case"boolean":break;default:if(s7($,G),Z===""+$)return}U2(G,Z,$,Q)}function tY(Z,G,B,$,z,Q){if(z.delete(B),Z=Z.getAttribute(B),Z===null){switch(typeof $){case"function":case"symbol":return}if(!$)return}else switch(typeof $){case"function":case"symbol":break;default:if($)return}U2(G,Z,$,Q)}function FJ(Z,G,B,$,z,Q){if(z.delete(B),Z=Z.getAttribute(B),Z===null)switch(typeof $){case"undefined":case"function":case"symbol":return}else if($!=null)switch(typeof $){case"function":case"symbol":break;default:if(s7($,B),Z===""+$)return}U2(G,Z,$,Q)}function eY(Z,G,B,$,z,Q){if(z.delete(B),Z=Z.getAttribute(B),Z===null)switch(typeof $){case"undefined":case"function":case"symbol":case"boolean":return;default:if(isNaN($))return}else if($!=null)switch(typeof $){case"function":case"symbol":case"boolean":break;default:if(!isNaN($)&&(s7($,G),Z===""+$))return}U2(G,Z,$,Q)}function RJ(Z,G,B,$,z,Q){if(z.delete(B),Z=Z.getAttribute(B),Z===null)switch(typeof $){case"undefined":case"function":case"symbol":case"boolean":return}else if($!=null)switch(typeof $){case"function":case"symbol":case"boolean":break;default:if(s7($,G),B=F9(""+$),Z===B)return}U2(G,Z,$,Q)}function Zj(Z,G,B,$){for(var z={},Q=new Set,q=Z.attributes,X=0;X<q.length;X++)switch(q[X].name.toLowerCase()){case"value":break;case"checked":break;case"selected":break;default:Q.add(q[X].name)}if(x5(G)){for(var j in B)if(B.hasOwnProperty(j)){var U=B[j];if(U!=null){if(k9.hasOwnProperty(j))typeof U!=="function"&&T6(j,U);else if(B.suppressHydrationWarning!==!0)switch(j){case"children":typeof U!=="string"&&typeof U!=="number"||U2("children",Z.textContent,U,z);continue;case"suppressContentEditableWarning":case"suppressHydrationWarning":case"defaultValue":case"defaultChecked":case"innerHTML":case"ref":continue;case"dangerouslySetInnerHTML":q=Z.innerHTML,U=U?U.__html:void 0,U!=null&&(U=iY(Z,U),U2(j,q,U,z));continue;case"style":Q.delete(j),nY(Z,U,z);continue;case"offsetParent":case"offsetTop":case"offsetLeft":case"offsetWidth":case"offsetHeight":case"isContentEditable":case"outerText":case"outerHTML":Q.delete(j.toLowerCase()),console.error("Assignment to read-only property will result in a no-op: `%s`",j);continue;case"className":Q.delete("class"),q=X7(Z,"class",U),U2("className",q,U,z);continue;default:$.context===M8&&G!=="svg"&&G!=="math"?Q.delete(j.toLowerCase()):Q.delete(j),q=X7(Z,j,U),U2(j,q,U,z)}}}}else for(U in B)if(B.hasOwnProperty(U)&&(j=B[U],j!=null)){if(k9.hasOwnProperty(U))typeof j!=="function"&&T6(U,j);else if(B.suppressHydrationWarning!==!0)switch(U){case"children":typeof j!=="string"&&typeof j!=="number"||U2("children",Z.textContent,j,z);continue;case"suppressContentEditableWarning":case"suppressHydrationWarning":case"value":case"checked":case"selected":case"defaultValue":case"defaultChecked":case"innerHTML":case"ref":continue;case"dangerouslySetInnerHTML":q=Z.innerHTML,j=j?j.__html:void 0,j!=null&&(j=iY(Z,j),q!==j&&(z[U]={__html:q}));continue;case"className":m5(Z,U,"class",j,Q,z);continue;case"tabIndex":m5(Z,U,"tabindex",j,Q,z);continue;case"style":Q.delete(U),nY(Z,j,z);continue;case"multiple":Q.delete(U),U2(U,Z.multiple,j,z);continue;case"muted":Q.delete(U),U2(U,Z.muted,j,z);continue;case"autoFocus":Q.delete("autofocus"),U2(U,Z.autofocus,j,z);continue;case"data":if(G!=="object"){Q.delete(U),q=Z.getAttribute("data"),U2(U,q,j,z);continue}case"src":case"href":if(!(j!==""||G==="a"&&U==="href"||G==="object"&&U==="data")){U==="src"?console.error('An empty string ("") was passed to the %s attribute. This may cause the browser to download the whole page again over the network. To fix this, either do not render the element at all or pass null to %s instead of an empty string.',U,U):console.error('An empty string ("") was passed to the %s attribute. To fix this, either do not render the element at all or pass null to %s instead of an empty string.',U,U);continue}RJ(Z,U,U,j,Q,z);continue;case"action":case"formAction":if(q=Z.getAttribute(U),typeof j==="function"){Q.delete(U.toLowerCase()),U==="formAction"?(Q.delete("name"),Q.delete("formenctype"),Q.delete("formmethod"),Q.delete("formtarget")):(Q.delete("enctype"),Q.delete("method"),Q.delete("target"));continue}else if(q===DV){Q.delete(U.toLowerCase()),U2(U,"function",j,z);continue}RJ(Z,U,U.toLowerCase(),j,Q,z);continue;case"xlinkHref":RJ(Z,U,"xlink:href",j,Q,z);continue;case"contentEditable":FJ(Z,U,"contenteditable",j,Q,z);continue;case"spellCheck":FJ(Z,U,"spellcheck",j,Q,z);continue;case"draggable":case"autoReverse":case"externalResourcesRequired":case"focusable":case"preserveAlpha":FJ(Z,U,U,j,Q,z);continue;case"allowFullScreen":case"async":case"autoPlay":case"controls":case"default":case"defer":case"disabled":case"disablePictureInPicture":case"disableRemotePlayback":case"formNoValidate":case"hidden":case"loop":case"noModule":case"noValidate":case"open":case"playsInline":case"readOnly":case"required":case"reversed":case"scoped":case"seamless":case"itemScope":tY(Z,U,U.toLowerCase(),j,Q,z);continue;case"capture":case"download":Z:{X=Z;var k=q=U,y=z;if(Q.delete(k),X=X.getAttribute(k),X===null)switch(typeof j){case"undefined":case"function":case"symbol":break Z;default:if(j===!1)break Z}else if(j!=null)switch(typeof j){case"function":case"symbol":break;case"boolean":if(j===!0&&X==="")break Z;break;default:if(s7(j,q),X===""+j)break Z}U2(q,X,j,y)}continue;case"cols":case"rows":case"size":case"span":Z:{if(X=Z,k=q=U,y=z,Q.delete(k),X=X.getAttribute(k),X===null)switch(typeof j){case"undefined":case"function":case"symbol":case"boolean":break Z;default:if(isNaN(j)||1>j)break Z}else if(j!=null)switch(typeof j){case"function":case"symbol":case"boolean":break;default:if(!(isNaN(j)||1>j)&&(s7(j,q),X===""+j))break Z}U2(q,X,j,y)}continue;case"rowSpan":eY(Z,U,"rowspan",j,Q,z);continue;case"start":eY(Z,U,U,j,Q,z);continue;case"xHeight":m5(Z,U,"x-height",j,Q,z);continue;case"xlinkActuate":m5(Z,U,"xlink:actuate",j,Q,z);continue;case"xlinkArcrole":m5(Z,U,"xlink:arcrole",j,Q,z);continue;case"xlinkRole":m5(Z,U,"xlink:role",j,Q,z);continue;case"xlinkShow":m5(Z,U,"xlink:show",j,Q,z);continue;case"xlinkTitle":m5(Z,U,"xlink:title",j,Q,z);continue;case"xlinkType":m5(Z,U,"xlink:type",j,Q,z);continue;case"xmlBase":m5(Z,U,"xml:base",j,Q,z);continue;case"xmlLang":m5(Z,U,"xml:lang",j,Q,z);continue;case"xmlSpace":m5(Z,U,"xml:space",j,Q,z);continue;case"inert":j!==""||Dz[U]||(Dz[U]=!0,console.error("Received an empty string for a boolean attribute `%s`. This will treat the attribute as if it were false. Either pass `false` to silence this warning, or pass `true` if you used an empty string in earlier versions of React to indicate this attribute is true.",U)),tY(Z,U,U,j,Q,z);continue;default:if(!(2<U.length)||U[0]!=="o"&&U[0]!=="O"||U[1]!=="n"&&U[1]!=="N"){X=gZ(U),q=!1,$.context===M8&&G!=="svg"&&G!=="math"?Q.delete(X.toLowerCase()):(k=U.toLowerCase(),k=y$.hasOwnProperty(k)?y$[k]||null:null,k!==null&&k!==U&&(q=!0,Q.delete(k)),Q.delete(X));Z:if(k=Z,y=X,X=j,f7(y))if(k.hasAttribute(y))k=k.getAttribute(y),s7(X,y),X=k===""+X?X:k;else{switch(typeof X){case"function":case"symbol":break Z;case"boolean":if(k=y.toLowerCase().slice(0,5),k!=="data-"&&k!=="aria-")break Z}X=X===void 0?void 0:null}else X=void 0;q||U2(U,X,j,z)}}}return 0<Q.size&&B.suppressHydrationWarning!==!0&&HL(Z,Q,z),Object.keys(z).length===0?null:z}function YL(Z,G){switch(Z.length){case 0:return"";case 1:return Z[0];case 2:return Z[0]+" "+G+" "+Z[1];default:return Z.slice(0,-1).join(", ")+", "+G+" "+Z[Z.length-1]}}function Gj(Z){switch(Z){case"css":case"script":case"font":case"img":case"image":case"input":case"link":return!0;default:return!1}}function jL(){if(typeof performance.getEntriesByType==="function"){for(var Z=0,G=0,B=performance.getEntriesByType("resource"),$=0;$<B.length;$++){var z=B[$],Q=z.transferSize,q=z.initiatorType,X=z.duration;if(Q&&X&&Gj(q)){q=0,X=z.responseEnd;for($+=1;$<B.length;$++){var j=B[$],U=j.startTime;if(U>X)break;var{transferSize:k,initiatorType:y}=j;k&&Gj(y)&&(j=j.responseEnd,q+=k*(j<X?1:(X-U)/(j-U)))}if(--$,G+=8*(Q+q)/(z.duration/1000),Z++,10<Z)break}}if(0<Z)return G/Z/1e6}return navigator.connection&&(Z=navigator.connection.downlink,typeof Z==="number")?Z:5}function V$(Z){return Z.nodeType===9?Z:Z.ownerDocument}function Bj(Z){switch(Z){case lG:return M0;case k$:return Az;default:return M8}}function $j(Z,G){if(Z===M8)switch(G){case"svg":return M0;case"math":return Az;default:return M8}return Z===M0&&G==="foreignObject"?M8:Z}function MJ(Z,G){return Z==="textarea"||Z==="noscript"||typeof G.children==="string"||typeof G.children==="number"||typeof G.children==="bigint"||typeof G.dangerouslySetInnerHTML==="object"&&G.dangerouslySetInnerHTML!==null&&G.dangerouslySetInnerHTML.__html!=null}function KL(){var Z=window.event;if(Z&&Z.type==="popstate"){if(Z===zH)return!1;return zH=Z,!0}return zH=null,!1}function L1(){var Z=window.event;return Z&&Z!==jB?Z.type:null}function U1(){var Z=window.event;return Z&&Z!==jB?Z.timeStamp:-1.1}function WL(Z){setTimeout(function(){throw Z})}function _L(Z,G,B){switch(G){case"button":case"input":case"select":case"textarea":B.autoFocus&&Z.focus();break;case"img":B.src?Z.src=B.src:B.srcSet&&(Z.srcset=B.srcSet)}}function LL(){}function UL(Z,G,B,$){XL(Z,G,B,$),Z[p2]=$}function zj(Z){WG(Z,"")}function VL(Z,G,B){Z.nodeValue=B}function Qj(Z){if(!Z.__reactWarnedAboutChildrenConflict){var G=Z[p2]||null;if(G!==null){var B=x4(Z);B!==null&&(typeof G.children==="string"||typeof G.children==="number"?(Z.__reactWarnedAboutChildrenConflict=!0,M4(B,function(){console.error('Cannot use a ref on a React element as a container to `createRoot` or `createPortal` if that element also sets "children" text content using React. It should be a leaf with no children. Otherwise it\'s ambiguous which children should be used.')})):G.dangerouslySetInnerHTML!=null&&(Z.__reactWarnedAboutChildrenConflict=!0,M4(B,function(){console.error('Cannot use a ref on a React element as a container to `createRoot` or `createPortal` if that element also sets "dangerouslySetInnerHTML" using React. It should be a leaf with no children. Otherwise it\'s ambiguous which children should be used.')})))}}}function u8(Z){return Z==="head"}function OL(Z,G){Z.removeChild(G)}function FL(Z,G){(Z.nodeType===9?Z.body:Z.nodeName==="HTML"?Z.ownerDocument.body:Z).removeChild(G)}function Jj(Z,G){var B=G,$=0;do{var z=B.nextSibling;if(Z.removeChild(B),z&&z.nodeType===8)if(B=z.data,B===YB||B===Pz){if($===0){Z.removeChild(z),mG(G);return}$--}else if(B===XB||B===j9||B===e9||B===R0||B===t9)$++;else if(B===AV)V1(Z.ownerDocument.documentElement);else if(B===TV){B=Z.ownerDocument.head,V1(B);for(var Q=B.firstChild;Q;){var{nextSibling:q,nodeName:X}=Q;Q[P1]||X==="SCRIPT"||X==="STYLE"||X==="LINK"&&Q.rel.toLowerCase()==="stylesheet"||B.removeChild(Q),Q=q}}else B===CV&&V1(Z.ownerDocument.body);B=z}while(B);mG(G)}function qj(Z,G){var B=Z;Z=0;do{var $=B.nextSibling;if(B.nodeType===1?G?(B._stashedDisplay=B.style.display,B.style.display="none"):(B.style.display=B._stashedDisplay||"",B.getAttribute("style")===""&&B.removeAttribute("style")):B.nodeType===3&&(G?(B._stashedText=B.nodeValue,B.nodeValue=""):B.nodeValue=B._stashedText||""),$&&$.nodeType===8)if(B=$.data,B===YB)if(Z===0)break;else Z--;else B!==XB&&B!==j9&&B!==e9&&B!==R0||Z++;B=$}while(B)}function RL(Z){qj(Z,!0)}function ML(Z){Z=Z.style,typeof Z.setProperty==="function"?Z.setProperty("display","none","important"):Z.display="none"}function NL(Z){Z.nodeValue=""}function DL(Z){qj(Z,!1)}function PL(Z,G){G=G[EV],G=G!==void 0&&G!==null&&G.hasOwnProperty("display")?G.display:null,Z.style.display=G==null||typeof G==="boolean"?"":(""+G).trim()}function AL(Z,G){Z.nodeValue=G}function NJ(Z){var G=Z.firstChild;G&&G.nodeType===10&&(G=G.nextSibling);for(;G;){var B=G;switch(G=G.nextSibling,B.nodeName){case"HTML":case"HEAD":case"BODY":NJ(B),H4(B);continue;case"SCRIPT":case"STYLE":continue;case"LINK":if(B.rel.toLowerCase()==="stylesheet")continue}Z.removeChild(B)}}function CL(Z,G,B,$){for(;Z.nodeType===1;){var z=B;if(Z.nodeName.toLowerCase()!==G.toLowerCase()){if(!$&&(Z.nodeName!=="INPUT"||Z.type!=="hidden"))break}else if(!$)if(G==="input"&&Z.type==="hidden"){s7(z.name,"name");var Q=z.name==null?null:""+z.name;if(z.type==="hidden"&&Z.getAttribute("name")===Q)return Z}else return Z;else if(!Z[P1])switch(G){case"meta":if(!Z.hasAttribute("itemprop"))break;return Z;case"link":if(Q=Z.getAttribute("rel"),Q==="stylesheet"&&Z.hasAttribute("data-precedence"))break;else if(Q!==z.rel||Z.getAttribute("href")!==(z.href==null||z.href===""?null:z.href)||Z.getAttribute("crossorigin")!==(z.crossOrigin==null?null:z.crossOrigin)||Z.getAttribute("title")!==(z.title==null?null:z.title))break;return Z;case"style":if(Z.hasAttribute("data-precedence"))break;return Z;case"script":if(Q=Z.getAttribute("src"),(Q!==(z.src==null?null:z.src)||Z.getAttribute("type")!==(z.type==null?null:z.type)||Z.getAttribute("crossorigin")!==(z.crossOrigin==null?null:z.crossOrigin))&&Q&&Z.hasAttribute("async")&&!Z.hasAttribute("itemprop"))break;return Z;default:return Z}if(Z=F5(Z.nextSibling),Z===null)break}return null}function TL(Z,G,B){if(G==="")return null;for(;Z.nodeType!==3;){if((Z.nodeType!==1||Z.nodeName!=="INPUT"||Z.type!=="hidden")&&!B)return null;if(Z=F5(Z.nextSibling),Z===null)return null}return Z}function Hj(Z,G){for(;Z.nodeType!==8;){if((Z.nodeType!==1||Z.nodeName!=="INPUT"||Z.type!=="hidden")&&!G)return null;if(Z=F5(Z.nextSibling),Z===null)return null}return Z}function DJ(Z){return Z.data===j9||Z.data===e9}function PJ(Z){return Z.data===R0||Z.data===j9&&Z.ownerDocument.readyState!==nW}function EL(Z,G){var B=Z.ownerDocument;if(Z.data===e9)Z._reactRetry=G;else if(Z.data!==j9||B.readyState!==nW)G();else{var $=function(){G(),B.removeEventListener("DOMContentLoaded",$)};B.addEventListener("DOMContentLoaded",$),Z._reactRetry=$}}function F5(Z){for(;Z!=null;Z=Z.nextSibling){var G=Z.nodeType;if(G===1||G===3)break;if(G===8){if(G=Z.data,G===XB||G===R0||G===j9||G===e9||G===t9||G===GH||G===rW)break;if(G===YB||G===Pz)return null}}return Z}function Xj(Z){if(Z.nodeType===1){for(var G=Z.nodeName.toLowerCase(),B={},$=Z.attributes,z=0;z<$.length;z++){var Q=$[z];B[rY(Q.name)]=Q.name.toLowerCase()==="style"?OJ(Z):Q.value}return{type:G,props:B}}return Z.nodeType===8?Z.data===t9?{type:"Activity",props:{}}:{type:"Suspense",props:{}}:Z.nodeValue}function Yj(Z,G,B){return B===null||B[PV]!==!0?(Z.nodeValue===G?Z=null:(G=h8(G),Z=h8(Z.nodeValue)===G?null:Z.nodeValue),Z):null}function AJ(Z){Z=Z.nextSibling;for(var G=0;Z;){if(Z.nodeType===8){var B=Z.data;if(B===YB||B===Pz){if(G===0)return F5(Z.nextSibling);G--}else B!==XB&&B!==R0&&B!==j9&&B!==e9&&B!==t9||G++}Z=Z.nextSibling}return null}function jj(Z){Z=Z.previousSibling;for(var G=0;Z;){if(Z.nodeType===8){var B=Z.data;if(B===XB||B===R0||B===j9||B===e9||B===t9){if(G===0)return Z;G--}else B!==YB&&B!==Pz||G++}Z=Z.previousSibling}return null}function wL(Z){mG(Z)}function IL(Z){mG(Z)}function xL(Z){mG(Z)}function Kj(Z,G,B,$,z){switch(z&&wB(Z,$.ancestorInfo),G=V$(B),Z){case"html":if(Z=G.documentElement,!Z)throw Error("React expected an <html> element (document.documentElement) to exist in the Document but one was not found. React never removes the documentElement for any Document it renders into so the cause is likely in some other script running on this page.");return Z;case"head":if(Z=G.head,!Z)throw Error("React expected a <head> element (document.head) to exist in the Document but one was not found. React never removes the head for any Document it renders into so the cause is likely in some other script running on this page.");return Z;case"body":if(Z=G.body,!Z)throw Error("React expected a <body> element (document.body) to exist in the Document but one was not found. React never removes the body for any Document it renders into so the cause is likely in some other script running on this page.");return Z;default:throw Error("resolveSingletonInstance was called with an element type that is not supported. This is a bug in React.")}}function SL(Z,G,B,$){if(!B[l8]&&x4(B)){var z=B.tagName.toLowerCase();console.error("You are mounting a new %s component when a previous one has not first unmounted. It is an error to render more than one %s component at a time and attributes and children of these components will likely fail in unpredictable ways. Please only render a single instance of <%s> and if you need to mount a new one, ensure any previous ones have unmounted first.",z,z,z)}switch(Z){case"html":case"head":case"body":break;default:console.error("acquireSingletonInstance was called with an element type that is not supported. This is a bug in React.")}for(z=B.attributes;z.length;)B.removeAttributeNode(z[0]);T2(B,Z,G),B[E2]=$,B[p2]=G}function V1(Z){for(var G=Z.attributes;G.length;)Z.removeAttributeNode(G[0]);H4(Z)}function O$(Z){return typeof Z.getRootNode==="function"?Z.getRootNode():Z.nodeType===9?Z:Z.ownerDocument}function Wj(Z,G,B){var $=N0;if($&&typeof G==="string"&&G){var z=D2(G);z='link[rel="'+Z+'"][href="'+z+'"]',typeof B==="string"&&(z+='[crossorigin="'+B+'"]'),$_.has(z)||($_.add(z),Z={rel:Z,crossOrigin:B,href:G},$.querySelector(z)===null&&(G=$.createElement("link"),T2(G,"link",Z),Q4(G),$.head.appendChild(G)))}}function _j(Z,G,B,$){var z=(z=p8.current)?O$(z):null;if(!z)throw Error('"resourceRoot" was expected to exist. This is a bug in React.');switch(Z){case"meta":case"title":return null;case"style":return typeof B.precedence==="string"&&typeof B.href==="string"?(B=bG(B.href),G=E4(z).hoistableStyles,$=G.get(B),$||($={type:"style",instance:null,count:0,state:null},G.set(B,$)),$):{type:"void",instance:null,count:0,state:null};case"link":if(B.rel==="stylesheet"&&typeof B.href==="string"&&typeof B.precedence==="string"){Z=bG(B.href);var Q=E4(z).hoistableStyles,q=Q.get(Z);if(!q&&(z=z.ownerDocument||z,q={type:"stylesheet",instance:null,count:0,state:{loading:GG,preload:null}},Q.set(Z,q),(Q=z.querySelector(O1(Z)))&&!Q._p&&(q.instance=Q,q.state.loading=KB|r5),!n5.has(Z))){var X={rel:"preload",as:"style",href:B.href,crossOrigin:B.crossOrigin,integrity:B.integrity,media:B.media,hrefLang:B.hrefLang,referrerPolicy:B.referrerPolicy};n5.set(Z,X),Q||vL(z,Z,X,q.state)}if(G&&$===null)throw B=`

  - `+F$(G)+`
  + `+F$(B),Error("Expected <link> not to update to be updated to a stylesheet with precedence. Check the `rel`, `href`, and `precedence` props of this component. Alternatively, check whether two different <link> components render in the same slot or share the same key."+B);return q}if(G&&$!==null)throw B=`

  - `+F$(G)+`
  + `+F$(B),Error("Expected stylesheet with precedence to not be updated to a different kind of <link>. Check the `rel`, `href`, and `precedence` props of this component. Alternatively, check whether two different <link> components render in the same slot or share the same key."+B);return null;case"script":return G=B.async,B=B.src,typeof B==="string"&&G&&typeof G!=="function"&&typeof G!=="symbol"?(B=fG(B),G=E4(z).hoistableScripts,$=G.get(B),$||($={type:"script",instance:null,count:0,state:null},G.set(B,$)),$):{type:"void",instance:null,count:0,state:null};default:throw Error('getResource encountered a type it did not expect: "'+Z+'". this is a bug in React.')}}function F$(Z){var G=0,B="<link";return typeof Z.rel==="string"?(G++,B+=' rel="'+Z.rel+'"'):$6.call(Z,"rel")&&(G++,B+=' rel="'+(Z.rel===null?"null":"invalid type "+typeof Z.rel)+'"'),typeof Z.href==="string"?(G++,B+=' href="'+Z.href+'"'):$6.call(Z,"href")&&(G++,B+=' href="'+(Z.href===null?"null":"invalid type "+typeof Z.href)+'"'),typeof Z.precedence==="string"?(G++,B+=' precedence="'+Z.precedence+'"'):$6.call(Z,"precedence")&&(G++,B+=" precedence={"+(Z.precedence===null?"null":"invalid type "+typeof Z.precedence)+"}"),Object.getOwnPropertyNames(Z).length>G&&(B+=" ..."),B+" />"}function bG(Z){return'href="'+D2(Z)+'"'}function O1(Z){return'link[rel="stylesheet"]['+Z+"]"}function Lj(Z){return k7({},Z,{"data-precedence":Z.precedence,precedence:null})}function vL(Z,G,B,$){Z.querySelector('link[rel="preload"][as="style"]['+G+"]")?$.loading=KB:(G=Z.createElement("link"),$.preload=G,G.addEventListener("load",function(){return $.loading|=KB}),G.addEventListener("error",function(){return $.loading|=G_}),T2(G,"link",B),Q4(G),Z.head.appendChild(G))}function fG(Z){return'[src="'+D2(Z)+'"]'}function F1(Z){return"script[async]"+Z}function Uj(Z,G,B){if(G.count++,G.instance===null)switch(G.type){case"style":var $=Z.querySelector('style[data-href~="'+D2(B.href)+'"]');if($)return G.instance=$,Q4($),$;var z=k7({},B,{"data-href":B.href,"data-precedence":B.precedence,href:null,precedence:null});return $=(Z.ownerDocument||Z).createElement("style"),Q4($),T2($,"style",z),R$($,B.precedence,Z),G.instance=$;case"stylesheet":z=bG(B.href);var Q=Z.querySelector(O1(z));if(Q)return G.state.loading|=r5,G.instance=Q,Q4(Q),Q;$=Lj(B),(z=n5.get(z))&&CJ($,z),Q=(Z.ownerDocument||Z).createElement("link"),Q4(Q);var q=Q;return q._p=new Promise(function(X,j){q.onload=X,q.onerror=j}),T2(Q,"link",$),G.state.loading|=r5,R$(Q,B.precedence,Z),G.instance=Q;case"script":if(Q=fG(B.src),z=Z.querySelector(F1(Q)))return G.instance=z,Q4(z),z;if($=B,z=n5.get(Q))$=k7({},B),TJ($,z);return Z=Z.ownerDocument||Z,z=Z.createElement("script"),Q4(z),T2(z,"link",$),Z.head.appendChild(z),G.instance=z;case"void":return null;default:throw Error('acquireResource encountered a resource type it did not expect: "'+G.type+'". this is a bug in React.')}else G.type==="stylesheet"&&(G.state.loading&r5)===GG&&($=G.instance,G.state.loading|=r5,R$($,B.precedence,Z));return G.instance}function R$(Z,G,B){for(var $=B.querySelectorAll('link[rel="stylesheet"][data-precedence],style[data-precedence]'),z=$.length?$[$.length-1]:null,Q=z,q=0;q<$.length;q++){var X=$[q];if(X.dataset.precedence===G)Q=X;else if(Q!==z)break}Q?Q.parentNode.insertBefore(Z,Q.nextSibling):(G=B.nodeType===9?B.head:B,G.insertBefore(Z,G.firstChild))}function CJ(Z,G){Z.crossOrigin==null&&(Z.crossOrigin=G.crossOrigin),Z.referrerPolicy==null&&(Z.referrerPolicy=G.referrerPolicy),Z.title==null&&(Z.title=G.title)}function TJ(Z,G){Z.crossOrigin==null&&(Z.crossOrigin=G.crossOrigin),Z.referrerPolicy==null&&(Z.referrerPolicy=G.referrerPolicy),Z.integrity==null&&(Z.integrity=G.integrity)}function Vj(Z,G,B){if(Cz===null){var $=new Map,z=Cz=new Map;z.set(B,$)}else z=Cz,$=z.get(B),$||($=new Map,z.set(B,$));if($.has(Z))return $;$.set(Z,null),B=B.getElementsByTagName(Z);for(z=0;z<B.length;z++){var Q=B[z];if(!(Q[P1]||Q[E2]||Z==="link"&&Q.getAttribute("rel")==="stylesheet")&&Q.namespaceURI!==lG){var q=Q.getAttribute(G)||"";q=Z+q;var X=$.get(q);X?X.push(Q):$.set(q,[Q])}}return $}function Oj(Z,G,B){Z=Z.ownerDocument||Z,Z.head.insertBefore(B,G==="title"?Z.querySelector("head > title"):null)}function kL(Z,G,B){var $=!B.ancestorInfo.containerTagInScope;if(B.context===M0||G.itemProp!=null)return!$||G.itemProp==null||Z!=="meta"&&Z!=="title"&&Z!=="style"&&Z!=="link"&&Z!=="script"||console.error("Cannot render a <%s> outside the main document if it has an `itemProp` prop. `itemProp` suggests the tag belongs to an `itemScope` which can appear anywhere in the DOM. If you were intending for React to hoist this <%s> remove the `itemProp` prop. Otherwise, try moving this tag into the <head> or <body> of the Document.",Z,Z),!1;switch(Z){case"meta":case"title":return!0;case"style":if(typeof G.precedence!=="string"||typeof G.href!=="string"||G.href===""){$&&console.error('Cannot render a <style> outside the main document without knowing its precedence and a unique href key. React can hoist and deduplicate <style> tags if you provide a `precedence` prop along with an `href` prop that does not conflict with the `href` values used in any other hoisted <style> or <link rel="stylesheet" ...> tags.  Note that hoisting <style> tags is considered an advanced feature that most will not use directly. Consider moving the <style> tag to the <head> or consider adding a `precedence="default"` and `href="some unique resource identifier"`.');break}return!0;case"link":if(typeof G.rel!=="string"||typeof G.href!=="string"||G.href===""||G.onLoad||G.onError){if(G.rel==="stylesheet"&&typeof G.precedence==="string"){Z=G.href;var{onError:z,disabled:Q}=G;B=[],G.onLoad&&B.push("`onLoad`"),z&&B.push("`onError`"),Q!=null&&B.push("`disabled`"),z=YL(B,"and"),z+=B.length===1?" prop":" props",Q=B.length===1?"an "+z:"the "+z,B.length&&console.error('React encountered a <link rel="stylesheet" href="%s" ... /> with a `precedence` prop that also included %s. The presence of loading and error handlers indicates an intent to manage the stylesheet loading state from your from your Component code and React will not hoist or deduplicate this stylesheet. If your intent was to have React hoist and deduplciate this stylesheet using the `precedence` prop remove the %s, otherwise remove the `precedence` prop.',Z,Q,z)}$&&(typeof G.rel!=="string"||typeof G.href!=="string"||G.href===""?console.error("Cannot render a <link> outside the main document without a `rel` and `href` prop. Try adding a `rel` and/or `href` prop to this <link> or moving the link into the <head> tag"):(G.onError||G.onLoad)&&console.error("Cannot render a <link> with onLoad or onError listeners outside the main document. Try removing onLoad={...} and onError={...} or moving it into the root <head> tag or somewhere in the <body>."));break}switch(G.rel){case"stylesheet":return Z=G.precedence,G=G.disabled,typeof Z!=="string"&&$&&console.error('Cannot render a <link rel="stylesheet" /> outside the main document without knowing its precedence. Consider adding precedence="default" or moving it into the root <head> tag.'),typeof Z==="string"&&G==null;default:return!0}case"script":if(Z=G.async&&typeof G.async!=="function"&&typeof G.async!=="symbol",!Z||G.onLoad||G.onError||!G.src||typeof G.src!=="string"){$&&(Z?G.onLoad||G.onError?console.error("Cannot render a <script> with onLoad or onError listeners outside the main document. Try removing onLoad={...} and onError={...} or moving it into the root <head> tag or somewhere in the <body>."):console.error("Cannot render a <script> outside the main document without `async={true}` and a non-empty `src` prop. Ensure there is a valid `src` and either make the script async or move it into the root <head> tag or somewhere in the <body>."):console.error('Cannot render a sync or defer <script> outside the main document without knowing its order. Try adding async="" or moving it into the root <head> tag.'));break}return!0;case"noscript":case"template":$&&console.error("Cannot render <%s> outside the main document. Try moving it into the root <head> tag.",Z)}return!1}function Fj(Z){return Z.type==="stylesheet"&&(Z.state.loading&B_)===GG?!1:!0}function yL(Z,G,B,$){if(B.type==="stylesheet"&&(typeof $.media!=="string"||matchMedia($.media).matches!==!1)&&(B.state.loading&r5)===GG){if(B.instance===null){var z=bG($.href),Q=G.querySelector(O1(z));if(Q){G=Q._p,G!==null&&typeof G==="object"&&typeof G.then==="function"&&(Z.count++,Z=M$.bind(Z),G.then(Z,Z)),B.state.loading|=r5,B.instance=Q,Q4(Q);return}Q=G.ownerDocument||G,$=Lj($),(z=n5.get(z))&&CJ($,z),Q=Q.createElement("link"),Q4(Q);var q=Q;q._p=new Promise(function(X,j){q.onload=X,q.onerror=j}),T2(Q,"link",$),B.instance=Q}Z.stylesheets===null&&(Z.stylesheets=new Map),Z.stylesheets.set(B,G),(G=B.state.preload)&&(B.state.loading&B_)===GG&&(Z.count++,B=M$.bind(Z),G.addEventListener("load",B),G.addEventListener("error",B))}}function gL(Z,G){return Z.stylesheets&&Z.count===0&&N$(Z,Z.stylesheets),0<Z.count||0<Z.imgCount?function(B){var $=setTimeout(function(){if(Z.stylesheets&&N$(Z,Z.stylesheets),Z.unsuspend){var Q=Z.unsuspend;Z.unsuspend=null,Q()}},xV+G);0<Z.imgBytes&&JH===0&&(JH=125*jL()*vV);var z=setTimeout(function(){if(Z.waitingForImages=!1,Z.count===0&&(Z.stylesheets&&N$(Z,Z.stylesheets),Z.unsuspend)){var Q=Z.unsuspend;Z.unsuspend=null,Q()}},(Z.imgBytes>JH?50:SV)+G);return Z.unsuspend=B,function(){Z.unsuspend=null,clearTimeout($),clearTimeout(z)}}:null}function M$(){if(this.count--,this.count===0&&(this.imgCount===0||!this.waitingForImages)){if(this.stylesheets)N$(this,this.stylesheets);else if(this.unsuspend){var Z=this.unsuspend;this.unsuspend=null,Z()}}}function N$(Z,G){Z.stylesheets=null,Z.unsuspend!==null&&(Z.count++,Tz=new Map,G.forEach(bL,Z),Tz=null,M$.call(Z))}function bL(Z,G){if(!(G.state.loading&r5)){var B=Tz.get(Z);if(B)var $=B.get(qH);else{B=new Map,Tz.set(Z,B);for(var z=Z.querySelectorAll("link[data-precedence],style[data-precedence]"),Q=0;Q<z.length;Q++){var q=z[Q];if(q.nodeName==="LINK"||q.getAttribute("media")!=="not all")B.set(q.dataset.precedence,q),$=q}$&&B.set(qH,$)}z=G.instance,q=z.getAttribute("data-precedence"),Q=B.get(q)||$,Q===$&&B.set(qH,z),B.set(q,z),this.count++,$=M$.bind(this),z.addEventListener("load",$),z.addEventListener("error",$),Q?Q.parentNode.insertBefore(z,Q.nextSibling):(Z=Z.nodeType===9?Z.head:Z,Z.insertBefore(z,Z.firstChild)),G.state.loading|=r5}}function fL(Z,G,B,$,z,Q,q,X,j){this.tag=1,this.containerInfo=Z,this.pingCache=this.current=this.pendingChildren=null,this.timeoutHandle=ZG,this.callbackNode=this.next=this.pendingContext=this.context=this.cancelPendingCommit=null,this.callbackPriority=0,this.expirationTimes=A7(-1),this.entangledLanes=this.shellSuspendCounter=this.errorRecoveryDisabledLanes=this.expiredLanes=this.warmLanes=this.pingedLanes=this.suspendedLanes=this.pendingLanes=0,this.entanglements=A7(0),this.hiddenUpdates=A7(null),this.identifierPrefix=$,this.onUncaughtError=z,this.onCaughtError=Q,this.onRecoverableError=q,this.pooledCache=null,this.pooledCacheLanes=0,this.formState=j,this.incompleteTransitions=new Map,this.passiveEffectDuration=this.effectDuration=-0,this.memoizedUpdaters=new Set,Z=this.pendingUpdatersLaneMap=[];for(G=0;31>G;G++)Z.push(new Set);this._debugRootType=B?"hydrateRoot()":"createRoot()"}function Rj(Z,G,B,$,z,Q,q,X,j,U,k,y){return Z=new fL(Z,G,B,q,j,U,k,y,X),G=zV,Q===!0&&(G|=g2|Q6),G|=E7,Q=R(3,null,null,G),Z.current=Q,Q.stateNode=Z,G=o0(),B8(G),Z.pooledCache=G,B8(G),Q.memoizedState={element:$,isDehydrated:B,cache:G},JQ(Q),Z}function Mj(Z){if(!Z)return o8;return Z=o8,Z}function EJ(Z,G,B,$,z,Q){if(y2&&typeof y2.onScheduleFiberRoot==="function")try{y2.onScheduleFiberRoot(pG,$,B)}catch(q){x6||(x6=!0,console.error("React instrumentation encountered an error: %o",q))}z=Mj(z),$.context===null?$.context=z:$.pendingContext=z,I6&&M5!==null&&!q_&&(q_=!0,console.error(`Render methods should be a pure function of props and state; triggering nested component updates from render is not allowed. If necessary, trigger nested updates in componentDidUpdate.

Check the render method of %s.`,Y4(M5)||"Unknown")),$=k8(G),$.payload={element:B},Q=Q===void 0?null:Q,Q!==null&&(typeof Q!=="function"&&console.error("Expected the last optional `callback` argument to be a function. Instead received: %s.",Q),$.callback=Q),B=y8(Z,$,G),B!==null&&(L6(G,"root.render()",null),bZ(B,Z,G),e0(B,Z,G))}function Nj(Z,G){if(Z=Z.memoizedState,Z!==null&&Z.dehydrated!==null){var B=Z.retryLane;Z.retryLane=B!==0&&B<G?B:G}}function wJ(Z,G){Nj(Z,G),(Z=Z.alternate)&&Nj(Z,G)}function Dj(Z){if(Z.tag===13||Z.tag===31){var G=Z2(Z,67108864);G!==null&&bZ(G,Z,67108864),wJ(Z,67108864)}}function Pj(Z){if(Z.tag===13||Z.tag===31){var G=O5(Z);G=S4(G);var B=Z2(Z,G);B!==null&&bZ(B,Z,G),wJ(Z,G)}}function mL(){return M5}function hL(Z,G,B,$){var z=l.T;l.T=null;var Q=BZ.p;try{BZ.p=N5,IJ(Z,G,B,$)}finally{BZ.p=Q,l.T=z}}function uL(Z,G,B,$){var z=l.T;l.T=null;var Q=BZ.p;try{BZ.p=z6,IJ(Z,G,B,$)}finally{BZ.p=Q,l.T=z}}function IJ(Z,G,B,$){if(wz){var z=xJ($);if(z===null)LJ(Z,G,$,Iz,B),Cj(Z,$);else if(dL(z,Z,G,B,$))$.stopPropagation();else if(Cj(Z,$),G&4&&-1<yV.indexOf(Z)){for(;z!==null;){var Q=x4(z);if(Q!==null)switch(Q.tag){case 3:if(Q=Q.stateNode,Q.current.memoizedState.isDehydrated){var q=J7(Q.pendingLanes);if(q!==0){var X=Q;X.pendingLanes|=2;for(X.entangledLanes|=2;q;){var j=1<<31-d2(q);X.entanglements[1]|=j,q&=~j}C6(Q),(i7&(W2|C5))===R2&&(Kz=V2()+yW,W1(0,!1))}}break;case 31:case 13:X=Z2(Q,2),X!==null&&bZ(X,Q,2),kG(),wJ(Q,2)}if(Q=xJ($),Q===null&&LJ(Z,G,$,Iz,B),Q===z)break;z=Q}z!==null&&$.stopPropagation()}else LJ(Z,G,$,null,B)}}function xJ(Z){return Z=T7(Z),SJ(Z)}function SJ(Z){if(Iz=null,Z=e(Z),Z!==null){var G=t(Z);if(G===null)Z=null;else{var B=G.tag;if(B===13){if(Z=I4(G),Z!==null)return Z;Z=null}else if(B===31){if(Z=u4(G),Z!==null)return Z;Z=null}else if(B===3){if(G.stateNode.current.memoizedState.isDehydrated)return G.tag===3?G.stateNode.containerInfo:null;Z=null}else G!==Z&&(Z=null)}}return Iz=Z,null}function Aj(Z){switch(Z){case"beforetoggle":case"cancel":case"click":case"close":case"contextmenu":case"copy":case"cut":case"auxclick":case"dblclick":case"dragend":case"dragstart":case"drop":case"focusin":case"focusout":case"input":case"invalid":case"keydown":case"keypress":case"keyup":case"mousedown":case"mouseup":case"paste":case"pause":case"play":case"pointercancel":case"pointerdown":case"pointerup":case"ratechange":case"reset":case"resize":case"seeked":case"submit":case"toggle":case"touchcancel":case"touchend":case"touchstart":case"volumechange":case"change":case"selectionchange":case"textInput":case"compositionstart":case"compositionend":case"compositionupdate":case"beforeblur":case"afterblur":case"beforeinput":case"blur":case"fullscreenchange":case"focus":case"hashchange":case"popstate":case"select":case"selectstart":return N5;case"drag":case"dragenter":case"dragexit":case"dragleave":case"dragover":case"mousemove":case"mouseout":case"mouseover":case"pointermove":case"pointerout":case"pointerover":case"scroll":case"touchmove":case"wheel":case"mouseenter":case"mouseleave":case"pointerenter":case"pointerleave":return z6;case"message":switch(tL()){case sJ:return N5;case aJ:return z6;case dG:case eL:return v6;case iJ:return S$;default:return v6}default:return v6}}function Cj(Z,G){switch(Z){case"focusin":case"focusout":K9=null;break;case"dragenter":case"dragleave":W9=null;break;case"mouseover":case"mouseout":_9=null;break;case"pointerover":case"pointerout":_B.delete(G.pointerId);break;case"gotpointercapture":case"lostpointercapture":LB.delete(G.pointerId)}}function R1(Z,G,B,$,z,Q){if(Z===null||Z.nativeEvent!==Q)return Z={blockedOn:G,domEventName:B,eventSystemFlags:$,nativeEvent:Q,targetContainers:[z]},G!==null&&(G=x4(G),G!==null&&Dj(G)),Z;return Z.eventSystemFlags|=$,G=Z.targetContainers,z!==null&&G.indexOf(z)===-1&&G.push(z),Z}function dL(Z,G,B,$,z){switch(G){case"focusin":return K9=R1(K9,Z,G,B,$,z),!0;case"dragenter":return W9=R1(W9,Z,G,B,$,z),!0;case"mouseover":return _9=R1(_9,Z,G,B,$,z),!0;case"pointerover":var Q=z.pointerId;return _B.set(Q,R1(_B.get(Q)||null,Z,G,B,$,z)),!0;case"gotpointercapture":return Q=z.pointerId,LB.set(Q,R1(LB.get(Q)||null,Z,G,B,$,z)),!0}return!1}function Tj(Z){var G=e(Z.target);if(G!==null){var B=t(G);if(B!==null){if(G=B.tag,G===13){if(G=I4(B),G!==null){Z.blockedOn=G,a(Z.priority,function(){Pj(B)});return}}else if(G===31){if(G=u4(B),G!==null){Z.blockedOn=G,a(Z.priority,function(){Pj(B)});return}}else if(G===3&&B.stateNode.current.memoizedState.isDehydrated){Z.blockedOn=B.tag===3?B.stateNode.containerInfo:null;return}}}Z.blockedOn=null}function D$(Z){if(Z.blockedOn!==null)return!1;for(var G=Z.targetContainers;0<G.length;){var B=xJ(Z.nativeEvent);if(B===null){B=Z.nativeEvent;var $=new B.constructor(B.type,B),z=$;A1!==null&&console.error("Expected currently replaying event to be null. This error is likely caused by a bug in React. Please file an issue."),A1=z,B.target.dispatchEvent($),A1===null&&console.error("Expected currently replaying event to not be null. This error is likely caused by a bug in React. Please file an issue."),A1=null}else return G=x4(B),G!==null&&Dj(G),Z.blockedOn=B,!1;G.shift()}return!0}function Ej(Z,G,B){D$(Z)&&B.delete(G)}function pL(){HH=!1,K9!==null&&D$(K9)&&(K9=null),W9!==null&&D$(W9)&&(W9=null),_9!==null&&D$(_9)&&(_9=null),_B.forEach(Ej),LB.forEach(Ej)}function P$(Z,G){Z.blockedOn===G&&(Z.blockedOn=null,HH||(HH=!0,B2.unstable_scheduleCallback(B2.unstable_NormalPriority,pL)))}function wj(Z){xz!==Z&&(xz=Z,B2.unstable_scheduleCallback(B2.unstable_NormalPriority,function(){xz===Z&&(xz=null);for(var G=0;G<Z.length;G+=3){var B=Z[G],$=Z[G+1],z=Z[G+2];if(typeof $!=="function")if(SJ($||B)===null)continue;else break;var Q=x4(B);Q!==null&&(Z.splice(G,3),G-=3,B={pending:!0,data:z,method:B.method,action:$},Object.freeze(B),SQ(Q,B,$,z))}}))}function mG(Z){function G(j){return P$(j,Z)}K9!==null&&P$(K9,Z),W9!==null&&P$(W9,Z),_9!==null&&P$(_9,Z),_B.forEach(G),LB.forEach(G);for(var B=0;B<L9.length;B++){var $=L9[B];$.blockedOn===Z&&($.blockedOn=null)}for(;0<L9.length&&(B=L9[0],B.blockedOn===null);)Tj(B),B.blockedOn===null&&L9.shift();if(B=(Z.ownerDocument||Z).$$reactFormReplay,B!=null)for($=0;$<B.length;$+=3){var z=B[$],Q=B[$+1],q=z[p2]||null;if(typeof Q==="function")q||wj(B);else if(q){var X=null;if(Q&&Q.hasAttribute("formAction")){if(z=Q,q=Q[p2]||null)X=q.formAction;else if(SJ(z)!==null)continue}else X=q.action;typeof X==="function"?B[$+1]=X:(B.splice($,3),$-=3),wj(B)}}}function Ij(){function Z(Q){Q.canIntercept&&Q.info==="react-transition"&&Q.intercept({handler:function(){return new Promise(function(q){return z=q})},focusReset:"manual",scroll:"manual"})}function G(){z!==null&&(z(),z=null),$||setTimeout(B,20)}function B(){if(!$&&!navigation.transition){var Q=navigation.currentEntry;Q&&Q.url!=null&&navigation.navigate(Q.url,{state:Q.getState(),info:"react-transition",history:"replace"})}}if(typeof navigation==="object"){var $=!1,z=null;return navigation.addEventListener("navigate",Z),navigation.addEventListener("navigatesuccess",G),navigation.addEventListener("navigateerror",G),setTimeout(B,100),function(){$=!0,navigation.removeEventListener("navigate",Z),navigation.removeEventListener("navigatesuccess",G),navigation.removeEventListener("navigateerror",G),z!==null&&(z(),z=null)}}}function vJ(Z){this._internalRoot=Z}function A$(Z){this._internalRoot=Z}function xj(Z){Z[l8]&&(Z._reactRootContainer?console.error("You are calling ReactDOMClient.createRoot() on a container that was previously passed to ReactDOM.render(). This is not supported."):console.error("You are calling ReactDOMClient.createRoot() on a container that has already been passed to createRoot() before. Instead, call root.render() on the existing root instead if you want to update it."))}typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart(Error());var B2=P_(),kJ=E5(),cL=vz(),k7=Object.assign,lL=Symbol.for("react.element"),E6=Symbol.for("react.transitional.element"),hG=Symbol.for("react.portal"),uG=Symbol.for("react.fragment"),C$=Symbol.for("react.strict_mode"),yJ=Symbol.for("react.profiler"),gJ=Symbol.for("react.consumer"),w6=Symbol.for("react.context"),M1=Symbol.for("react.forward_ref"),bJ=Symbol.for("react.suspense"),fJ=Symbol.for("react.suspense_list"),T$=Symbol.for("react.memo"),R5=Symbol.for("react.lazy"),mJ=Symbol.for("react.activity"),sL=Symbol.for("react.memo_cache_sentinel"),Sj=Symbol.iterator,aL=Symbol.for("react.client.reference"),j2=Array.isArray,l=kJ.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE,BZ=cL.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE,iL=Object.freeze({pending:!1,data:null,method:null,action:null}),hJ=[],uJ=[],q8=-1,d8=l4(null),N1=l4(null),p8=l4(null),E$=l4(null),D1=0,vj,kj,yj,gj,bj,fj,mj;R7.__reactDisabledLog=!0;var dJ,hj,pJ=!1,cJ=new(typeof WeakMap==="function"?WeakMap:Map),M5=null,I6=!1,$6=Object.prototype.hasOwnProperty,lJ=B2.unstable_scheduleCallback,oL=B2.unstable_cancelCallback,rL=B2.unstable_shouldYield,nL=B2.unstable_requestPaint,V2=B2.unstable_now,tL=B2.unstable_getCurrentPriorityLevel,sJ=B2.unstable_ImmediatePriority,aJ=B2.unstable_UserBlockingPriority,dG=B2.unstable_NormalPriority,eL=B2.unstable_LowPriority,iJ=B2.unstable_IdlePriority,ZU=B2.log,GU=B2.unstable_setDisableYieldValue,pG=null,y2=null,x6=!1,S6=typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u",d2=Math.clz32?Math.clz32:z7,BU=Math.log,$U=Math.LN2,w$=256,I$=262144,x$=4194304,N5=2,z6=8,v6=32,S$=268435456,c8=Math.random().toString(36).slice(2),E2="__reactFiber$"+c8,p2="__reactProps$"+c8,l8="__reactContainer$"+c8,oJ="__reactEvents$"+c8,zU="__reactListeners$"+c8,QU="__reactHandles$"+c8,uj="__reactResources$"+c8,P1="__reactMarker$"+c8,dj=new Set,k9={},rJ={},JU={button:!0,checkbox:!0,image:!0,hidden:!0,radio:!0,reset:!0,submit:!0},qU=RegExp("^[:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD][:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$"),pj={},cj={},HU=/[\n"\\]/g,lj=!1,sj=!1,aj=!1,ij=!1,oj=!1,rj=!1,nj=["value","defaultValue"],tj=!1,ej=/["'&<>\n\t]|^\s|\s$/,XU="address applet area article aside base basefont bgsound blockquote body br button caption center col colgroup dd details dir div dl dt embed fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html iframe img input isindex li link listing main marquee menu menuitem meta nav noembed noframes noscript object ol p param plaintext pre script section select source style summary table tbody td template textarea tfoot th thead title tr track ul wbr xmp".split(" "),ZK="applet caption html table td th marquee object template foreignObject desc title".split(" "),YU=ZK.concat(["button"]),jU="dd dt li option optgroup p rp rt".split(" "),GK={current:null,formTag:null,aTagInScope:null,buttonTagInScope:null,nobrTagInScope:null,pTagInButtonScope:null,listItemTagAutoclosing:null,dlItemTagAutoclosing:null,containerTagInScope:null,implicitRootScope:!1},v$={},nJ={animation:"animationDelay animationDirection animationDuration animationFillMode animationIterationCount animationName animationPlayState animationTimingFunction".split(" "),background:"backgroundAttachment backgroundClip backgroundColor backgroundImage backgroundOrigin backgroundPositionX backgroundPositionY backgroundRepeat backgroundSize".split(" "),backgroundPosition:["backgroundPositionX","backgroundPositionY"],border:"borderBottomColor borderBottomStyle borderBottomWidth borderImageOutset borderImageRepeat borderImageSlice borderImageSource borderImageWidth borderLeftColor borderLeftStyle borderLeftWidth borderRightColor borderRightStyle borderRightWidth borderTopColor borderTopStyle borderTopWidth".split(" "),borderBlockEnd:["borderBlockEndColor","borderBlockEndStyle","borderBlockEndWidth"],borderBlockStart:["borderBlockStartColor","borderBlockStartStyle","borderBlockStartWidth"],borderBottom:["borderBottomColor","borderBottomStyle","borderBottomWidth"],borderColor:["borderBottomColor","borderLeftColor","borderRightColor","borderTopColor"],borderImage:["borderImageOutset","borderImageRepeat","borderImageSlice","borderImageSource","borderImageWidth"],borderInlineEnd:["borderInlineEndColor","borderInlineEndStyle","borderInlineEndWidth"],borderInlineStart:["borderInlineStartColor","borderInlineStartStyle","borderInlineStartWidth"],borderLeft:["borderLeftColor","borderLeftStyle","borderLeftWidth"],borderRadius:["borderBottomLeftRadius","borderBottomRightRadius","borderTopLeftRadius","borderTopRightRadius"],borderRight:["borderRightColor","borderRightStyle","borderRightWidth"],borderStyle:["borderBottomStyle","borderLeftStyle","borderRightStyle","borderTopStyle"],borderTop:["borderTopColor","borderTopStyle","borderTopWidth"],borderWidth:["borderBottomWidth","borderLeftWidth","borderRightWidth","borderTopWidth"],columnRule:["columnRuleColor","columnRuleStyle","columnRuleWidth"],columns:["columnCount","columnWidth"],flex:["flexBasis","flexGrow","flexShrink"],flexFlow:["flexDirection","flexWrap"],font:"fontFamily fontFeatureSettings fontKerning fontLanguageOverride fontSize fontSizeAdjust fontStretch fontStyle fontVariant fontVariantAlternates fontVariantCaps fontVariantEastAsian fontVariantLigatures fontVariantNumeric fontVariantPosition fontWeight lineHeight".split(" "),fontVariant:"fontVariantAlternates fontVariantCaps fontVariantEastAsian fontVariantLigatures fontVariantNumeric fontVariantPosition".split(" "),gap:["columnGap","rowGap"],grid:"gridAutoColumns gridAutoFlow gridAutoRows gridTemplateAreas gridTemplateColumns gridTemplateRows".split(" "),gridArea:["gridColumnEnd","gridColumnStart","gridRowEnd","gridRowStart"],gridColumn:["gridColumnEnd","gridColumnStart"],gridColumnGap:["columnGap"],gridGap:["columnGap","rowGap"],gridRow:["gridRowEnd","gridRowStart"],gridRowGap:["rowGap"],gridTemplate:["gridTemplateAreas","gridTemplateColumns","gridTemplateRows"],listStyle:["listStyleImage","listStylePosition","listStyleType"],margin:["marginBottom","marginLeft","marginRight","marginTop"],marker:["markerEnd","markerMid","markerStart"],mask:"maskClip maskComposite maskImage maskMode maskOrigin maskPositionX maskPositionY maskRepeat maskSize".split(" "),maskPosition:["maskPositionX","maskPositionY"],outline:["outlineColor","outlineStyle","outlineWidth"],overflow:["overflowX","overflowY"],padding:["paddingBottom","paddingLeft","paddingRight","paddingTop"],placeContent:["alignContent","justifyContent"],placeItems:["alignItems","justifyItems"],placeSelf:["alignSelf","justifySelf"],textDecoration:["textDecorationColor","textDecorationLine","textDecorationStyle"],textEmphasis:["textEmphasisColor","textEmphasisStyle"],transition:["transitionDelay","transitionDuration","transitionProperty","transitionTimingFunction"],wordWrap:["overflowWrap"]},BK=/([A-Z])/g,$K=/^ms-/,KU=/^(?:webkit|moz|o)[A-Z]/,WU=/^-ms-/,_U=/-(.)/g,zK=/;\s*$/,cG={},tJ={},QK=!1,JK=!1,qK=new Set("animationIterationCount aspectRatio borderImageOutset borderImageSlice borderImageWidth boxFlex boxFlexGroup boxOrdinalGroup columnCount columns flex flexGrow flexPositive flexShrink flexNegative flexOrder gridArea gridRow gridRowEnd gridRowSpan gridRowStart gridColumn gridColumnEnd gridColumnSpan gridColumnStart fontWeight lineClamp lineHeight opacity order orphans scale tabSize widows zIndex zoom fillOpacity floodOpacity stopOpacity strokeDasharray strokeDashoffset strokeMiterlimit strokeOpacity strokeWidth MozAnimationIterationCount MozBoxFlex MozBoxFlexGroup MozLineClamp msAnimationIterationCount msFlex msZoom msFlexGrow msFlexNegative msFlexOrder msFlexPositive msFlexShrink msGridColumn msGridColumnSpan msGridRow msGridRowSpan WebkitAnimationIterationCount WebkitBoxFlex WebKitBoxFlexGroup WebkitBoxOrdinalGroup WebkitColumnCount WebkitColumns WebkitFlex WebkitFlexGrow WebkitFlexPositive WebkitFlexShrink WebkitLineClamp".split(" ")),k$="http://www.w3.org/1998/Math/MathML",lG="http://www.w3.org/2000/svg",LU=new Map([["acceptCharset","accept-charset"],["htmlFor","for"],["httpEquiv","http-equiv"],["crossOrigin","crossorigin"],["accentHeight","accent-height"],["alignmentBaseline","alignment-baseline"],["arabicForm","arabic-form"],["baselineShift","baseline-shift"],["capHeight","cap-height"],["clipPath","clip-path"],["clipRule","clip-rule"],["colorInterpolation","color-interpolation"],["colorInterpolationFilters","color-interpolation-filters"],["colorProfile","color-profile"],["colorRendering","color-rendering"],["dominantBaseline","dominant-baseline"],["enableBackground","enable-background"],["fillOpacity","fill-opacity"],["fillRule","fill-rule"],["floodColor","flood-color"],["floodOpacity","flood-opacity"],["fontFamily","font-family"],["fontSize","font-size"],["fontSizeAdjust","font-size-adjust"],["fontStretch","font-stretch"],["fontStyle","font-style"],["fontVariant","font-variant"],["fontWeight","font-weight"],["glyphName","glyph-name"],["glyphOrientationHorizontal","glyph-orientation-horizontal"],["glyphOrientationVertical","glyph-orientation-vertical"],["horizAdvX","horiz-adv-x"],["horizOriginX","horiz-origin-x"],["imageRendering","image-rendering"],["letterSpacing","letter-spacing"],["lightingColor","lighting-color"],["markerEnd","marker-end"],["markerMid","marker-mid"],["markerStart","marker-start"],["overlinePosition","overline-position"],["overlineThickness","overline-thickness"],["paintOrder","paint-order"],["panose-1","panose-1"],["pointerEvents","pointer-events"],["renderingIntent","rendering-intent"],["shapeRendering","shape-rendering"],["stopColor","stop-color"],["stopOpacity","stop-opacity"],["strikethroughPosition","strikethrough-position"],["strikethroughThickness","strikethrough-thickness"],["strokeDasharray","stroke-dasharray"],["strokeDashoffset","stroke-dashoffset"],["strokeLinecap","stroke-linecap"],["strokeLinejoin","stroke-linejoin"],["strokeMiterlimit","stroke-miterlimit"],["strokeOpacity","stroke-opacity"],["strokeWidth","stroke-width"],["textAnchor","text-anchor"],["textDecoration","text-decoration"],["textRendering","text-rendering"],["transformOrigin","transform-origin"],["underlinePosition","underline-position"],["underlineThickness","underline-thickness"],["unicodeBidi","unicode-bidi"],["unicodeRange","unicode-range"],["unitsPerEm","units-per-em"],["vAlphabetic","v-alphabetic"],["vHanging","v-hanging"],["vIdeographic","v-ideographic"],["vMathematical","v-mathematical"],["vectorEffect","vector-effect"],["vertAdvY","vert-adv-y"],["vertOriginX","vert-origin-x"],["vertOriginY","vert-origin-y"],["wordSpacing","word-spacing"],["writingMode","writing-mode"],["xmlnsXlink","xmlns:xlink"],["xHeight","x-height"]]),y$={accept:"accept",acceptcharset:"acceptCharset","accept-charset":"acceptCharset",accesskey:"accessKey",action:"action",allowfullscreen:"allowFullScreen",alt:"alt",as:"as",async:"async",autocapitalize:"autoCapitalize",autocomplete:"autoComplete",autocorrect:"autoCorrect",autofocus:"autoFocus",autoplay:"autoPlay",autosave:"autoSave",capture:"capture",cellpadding:"cellPadding",cellspacing:"cellSpacing",challenge:"challenge",charset:"charSet",checked:"checked",children:"children",cite:"cite",class:"className",classid:"classID",classname:"className",cols:"cols",colspan:"colSpan",content:"content",contenteditable:"contentEditable",contextmenu:"contextMenu",controls:"controls",controlslist:"controlsList",coords:"coords",crossorigin:"crossOrigin",dangerouslysetinnerhtml:"dangerouslySetInnerHTML",data:"data",datetime:"dateTime",default:"default",defaultchecked:"defaultChecked",defaultvalue:"defaultValue",defer:"defer",dir:"dir",disabled:"disabled",disablepictureinpicture:"disablePictureInPicture",disableremoteplayback:"disableRemotePlayback",download:"download",draggable:"draggable",enctype:"encType",enterkeyhint:"enterKeyHint",fetchpriority:"fetchPriority",for:"htmlFor",form:"form",formmethod:"formMethod",formaction:"formAction",formenctype:"formEncType",formnovalidate:"formNoValidate",formtarget:"formTarget",frameborder:"frameBorder",headers:"headers",height:"height",hidden:"hidden",high:"high",href:"href",hreflang:"hrefLang",htmlfor:"htmlFor",httpequiv:"httpEquiv","http-equiv":"httpEquiv",icon:"icon",id:"id",imagesizes:"imageSizes",imagesrcset:"imageSrcSet",inert:"inert",innerhtml:"innerHTML",inputmode:"inputMode",integrity:"integrity",is:"is",itemid:"itemID",itemprop:"itemProp",itemref:"itemRef",itemscope:"itemScope",itemtype:"itemType",keyparams:"keyParams",keytype:"keyType",kind:"kind",label:"label",lang:"lang",list:"list",loop:"loop",low:"low",manifest:"manifest",marginwidth:"marginWidth",marginheight:"marginHeight",max:"max",maxlength:"maxLength",media:"media",mediagroup:"mediaGroup",method:"method",min:"min",minlength:"minLength",multiple:"multiple",muted:"muted",name:"name",nomodule:"noModule",nonce:"nonce",novalidate:"noValidate",open:"open",optimum:"optimum",pattern:"pattern",placeholder:"placeholder",playsinline:"playsInline",poster:"poster",preload:"preload",profile:"profile",radiogroup:"radioGroup",readonly:"readOnly",referrerpolicy:"referrerPolicy",rel:"rel",required:"required",reversed:"reversed",role:"role",rows:"rows",rowspan:"rowSpan",sandbox:"sandbox",scope:"scope",scoped:"scoped",scrolling:"scrolling",seamless:"seamless",selected:"selected",shape:"shape",size:"size",sizes:"sizes",span:"span",spellcheck:"spellCheck",src:"src",srcdoc:"srcDoc",srclang:"srcLang",srcset:"srcSet",start:"start",step:"step",style:"style",summary:"summary",tabindex:"tabIndex",target:"target",title:"title",type:"type",usemap:"useMap",value:"value",width:"width",wmode:"wmode",wrap:"wrap",about:"about",accentheight:"accentHeight","accent-height":"accentHeight",accumulate:"accumulate",additive:"additive",alignmentbaseline:"alignmentBaseline","alignment-baseline":"alignmentBaseline",allowreorder:"allowReorder",alphabetic:"alphabetic",amplitude:"amplitude",arabicform:"arabicForm","arabic-form":"arabicForm",ascent:"ascent",attributename:"attributeName",attributetype:"attributeType",autoreverse:"autoReverse",azimuth:"azimuth",basefrequency:"baseFrequency",baselineshift:"baselineShift","baseline-shift":"baselineShift",baseprofile:"baseProfile",bbox:"bbox",begin:"begin",bias:"bias",by:"by",calcmode:"calcMode",capheight:"capHeight","cap-height":"capHeight",clip:"clip",clippath:"clipPath","clip-path":"clipPath",clippathunits:"clipPathUnits",cliprule:"clipRule","clip-rule":"clipRule",color:"color",colorinterpolation:"colorInterpolation","color-interpolation":"colorInterpolation",colorinterpolationfilters:"colorInterpolationFilters","color-interpolation-filters":"colorInterpolationFilters",colorprofile:"colorProfile","color-profile":"colorProfile",colorrendering:"colorRendering","color-rendering":"colorRendering",contentscripttype:"contentScriptType",contentstyletype:"contentStyleType",cursor:"cursor",cx:"cx",cy:"cy",d:"d",datatype:"datatype",decelerate:"decelerate",descent:"descent",diffuseconstant:"diffuseConstant",direction:"direction",display:"display",divisor:"divisor",dominantbaseline:"dominantBaseline","dominant-baseline":"dominantBaseline",dur:"dur",dx:"dx",dy:"dy",edgemode:"edgeMode",elevation:"elevation",enablebackground:"enableBackground","enable-background":"enableBackground",end:"end",exponent:"exponent",externalresourcesrequired:"externalResourcesRequired",fill:"fill",fillopacity:"fillOpacity","fill-opacity":"fillOpacity",fillrule:"fillRule","fill-rule":"fillRule",filter:"filter",filterres:"filterRes",filterunits:"filterUnits",floodopacity:"floodOpacity","flood-opacity":"floodOpacity",floodcolor:"floodColor","flood-color":"floodColor",focusable:"focusable",fontfamily:"fontFamily","font-family":"fontFamily",fontsize:"fontSize","font-size":"fontSize",fontsizeadjust:"fontSizeAdjust","font-size-adjust":"fontSizeAdjust",fontstretch:"fontStretch","font-stretch":"fontStretch",fontstyle:"fontStyle","font-style":"fontStyle",fontvariant:"fontVariant","font-variant":"fontVariant",fontweight:"fontWeight","font-weight":"fontWeight",format:"format",from:"from",fx:"fx",fy:"fy",g1:"g1",g2:"g2",glyphname:"glyphName","glyph-name":"glyphName",glyphorientationhorizontal:"glyphOrientationHorizontal","glyph-orientation-horizontal":"glyphOrientationHorizontal",glyphorientationvertical:"glyphOrientationVertical","glyph-orientation-vertical":"glyphOrientationVertical",glyphref:"glyphRef",gradienttransform:"gradientTransform",gradientunits:"gradientUnits",hanging:"hanging",horizadvx:"horizAdvX","horiz-adv-x":"horizAdvX",horizoriginx:"horizOriginX","horiz-origin-x":"horizOriginX",ideographic:"ideographic",imagerendering:"imageRendering","image-rendering":"imageRendering",in2:"in2",in:"in",inlist:"inlist",intercept:"intercept",k1:"k1",k2:"k2",k3:"k3",k4:"k4",k:"k",kernelmatrix:"kernelMatrix",kernelunitlength:"kernelUnitLength",kerning:"kerning",keypoints:"keyPoints",keysplines:"keySplines",keytimes:"keyTimes",lengthadjust:"lengthAdjust",letterspacing:"letterSpacing","letter-spacing":"letterSpacing",lightingcolor:"lightingColor","lighting-color":"lightingColor",limitingconeangle:"limitingConeAngle",local:"local",markerend:"markerEnd","marker-end":"markerEnd",markerheight:"markerHeight",markermid:"markerMid","marker-mid":"markerMid",markerstart:"markerStart","marker-start":"markerStart",markerunits:"markerUnits",markerwidth:"markerWidth",mask:"mask",maskcontentunits:"maskContentUnits",maskunits:"maskUnits",mathematical:"mathematical",mode:"mode",numoctaves:"numOctaves",offset:"offset",opacity:"opacity",operator:"operator",order:"order",orient:"orient",orientation:"orientation",origin:"origin",overflow:"overflow",overlineposition:"overlinePosition","overline-position":"overlinePosition",overlinethickness:"overlineThickness","overline-thickness":"overlineThickness",paintorder:"paintOrder","paint-order":"paintOrder",panose1:"panose1","panose-1":"panose1",pathlength:"pathLength",patterncontentunits:"patternContentUnits",patterntransform:"patternTransform",patternunits:"patternUnits",pointerevents:"pointerEvents","pointer-events":"pointerEvents",points:"points",pointsatx:"pointsAtX",pointsaty:"pointsAtY",pointsatz:"pointsAtZ",popover:"popover",popovertarget:"popoverTarget",popovertargetaction:"popoverTargetAction",prefix:"prefix",preservealpha:"preserveAlpha",preserveaspectratio:"preserveAspectRatio",primitiveunits:"primitiveUnits",property:"property",r:"r",radius:"radius",refx:"refX",refy:"refY",renderingintent:"renderingIntent","rendering-intent":"renderingIntent",repeatcount:"repeatCount",repeatdur:"repeatDur",requiredextensions:"requiredExtensions",requiredfeatures:"requiredFeatures",resource:"resource",restart:"restart",result:"result",results:"results",rotate:"rotate",rx:"rx",ry:"ry",scale:"scale",security:"security",seed:"seed",shaperendering:"shapeRendering","shape-rendering":"shapeRendering",slope:"slope",spacing:"spacing",specularconstant:"specularConstant",specularexponent:"specularExponent",speed:"speed",spreadmethod:"spreadMethod",startoffset:"startOffset",stddeviation:"stdDeviation",stemh:"stemh",stemv:"stemv",stitchtiles:"stitchTiles",stopcolor:"stopColor","stop-color":"stopColor",stopopacity:"stopOpacity","stop-opacity":"stopOpacity",strikethroughposition:"strikethroughPosition","strikethrough-position":"strikethroughPosition",strikethroughthickness:"strikethroughThickness","strikethrough-thickness":"strikethroughThickness",string:"string",stroke:"stroke",strokedasharray:"strokeDasharray","stroke-dasharray":"strokeDasharray",strokedashoffset:"strokeDashoffset","stroke-dashoffset":"strokeDashoffset",strokelinecap:"strokeLinecap","stroke-linecap":"strokeLinecap",strokelinejoin:"strokeLinejoin","stroke-linejoin":"strokeLinejoin",strokemiterlimit:"strokeMiterlimit","stroke-miterlimit":"strokeMiterlimit",strokewidth:"strokeWidth","stroke-width":"strokeWidth",strokeopacity:"strokeOpacity","stroke-opacity":"strokeOpacity",suppresscontenteditablewarning:"suppressContentEditableWarning",suppresshydrationwarning:"suppressHydrationWarning",surfacescale:"surfaceScale",systemlanguage:"systemLanguage",tablevalues:"tableValues",targetx:"targetX",targety:"targetY",textanchor:"textAnchor","text-anchor":"textAnchor",textdecoration:"textDecoration","text-decoration":"textDecoration",textlength:"textLength",textrendering:"textRendering","text-rendering":"textRendering",to:"to",transform:"transform",transformorigin:"transformOrigin","transform-origin":"transformOrigin",typeof:"typeof",u1:"u1",u2:"u2",underlineposition:"underlinePosition","underline-position":"underlinePosition",underlinethickness:"underlineThickness","underline-thickness":"underlineThickness",unicode:"unicode",unicodebidi:"unicodeBidi","unicode-bidi":"unicodeBidi",unicoderange:"unicodeRange","unicode-range":"unicodeRange",unitsperem:"unitsPerEm","units-per-em":"unitsPerEm",unselectable:"unselectable",valphabetic:"vAlphabetic","v-alphabetic":"vAlphabetic",values:"values",vectoreffect:"vectorEffect","vector-effect":"vectorEffect",version:"version",vertadvy:"vertAdvY","vert-adv-y":"vertAdvY",vertoriginx:"vertOriginX","vert-origin-x":"vertOriginX",vertoriginy:"vertOriginY","vert-origin-y":"vertOriginY",vhanging:"vHanging","v-hanging":"vHanging",videographic:"vIdeographic","v-ideographic":"vIdeographic",viewbox:"viewBox",viewtarget:"viewTarget",visibility:"visibility",vmathematical:"vMathematical","v-mathematical":"vMathematical",vocab:"vocab",widths:"widths",wordspacing:"wordSpacing","word-spacing":"wordSpacing",writingmode:"writingMode","writing-mode":"writingMode",x1:"x1",x2:"x2",x:"x",xchannelselector:"xChannelSelector",xheight:"xHeight","x-height":"xHeight",xlinkactuate:"xlinkActuate","xlink:actuate":"xlinkActuate",xlinkarcrole:"xlinkArcrole","xlink:arcrole":"xlinkArcrole",xlinkhref:"xlinkHref","xlink:href":"xlinkHref",xlinkrole:"xlinkRole","xlink:role":"xlinkRole",xlinkshow:"xlinkShow","xlink:show":"xlinkShow",xlinktitle:"xlinkTitle","xlink:title":"xlinkTitle",xlinktype:"xlinkType","xlink:type":"xlinkType",xmlbase:"xmlBase","xml:base":"xmlBase",xmllang:"xmlLang","xml:lang":"xmlLang",xmlns:"xmlns","xml:space":"xmlSpace",xmlnsxlink:"xmlnsXlink","xmlns:xlink":"xmlnsXlink",xmlspace:"xmlSpace",y1:"y1",y2:"y2",y:"y",ychannelselector:"yChannelSelector",z:"z",zoomandpan:"zoomAndPan"},HK={"aria-current":0,"aria-description":0,"aria-details":0,"aria-disabled":0,"aria-hidden":0,"aria-invalid":0,"aria-keyshortcuts":0,"aria-label":0,"aria-roledescription":0,"aria-autocomplete":0,"aria-checked":0,"aria-expanded":0,"aria-haspopup":0,"aria-level":0,"aria-modal":0,"aria-multiline":0,"aria-multiselectable":0,"aria-orientation":0,"aria-placeholder":0,"aria-pressed":0,"aria-readonly":0,"aria-required":0,"aria-selected":0,"aria-sort":0,"aria-valuemax":0,"aria-valuemin":0,"aria-valuenow":0,"aria-valuetext":0,"aria-atomic":0,"aria-busy":0,"aria-live":0,"aria-relevant":0,"aria-dropeffect":0,"aria-grabbed":0,"aria-activedescendant":0,"aria-colcount":0,"aria-colindex":0,"aria-colspan":0,"aria-controls":0,"aria-describedby":0,"aria-errormessage":0,"aria-flowto":0,"aria-labelledby":0,"aria-owns":0,"aria-posinset":0,"aria-rowcount":0,"aria-rowindex":0,"aria-rowspan":0,"aria-setsize":0,"aria-braillelabel":0,"aria-brailleroledescription":0,"aria-colindextext":0,"aria-rowindextext":0},sG={},UU=RegExp("^(aria)-[:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$"),VU=RegExp("^(aria)[A-Z][:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$"),XK=!1,c2={},YK=/^on./,OU=/^on[^A-Z]/,FU=RegExp("^(aria)-[:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$"),RU=RegExp("^(aria)[A-Z][:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$"),MU=/^[\u0000-\u001F ]*j[\r\n\t]*a[\r\n\t]*v[\r\n\t]*a[\r\n\t]*s[\r\n\t]*c[\r\n\t]*r[\r\n\t]*i[\r\n\t]*p[\r\n\t]*t[\r\n\t]*:/i,A1=null,aG=null,iG=null,eJ=!1,k6=!(typeof window>"u"||typeof window.document>"u"||typeof window.document.createElement>"u"),Zq=!1;if(k6)try{var C1={};Object.defineProperty(C1,"passive",{get:function(){Zq=!0}}),window.addEventListener("test",C1,C1),window.removeEventListener("test",C1,C1)}catch(Z){Zq=!1}var s8=null,Gq=null,g$=null,y9={eventPhase:0,bubbles:0,cancelable:0,timeStamp:function(Z){return Z.timeStamp||Date.now()},defaultPrevented:0,isTrusted:0},b$=pZ(y9),T1=k7({},y9,{view:0,detail:0}),NU=pZ(T1),Bq,$q,E1,f$=k7({},T1,{screenX:0,screenY:0,clientX:0,clientY:0,pageX:0,pageY:0,ctrlKey:0,shiftKey:0,altKey:0,metaKey:0,getModifierState:M9,button:0,buttons:0,relatedTarget:function(Z){return Z.relatedTarget===void 0?Z.fromElement===Z.srcElement?Z.toElement:Z.fromElement:Z.relatedTarget},movementX:function(Z){if("movementX"in Z)return Z.movementX;return Z!==E1&&(E1&&Z.type==="mousemove"?(Bq=Z.screenX-E1.screenX,$q=Z.screenY-E1.screenY):$q=Bq=0,E1=Z),Bq},movementY:function(Z){return"movementY"in Z?Z.movementY:$q}}),jK=pZ(f$),DU=k7({},f$,{dataTransfer:0}),PU=pZ(DU),AU=k7({},T1,{relatedTarget:0}),zq=pZ(AU),CU=k7({},y9,{animationName:0,elapsedTime:0,pseudoElement:0}),TU=pZ(CU),EU=k7({},y9,{clipboardData:function(Z){return"clipboardData"in Z?Z.clipboardData:window.clipboardData}}),wU=pZ(EU),IU=k7({},y9,{data:0}),KK=pZ(IU),xU=KK,SU={Esc:"Escape",Spacebar:" ",Left:"ArrowLeft",Up:"ArrowUp",Right:"ArrowRight",Down:"ArrowDown",Del:"Delete",Win:"OS",Menu:"ContextMenu",Apps:"ContextMenu",Scroll:"ScrollLock",MozPrintableKey:"Unidentified"},vU={8:"Backspace",9:"Tab",12:"Clear",13:"Enter",16:"Shift",17:"Control",18:"Alt",19:"Pause",20:"CapsLock",27:"Escape",32:" ",33:"PageUp",34:"PageDown",35:"End",36:"Home",37:"ArrowLeft",38:"ArrowUp",39:"ArrowRight",40:"ArrowDown",45:"Insert",46:"Delete",112:"F1",113:"F2",114:"F3",115:"F4",116:"F5",117:"F6",118:"F7",119:"F8",120:"F9",121:"F10",122:"F11",123:"F12",144:"NumLock",145:"ScrollLock",224:"Meta"},kU={Alt:"altKey",Control:"ctrlKey",Meta:"metaKey",Shift:"shiftKey"},yU=k7({},T1,{key:function(Z){if(Z.key){var G=SU[Z.key]||Z.key;if(G!=="Unidentified")return G}return Z.type==="keypress"?(Z=R9(Z),Z===13?"Enter":String.fromCharCode(Z)):Z.type==="keydown"||Z.type==="keyup"?vU[Z.keyCode]||"Unidentified":""},code:0,location:0,ctrlKey:0,shiftKey:0,altKey:0,metaKey:0,repeat:0,locale:0,getModifierState:M9,charCode:function(Z){return Z.type==="keypress"?R9(Z):0},keyCode:function(Z){return Z.type==="keydown"||Z.type==="keyup"?Z.keyCode:0},which:function(Z){return Z.type==="keypress"?R9(Z):Z.type==="keydown"||Z.type==="keyup"?Z.keyCode:0}}),gU=pZ(yU),bU=k7({},f$,{pointerId:0,width:0,height:0,pressure:0,tangentialPressure:0,tiltX:0,tiltY:0,twist:0,pointerType:0,isPrimary:0}),WK=pZ(bU),fU=k7({},T1,{touches:0,targetTouches:0,changedTouches:0,altKey:0,metaKey:0,ctrlKey:0,shiftKey:0,getModifierState:M9}),mU=pZ(fU),hU=k7({},y9,{propertyName:0,elapsedTime:0,pseudoElement:0}),uU=pZ(hU),dU=k7({},f$,{deltaX:function(Z){return"deltaX"in Z?Z.deltaX:("wheelDeltaX"in Z)?-Z.wheelDeltaX:0},deltaY:function(Z){return"deltaY"in Z?Z.deltaY:("wheelDeltaY"in Z)?-Z.wheelDeltaY:("wheelDelta"in Z)?-Z.wheelDelta:0},deltaZ:0,deltaMode:0}),pU=pZ(dU),cU=k7({},y9,{newState:0,oldState:0}),lU=pZ(cU),sU=[9,13,27,32],_K=229,Qq=k6&&"CompositionEvent"in window,w1=null;k6&&"documentMode"in document&&(w1=document.documentMode);var aU=k6&&"TextEvent"in window&&!w1,LK=k6&&(!Qq||w1&&8<w1&&11>=w1),UK=32,VK=String.fromCharCode(UK),OK=!1,oG=!1,iU={color:!0,date:!0,datetime:!0,"datetime-local":!0,email:!0,month:!0,number:!0,password:!0,range:!0,search:!0,tel:!0,text:!0,time:!0,url:!0,week:!0},I1=null,x1=null,FK=!1;k6&&(FK=a6("input")&&(!document.documentMode||9<document.documentMode));var l2=typeof Object.is==="function"?Object.is:ZQ,oU=k6&&"documentMode"in document&&11>=document.documentMode,rG=null,Jq=null,S1=null,qq=!1,nG={animationend:y5("Animation","AnimationEnd"),animationiteration:y5("Animation","AnimationIteration"),animationstart:y5("Animation","AnimationStart"),transitionrun:y5("Transition","TransitionRun"),transitionstart:y5("Transition","TransitionStart"),transitioncancel:y5("Transition","TransitionCancel"),transitionend:y5("Transition","TransitionEnd")},Hq={},RK={};k6&&(RK=document.createElement("div").style,("AnimationEvent"in window)||(delete nG.animationend.animation,delete nG.animationiteration.animation,delete nG.animationstart.animation),("TransitionEvent"in window)||delete nG.transitionend.transition);var MK=W6("animationend"),NK=W6("animationiteration"),DK=W6("animationstart"),rU=W6("transitionrun"),nU=W6("transitionstart"),tU=W6("transitioncancel"),PK=W6("transitionend"),AK=new Map,Xq="abort auxClick beforeToggle cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(" ");Xq.push("scrollEnd");var CK=0;if(typeof performance==="object"&&typeof performance.now==="function")var eU=performance,TK=function(){return eU.now()};else{var ZV=Date;TK=function(){return ZV.now()}}var Yq=typeof reportError==="function"?reportError:function(Z){if(typeof window==="object"&&typeof window.ErrorEvent==="function"){var G=new window.ErrorEvent("error",{bubbles:!0,cancelable:!0,message:typeof Z==="object"&&Z!==null&&typeof Z.message==="string"?String(Z.message):String(Z),error:Z});if(!window.dispatchEvent(G))return}else if(typeof process==="object"&&typeof process.emit==="function"){process.emit("uncaughtException",Z);return}console.error(Z)},GV="This object has been omitted by React in the console log to avoid sending too much data from the server. Try logging smaller or more specific objects.",m$=0,jq=1,Kq=2,Wq=3,h$="– ",u$="+ ",EK="  ",MZ=typeof console<"u"&&typeof console.timeStamp==="function"&&typeof performance<"u"&&typeof performance.measure==="function",h5="Components ⚛",y7="Scheduler ⚛",m7="Blocking",a8=!1,H8={color:"primary",properties:null,tooltipText:"",track:h5},i8={start:-0,end:-0,detail:{devtools:H8}},BV=["Changed Props",""],wK="This component received deeply equal props. It might benefit from useMemo or the React Compiler in its owner.",$V=["Changed Props",wK],v1=1,X8=2,u5=[],tG=0,_q=0,o8={};Object.freeze(o8);var d5=null,eG=null,_7=0,zV=1,E7=2,g2=8,Q6=16,QV=32,IK=!1;try{var xK=Object.preventExtensions({});}catch(Z){IK=!0}var Lq=new WeakMap,Z0=[],G0=0,d$=null,k1=0,p5=[],c5=0,g9=null,Y8=1,j8="",w2=null,NZ=null,d7=!1,y6=!1,D5=null,r8=null,l5=!1,Uq=Error("Hydration Mismatch Exception: This is not a real error, and should not leak into userspace. If you're seeing this, it's likely a bug in React."),Vq=l4(null),Oq=l4(null),SK={},p$=null,B0=null,$0=!1,JV=typeof AbortController<"u"?AbortController:function(){var Z=[],G=this.signal={aborted:!1,addEventListener:function(B,$){Z.push($)}};this.abort=function(){G.aborted=!0,Z.forEach(function(B){return B()})}},qV=B2.unstable_scheduleCallback,HV=B2.unstable_NormalPriority,$2={$$typeof:w6,Consumer:null,Provider:null,_currentValue:null,_currentValue2:null,_threadCount:0,_currentRenderer:null,_currentRenderer2:null},z2=B2.unstable_now,c$=console.createTask?console.createTask:function(){return null},y1=1,l$=2,O2=-0,n8=-0,K8=-0,W8=null,s2=-1.1,b9=-0,IZ=-0,G7=-1.1,j7=-1.1,TZ=null,fZ=!1,t8=-0,g6=-1.1,g1=null,e8=0,Fq=null,Rq=null,f9=-1.1,b1=null,z0=-1.1,s$=-1.1,b6=-0,_8=-1.1,s5=-1.1,Mq=0,f1=null,vK=null,kK=null,Z9=-1.1,m9=null,G9=-1.1,a$=-1.1,yK=-0,gK=-0,i$=0,L8=null,bK=0,m1=-1.1,o$=!1,r$=!1,h1=null,Nq=0,h9=0,Q0=null,fK=l.S;l.S=function(Z,G){if(vW=V2(),typeof G==="object"&&G!==null&&typeof G.then==="function"){if(0>_8&&0>s5){_8=z2();var B=U1(),$=L1();if(B!==G9||$!==m9)G9=-1.1;Z9=B,m9=$}T3(Z,G)}fK!==null&&fK(Z,G)};var u9=l4(null),J6={recordUnsafeLifecycleWarnings:function(){},flushPendingUnsafeLifecycleWarnings:function(){},recordLegacyContextWarning:function(){},flushLegacyContextWarning:function(){},discardPendingWarnings:function(){}},u1=[],d1=[],p1=[],c1=[],l1=[],s1=[],d9=new Set;J6.recordUnsafeLifecycleWarnings=function(Z,G){d9.has(Z.type)||(typeof G.componentWillMount==="function"&&G.componentWillMount.__suppressDeprecationWarning!==!0&&u1.push(Z),Z.mode&g2&&typeof G.UNSAFE_componentWillMount==="function"&&d1.push(Z),typeof G.componentWillReceiveProps==="function"&&G.componentWillReceiveProps.__suppressDeprecationWarning!==!0&&p1.push(Z),Z.mode&g2&&typeof G.UNSAFE_componentWillReceiveProps==="function"&&c1.push(Z),typeof G.componentWillUpdate==="function"&&G.componentWillUpdate.__suppressDeprecationWarning!==!0&&l1.push(Z),Z.mode&g2&&typeof G.UNSAFE_componentWillUpdate==="function"&&s1.push(Z))},J6.flushPendingUnsafeLifecycleWarnings=function(){var Z=new Set;0<u1.length&&(u1.forEach(function(X){Z.add(Y4(X)||"Component"),d9.add(X.type)}),u1=[]);var G=new Set;0<d1.length&&(d1.forEach(function(X){G.add(Y4(X)||"Component"),d9.add(X.type)}),d1=[]);var B=new Set;0<p1.length&&(p1.forEach(function(X){B.add(Y4(X)||"Component"),d9.add(X.type)}),p1=[]);var $=new Set;0<c1.length&&(c1.forEach(function(X){$.add(Y4(X)||"Component"),d9.add(X.type)}),c1=[]);var z=new Set;0<l1.length&&(l1.forEach(function(X){z.add(Y4(X)||"Component"),d9.add(X.type)}),l1=[]);var Q=new Set;if(0<s1.length&&(s1.forEach(function(X){Q.add(Y4(X)||"Component"),d9.add(X.type)}),s1=[]),0<G.size){var q=g(G);console.error(`Using UNSAFE_componentWillMount in strict mode is not recommended and may indicate bugs in your code. See https://react.dev/link/unsafe-component-lifecycles for details.

* Move code with side effects to componentDidMount, and set initial state in the constructor.

Please update the following components: %s`,q)}0<$.size&&(q=g($),console.error(`Using UNSAFE_componentWillReceiveProps in strict mode is not recommended and may indicate bugs in your code. See https://react.dev/link/unsafe-component-lifecycles for details.

* Move data fetching code or side effects to componentDidUpdate.
* If you're updating state whenever props change, refactor your code to use memoization techniques or move it to static getDerivedStateFromProps. Learn more at: https://react.dev/link/derived-state

Please update the following components: %s`,q)),0<Q.size&&(q=g(Q),console.error(`Using UNSAFE_componentWillUpdate in strict mode is not recommended and may indicate bugs in your code. See https://react.dev/link/unsafe-component-lifecycles for details.

* Move data fetching code or side effects to componentDidUpdate.

Please update the following components: %s`,q)),0<Z.size&&(q=g(Z),console.warn(`componentWillMount has been renamed, and is not recommended for use. See https://react.dev/link/unsafe-component-lifecycles for details.

* Move code with side effects to componentDidMount, and set initial state in the constructor.
* Rename componentWillMount to UNSAFE_componentWillMount to suppress this warning in non-strict mode. In React 18.x, only the UNSAFE_ name will work. To rename all deprecated lifecycles to their new names, you can run \`npx react-codemod rename-unsafe-lifecycles\` in your project source folder.

Please update the following components: %s`,q)),0<B.size&&(q=g(B),console.warn(`componentWillReceiveProps has been renamed, and is not recommended for use. See https://react.dev/link/unsafe-component-lifecycles for details.

* Move data fetching code or side effects to componentDidUpdate.
* If you're updating state whenever props change, refactor your code to use memoization techniques or move it to static getDerivedStateFromProps. Learn more at: https://react.dev/link/derived-state
* Rename componentWillReceiveProps to UNSAFE_componentWillReceiveProps to suppress this warning in non-strict mode. In React 18.x, only the UNSAFE_ name will work. To rename all deprecated lifecycles to their new names, you can run \`npx react-codemod rename-unsafe-lifecycles\` in your project source folder.

Please update the following components: %s`,q)),0<z.size&&(q=g(z),console.warn(`componentWillUpdate has been renamed, and is not recommended for use. See https://react.dev/link/unsafe-component-lifecycles for details.

* Move data fetching code or side effects to componentDidUpdate.
* Rename componentWillUpdate to UNSAFE_componentWillUpdate to suppress this warning in non-strict mode. In React 18.x, only the UNSAFE_ name will work. To rename all deprecated lifecycles to their new names, you can run \`npx react-codemod rename-unsafe-lifecycles\` in your project source folder.

Please update the following components: %s`,q))};var n$=new Map,mK=new Set;J6.recordLegacyContextWarning=function(Z,G){var B=null;for(var $=Z;$!==null;)$.mode&g2&&(B=$),$=$.return;B===null?console.error("Expected to find a StrictMode component in a strict mode tree. This error is likely caused by a bug in React. Please file an issue."):!mK.has(Z.type)&&($=n$.get(B),Z.type.contextTypes!=null||Z.type.childContextTypes!=null||G!==null&&typeof G.getChildContext==="function")&&($===void 0&&($=[],n$.set(B,$)),$.push(Z))},J6.flushLegacyContextWarning=function(){n$.forEach(function(Z){if(Z.length!==0){var G=Z[0],B=new Set;Z.forEach(function(z){B.add(Y4(z)||"Component"),mK.add(z.type)});var $=g(B);M4(G,function(){console.error(`Legacy context API has been detected within a strict-mode tree.

The old API will be supported in all 16.x releases, but applications using it should migrate to the new version.

Please update the following components: %s

Learn more about this warning here: https://react.dev/link/legacy-context`,$)})}})},J6.discardPendingWarnings=function(){u1=[],d1=[],p1=[],c1=[],l1=[],s1=[],n$=new Map};var hK={react_stack_bottom_frame:function(Z,G,B){var $=I6;I6=!0;try{return Z(G,B)}finally{I6=$}}},Dq=hK.react_stack_bottom_frame.bind(hK),uK={react_stack_bottom_frame:function(Z){var G=I6;I6=!0;try{return Z.render()}finally{I6=G}}},dK=uK.react_stack_bottom_frame.bind(uK),pK={react_stack_bottom_frame:function(Z,G){try{G.componentDidMount()}catch(B){GZ(Z,Z.return,B)}}},Pq=pK.react_stack_bottom_frame.bind(pK),cK={react_stack_bottom_frame:function(Z,G,B,$,z){try{G.componentDidUpdate(B,$,z)}catch(Q){GZ(Z,Z.return,Q)}}},lK=cK.react_stack_bottom_frame.bind(cK),sK={react_stack_bottom_frame:function(Z,G){var B=G.stack;Z.componentDidCatch(G.value,{componentStack:B!==null?B:""})}},XV=sK.react_stack_bottom_frame.bind(sK),aK={react_stack_bottom_frame:function(Z,G,B){try{B.componentWillUnmount()}catch($){GZ(Z,G,$)}}},iK=aK.react_stack_bottom_frame.bind(aK),oK={react_stack_bottom_frame:function(Z){var G=Z.create;return Z=Z.inst,G=G(),Z.destroy=G}},YV=oK.react_stack_bottom_frame.bind(oK),rK={react_stack_bottom_frame:function(Z,G,B){try{B()}catch($){GZ(Z,G,$)}}},jV=rK.react_stack_bottom_frame.bind(rK),nK={react_stack_bottom_frame:function(Z){var G=Z._init;return G(Z._payload)}},KV=nK.react_stack_bottom_frame.bind(nK),J0=Error("Suspense Exception: This is not a real error! It's an implementation detail of `use` to interrupt the current render. You must either rethrow it immediately, or move the `use` call outside of the `try/catch` block. Capturing without rethrowing will lead to unexpected behavior.\n\nTo handle async errors, wrap your component in an error boundary, or call the promise's `.catch` method and pass the result to `use`."),Aq=Error("Suspense Exception: This is not a real error, and should not leak into userspace. If you're seeing this, it's likely a bug in React."),t$=Error("Suspense Exception: This is not a real error! It's an implementation detail of `useActionState` to interrupt the current render. You must either rethrow it immediately, or move the `useActionState` call outside of the `try/catch` block. Capturing without rethrowing will lead to unexpected behavior.\n\nTo handle async errors, wrap your component in an error boundary."),e$={then:function(){console.error('Internal React error: A listener was unexpectedly attached to a "noop" thenable. This is a bug in React. Please file an issue.')}},p9=null,a1=!1,q0=null,i1=0,w7=null,Cq,tK=Cq=!1,eK={},ZW={},GW={};b=function(Z,G,B){if(B!==null&&typeof B==="object"&&B._store&&(!B._store.validated&&B.key==null||B._store.validated===2)){if(typeof B._store!=="object")throw Error("React Component in warnForMissingKey should have a _store. This error is likely caused by a bug in React. Please file an issue.");B._store.validated=1;var $=Y4(Z),z=$||"null";if(!eK[z]){eK[z]=!0,B=B._owner,Z=Z._debugOwner;var Q="";Z&&typeof Z.tag==="number"&&(z=Y4(Z))&&(Q=`

Check the render method of \``+z+"`."),Q||$&&(Q=`

Check the top-level render call using <`+$+">.");var q="";B!=null&&Z!==B&&($=null,typeof B.tag==="number"?$=Y4(B):typeof B.name==="string"&&($=B.name),$&&(q=" It was passed a child from "+$+".")),M4(G,function(){console.error('Each child in a list should have a unique "key" prop.%s%s See https://react.dev/link/warning-keys for more information.',Q,q)})}}};var c9=aH(!0),BW=aH(!1),$W=0,zW=1,QW=2,Tq=3,B9=!1,JW=!1,Eq=null,wq=!1,H0=l4(null),Zz=l4(0),P5=l4(null),a5=null,X0=1,o1=2,rZ=l4(0),Gz=0,i5=1,a2=2,A5=4,i2=8,Y0,qW=new Set,HW=new Set,Iq=new Set,XW=new Set,U8=0,V7=null,KZ=null,Q2=null,Bz=!1,j0=!1,l9=!1,$z=0,r1=0,V8=null,WV=0,_V=25,c=null,o5=null,O8=-1,n1=!1,t1={readContext:r7,use:f8,useCallback:sZ,useContext:sZ,useEffect:sZ,useImperativeHandle:sZ,useLayoutEffect:sZ,useInsertionEffect:sZ,useMemo:sZ,useReducer:sZ,useRef:sZ,useState:sZ,useDebugValue:sZ,useDeferredValue:sZ,useTransition:sZ,useSyncExternalStore:sZ,useId:sZ,useHostTransitionStatus:sZ,useFormState:sZ,useActionState:sZ,useOptimistic:sZ,useMemoCache:sZ,useCacheRefresh:sZ};t1.useEffectEvent=sZ;var xq=null,YW=null,Sq=null,jW=null,f6=null,q6=null,zz=null;xq={readContext:function(Z){return r7(Z)},use:f8,useCallback:function(Z,G){return c="useCallback",v7(),TG(G),EQ(Z,G)},useContext:function(Z){return c="useContext",v7(),r7(Z)},useEffect:function(Z,G){return c="useEffect",v7(),TG(G),nB(Z,G)},useImperativeHandle:function(Z,G,B){return c="useImperativeHandle",v7(),TG(B),TQ(Z,G,B)},useInsertionEffect:function(Z,G){c="useInsertionEffect",v7(),TG(G),w9(4,a2,Z,G)},useLayoutEffect:function(Z,G){return c="useLayoutEffect",v7(),TG(G),CQ(Z,G)},useMemo:function(Z,G){c="useMemo",v7(),TG(G);var B=l.H;l.H=f6;try{return wQ(Z,G)}finally{l.H=B}},useReducer:function(Z,G,B){c="useReducer",v7();var $=l.H;l.H=f6;try{return VQ(Z,G,B)}finally{l.H=$}},useRef:function(Z){return c="useRef",v7(),PQ(Z)},useState:function(Z){c="useState",v7();var G=l.H;l.H=f6;try{return MQ(Z)}finally{l.H=G}},useDebugValue:function(){c="useDebugValue",v7()},useDeferredValue:function(Z,G){return c="useDeferredValue",v7(),IQ(Z,G)},useTransition:function(){return c="useTransition",v7(),vQ()},useSyncExternalStore:function(Z,G,B){return c="useSyncExternalStore",v7(),FQ(Z,G,B)},useId:function(){return c="useId",v7(),kQ()},useFormState:function(Z,G){return c="useFormState",v7(),sB(),wG(Z,G)},useActionState:function(Z,G){return c="useActionState",v7(),wG(Z,G)},useOptimistic:function(Z){return c="useOptimistic",v7(),NQ(Z)},useHostTransitionStatus:I9,useMemoCache:E9,useCacheRefresh:function(){return c="useCacheRefresh",v7(),yQ()},useEffectEvent:function(Z){return c="useEffectEvent",v7(),AQ(Z)}},YW={readContext:function(Z){return r7(Z)},use:f8,useCallback:function(Z,G){return c="useCallback",_4(),EQ(Z,G)},useContext:function(Z){return c="useContext",_4(),r7(Z)},useEffect:function(Z,G){return c="useEffect",_4(),nB(Z,G)},useImperativeHandle:function(Z,G,B){return c="useImperativeHandle",_4(),TQ(Z,G,B)},useInsertionEffect:function(Z,G){c="useInsertionEffect",_4(),w9(4,a2,Z,G)},useLayoutEffect:function(Z,G){return c="useLayoutEffect",_4(),CQ(Z,G)},useMemo:function(Z,G){c="useMemo",_4();var B=l.H;l.H=f6;try{return wQ(Z,G)}finally{l.H=B}},useReducer:function(Z,G,B){c="useReducer",_4();var $=l.H;l.H=f6;try{return VQ(Z,G,B)}finally{l.H=$}},useRef:function(Z){return c="useRef",_4(),PQ(Z)},useState:function(Z){c="useState",_4();var G=l.H;l.H=f6;try{return MQ(Z)}finally{l.H=G}},useDebugValue:function(){c="useDebugValue",_4()},useDeferredValue:function(Z,G){return c="useDeferredValue",_4(),IQ(Z,G)},useTransition:function(){return c="useTransition",_4(),vQ()},useSyncExternalStore:function(Z,G,B){return c="useSyncExternalStore",_4(),FQ(Z,G,B)},useId:function(){return c="useId",_4(),kQ()},useActionState:function(Z,G){return c="useActionState",_4(),wG(Z,G)},useFormState:function(Z,G){return c="useFormState",_4(),sB(),wG(Z,G)},useOptimistic:function(Z){return c="useOptimistic",_4(),NQ(Z)},useHostTransitionStatus:I9,useMemoCache:E9,useCacheRefresh:function(){return c="useCacheRefresh",_4(),yQ()},useEffectEvent:function(Z){return c="useEffectEvent",_4(),AQ(Z)}},Sq={readContext:function(Z){return r7(Z)},use:f8,useCallback:function(Z,G){return c="useCallback",_4(),Z$(Z,G)},useContext:function(Z){return c="useContext",_4(),r7(Z)},useEffect:function(Z,G){c="useEffect",_4(),z5(2048,i2,Z,G)},useImperativeHandle:function(Z,G,B){return c="useImperativeHandle",_4(),eB(Z,G,B)},useInsertionEffect:function(Z,G){return c="useInsertionEffect",_4(),z5(4,a2,Z,G)},useLayoutEffect:function(Z,G){return c="useLayoutEffect",_4(),z5(4,A5,Z,G)},useMemo:function(Z,G){c="useMemo",_4();var B=l.H;l.H=q6;try{return G$(Z,G)}finally{l.H=B}},useReducer:function(Z,G,B){c="useReducer",_4();var $=l.H;l.H=q6;try{return EG(Z,G,B)}finally{l.H=$}},useRef:function(){return c="useRef",_4(),QZ().memoizedState},useState:function(){c="useState",_4();var Z=l.H;l.H=q6;try{return EG(G6)}finally{l.H=Z}},useDebugValue:function(){c="useDebugValue",_4()},useDeferredValue:function(Z,G){return c="useDeferredValue",_4(),LX(Z,G)},useTransition:function(){return c="useTransition",_4(),MX()},useSyncExternalStore:function(Z,G,B){return c="useSyncExternalStore",_4(),iB(Z,G,B)},useId:function(){return c="useId",_4(),QZ().memoizedState},useFormState:function(Z){return c="useFormState",_4(),sB(),oB(Z)},useActionState:function(Z){return c="useActionState",_4(),oB(Z)},useOptimistic:function(Z,G){return c="useOptimistic",_4(),QX(Z,G)},useHostTransitionStatus:I9,useMemoCache:E9,useCacheRefresh:function(){return c="useCacheRefresh",_4(),QZ().memoizedState},useEffectEvent:function(Z){return c="useEffectEvent",_4(),tB(Z)}},jW={readContext:function(Z){return r7(Z)},use:f8,useCallback:function(Z,G){return c="useCallback",_4(),Z$(Z,G)},useContext:function(Z){return c="useContext",_4(),r7(Z)},useEffect:function(Z,G){c="useEffect",_4(),z5(2048,i2,Z,G)},useImperativeHandle:function(Z,G,B){return c="useImperativeHandle",_4(),eB(Z,G,B)},useInsertionEffect:function(Z,G){return c="useInsertionEffect",_4(),z5(4,a2,Z,G)},useLayoutEffect:function(Z,G){return c="useLayoutEffect",_4(),z5(4,A5,Z,G)},useMemo:function(Z,G){c="useMemo",_4();var B=l.H;l.H=zz;try{return G$(Z,G)}finally{l.H=B}},useReducer:function(Z,G,B){c="useReducer",_4();var $=l.H;l.H=zz;try{return $1(Z,G,B)}finally{l.H=$}},useRef:function(){return c="useRef",_4(),QZ().memoizedState},useState:function(){c="useState",_4();var Z=l.H;l.H=zz;try{return $1(G6)}finally{l.H=Z}},useDebugValue:function(){c="useDebugValue",_4()},useDeferredValue:function(Z,G){return c="useDeferredValue",_4(),UX(Z,G)},useTransition:function(){return c="useTransition",_4(),NX()},useSyncExternalStore:function(Z,G,B){return c="useSyncExternalStore",_4(),iB(Z,G,B)},useId:function(){return c="useId",_4(),QZ().memoizedState},useFormState:function(Z){return c="useFormState",_4(),sB(),rB(Z)},useActionState:function(Z){return c="useActionState",_4(),rB(Z)},useOptimistic:function(Z,G){return c="useOptimistic",_4(),qX(Z,G)},useHostTransitionStatus:I9,useMemoCache:E9,useCacheRefresh:function(){return c="useCacheRefresh",_4(),QZ().memoizedState},useEffectEvent:function(Z){return c="useEffectEvent",_4(),tB(Z)}},f6={readContext:function(Z){return x(),r7(Z)},use:function(Z){return C(),f8(Z)},useCallback:function(Z,G){return c="useCallback",C(),v7(),EQ(Z,G)},useContext:function(Z){return c="useContext",C(),v7(),r7(Z)},useEffect:function(Z,G){return c="useEffect",C(),v7(),nB(Z,G)},useImperativeHandle:function(Z,G,B){return c="useImperativeHandle",C(),v7(),TQ(Z,G,B)},useInsertionEffect:function(Z,G){c="useInsertionEffect",C(),v7(),w9(4,a2,Z,G)},useLayoutEffect:function(Z,G){return c="useLayoutEffect",C(),v7(),CQ(Z,G)},useMemo:function(Z,G){c="useMemo",C(),v7();var B=l.H;l.H=f6;try{return wQ(Z,G)}finally{l.H=B}},useReducer:function(Z,G,B){c="useReducer",C(),v7();var $=l.H;l.H=f6;try{return VQ(Z,G,B)}finally{l.H=$}},useRef:function(Z){return c="useRef",C(),v7(),PQ(Z)},useState:function(Z){c="useState",C(),v7();var G=l.H;l.H=f6;try{return MQ(Z)}finally{l.H=G}},useDebugValue:function(){c="useDebugValue",C(),v7()},useDeferredValue:function(Z,G){return c="useDeferredValue",C(),v7(),IQ(Z,G)},useTransition:function(){return c="useTransition",C(),v7(),vQ()},useSyncExternalStore:function(Z,G,B){return c="useSyncExternalStore",C(),v7(),FQ(Z,G,B)},useId:function(){return c="useId",C(),v7(),kQ()},useFormState:function(Z,G){return c="useFormState",C(),v7(),wG(Z,G)},useActionState:function(Z,G){return c="useActionState",C(),v7(),wG(Z,G)},useOptimistic:function(Z){return c="useOptimistic",C(),v7(),NQ(Z)},useMemoCache:function(Z){return C(),E9(Z)},useHostTransitionStatus:I9,useCacheRefresh:function(){return c="useCacheRefresh",v7(),yQ()},useEffectEvent:function(Z){return c="useEffectEvent",C(),v7(),AQ(Z)}},q6={readContext:function(Z){return x(),r7(Z)},use:function(Z){return C(),f8(Z)},useCallback:function(Z,G){return c="useCallback",C(),_4(),Z$(Z,G)},useContext:function(Z){return c="useContext",C(),_4(),r7(Z)},useEffect:function(Z,G){c="useEffect",C(),_4(),z5(2048,i2,Z,G)},useImperativeHandle:function(Z,G,B){return c="useImperativeHandle",C(),_4(),eB(Z,G,B)},useInsertionEffect:function(Z,G){return c="useInsertionEffect",C(),_4(),z5(4,a2,Z,G)},useLayoutEffect:function(Z,G){return c="useLayoutEffect",C(),_4(),z5(4,A5,Z,G)},useMemo:function(Z,G){c="useMemo",C(),_4();var B=l.H;l.H=q6;try{return G$(Z,G)}finally{l.H=B}},useReducer:function(Z,G,B){c="useReducer",C(),_4();var $=l.H;l.H=q6;try{return EG(Z,G,B)}finally{l.H=$}},useRef:function(){return c="useRef",C(),_4(),QZ().memoizedState},useState:function(){c="useState",C(),_4();var Z=l.H;l.H=q6;try{return EG(G6)}finally{l.H=Z}},useDebugValue:function(){c="useDebugValue",C(),_4()},useDeferredValue:function(Z,G){return c="useDeferredValue",C(),_4(),LX(Z,G)},useTransition:function(){return c="useTransition",C(),_4(),MX()},useSyncExternalStore:function(Z,G,B){return c="useSyncExternalStore",C(),_4(),iB(Z,G,B)},useId:function(){return c="useId",C(),_4(),QZ().memoizedState},useFormState:function(Z){return c="useFormState",C(),_4(),oB(Z)},useActionState:function(Z){return c="useActionState",C(),_4(),oB(Z)},useOptimistic:function(Z,G){return c="useOptimistic",C(),_4(),QX(Z,G)},useMemoCache:function(Z){return C(),E9(Z)},useHostTransitionStatus:I9,useCacheRefresh:function(){return c="useCacheRefresh",_4(),QZ().memoizedState},useEffectEvent:function(Z){return c="useEffectEvent",C(),_4(),tB(Z)}},zz={readContext:function(Z){return x(),r7(Z)},use:function(Z){return C(),f8(Z)},useCallback:function(Z,G){return c="useCallback",C(),_4(),Z$(Z,G)},useContext:function(Z){return c="useContext",C(),_4(),r7(Z)},useEffect:function(Z,G){c="useEffect",C(),_4(),z5(2048,i2,Z,G)},useImperativeHandle:function(Z,G,B){return c="useImperativeHandle",C(),_4(),eB(Z,G,B)},useInsertionEffect:function(Z,G){return c="useInsertionEffect",C(),_4(),z5(4,a2,Z,G)},useLayoutEffect:function(Z,G){return c="useLayoutEffect",C(),_4(),z5(4,A5,Z,G)},useMemo:function(Z,G){c="useMemo",C(),_4();var B=l.H;l.H=q6;try{return G$(Z,G)}finally{l.H=B}},useReducer:function(Z,G,B){c="useReducer",C(),_4();var $=l.H;l.H=q6;try{return $1(Z,G,B)}finally{l.H=$}},useRef:function(){return c="useRef",C(),_4(),QZ().memoizedState},useState:function(){c="useState",C(),_4();var Z=l.H;l.H=q6;try{return $1(G6)}finally{l.H=Z}},useDebugValue:function(){c="useDebugValue",C(),_4()},useDeferredValue:function(Z,G){return c="useDeferredValue",C(),_4(),UX(Z,G)},useTransition:function(){return c="useTransition",C(),_4(),NX()},useSyncExternalStore:function(Z,G,B){return c="useSyncExternalStore",C(),_4(),iB(Z,G,B)},useId:function(){return c="useId",C(),_4(),QZ().memoizedState},useFormState:function(Z){return c="useFormState",C(),_4(),rB(Z)},useActionState:function(Z){return c="useActionState",C(),_4(),rB(Z)},useOptimistic:function(Z,G){return c="useOptimistic",C(),_4(),qX(Z,G)},useMemoCache:function(Z){return C(),E9(Z)},useHostTransitionStatus:I9,useCacheRefresh:function(){return c="useCacheRefresh",_4(),QZ().memoizedState},useEffectEvent:function(Z){return c="useEffectEvent",C(),_4(),tB(Z)}};var KW={},WW=new Set,_W=new Set,LW=new Set,UW=new Set,VW=new Set,OW=new Set,FW=new Set,RW=new Set,MW=new Set,NW=new Set;Object.freeze(KW);var vq={enqueueSetState:function(Z,G,B){Z=Z._reactInternals;var $=O5(Z),z=k8($);z.payload=G,B!==void 0&&B!==null&&(bQ(B),z.callback=B),G=y8(Z,z,$),G!==null&&(L6($,"this.setState()",Z),bZ(G,Z,$),e0(G,Z,$))},enqueueReplaceState:function(Z,G,B){Z=Z._reactInternals;var $=O5(Z),z=k8($);z.tag=zW,z.payload=G,B!==void 0&&B!==null&&(bQ(B),z.callback=B),G=y8(Z,z,$),G!==null&&(L6($,"this.replaceState()",Z),bZ(G,Z,$),e0(G,Z,$))},enqueueForceUpdate:function(Z,G){Z=Z._reactInternals;var B=O5(Z),$=k8(B);$.tag=QW,G!==void 0&&G!==null&&(bQ(G),$.callback=G),G=y8(Z,$,B),G!==null&&(L6(B,"this.forceUpdate()",Z),bZ(G,Z,B),e0(G,Z,B))}},K0=null,kq=null,yq=Error("This is not a real error. It's an implementation detail of React's selective hydration feature. If this leaks into userspace, it's a bug in React. Please file an issue."),J2=!1,DW={},PW={},AW={},CW={},W0=!1,TW={},Qz={},gq={dehydrated:null,treeContext:null,retryLane:0,hydrationErrors:null},EW=!1,wW=null;wW=new Set;var F8=!1,q2=!1,bq=!1,IW=typeof WeakSet==="function"?WeakSet:Set,F2=null,_0=null,L0=null,H2=null,q5=!1,H6=null,K2=!1,e1=8192,LV={getCacheForType:function(Z){var G=r7($2),B=G.data.get(Z);return B===void 0&&(B=Z(),G.data.set(Z,B)),B},cacheSignal:function(){return r7($2).controller.signal},getOwner:function(){return M5}};if(typeof Symbol==="function"&&Symbol.for){var ZB=Symbol.for;ZB("selector.component"),ZB("selector.has_pseudo_class"),ZB("selector.role"),ZB("selector.test_id"),ZB("selector.text")}var UV=[],VV=typeof WeakMap==="function"?WeakMap:Map,R2=0,W2=2,C5=4,R8=0,GB=1,s9=2,Jz=3,$9=4,qz=6,xW=5,i7=R2,WZ=null,x7=null,I7=0,H5=0,Hz=1,a9=2,BB=3,SW=4,fq=5,$B=6,Xz=7,mq=8,i9=9,JZ=H5,T5=null,z9=!1,U0=!1,hq=!1,m6=0,xZ=R8,Q9=0,J9=0,uq=0,X5=0,o9=0,zB=null,o2=null,Yz=!1,jz=0,vW=0,kW=300,Kz=1/0,yW=500,QB=null,aZ=null,q9=null,Wz=0,dq=1,pq=2,gW=3,H9=0,bW=1,fW=2,mW=3,hW=4,_z=5,X2=0,X9=null,V0=null,X6=0,cq=0,lq=-0,sq=null,uW=null,dW=null,Y6=Wz,pW=null,OV=50,JB=0,aq=null,iq=!1,Lz=!1,FV=50,r9=0,qB=null,O0=!1,Uz=null,cW=!1,lW=new Set,RV={},Vz=null,F0=null,oq=!1,rq=!1,Oz=!1,nq=!1,Y9=0,tq={};(function(){for(var Z=0;Z<Xq.length;Z++){var G=Xq[Z],B=G.toLowerCase();G=G[0].toUpperCase()+G.slice(1),x2(B,"on"+G)}x2(MK,"onAnimationEnd"),x2(NK,"onAnimationIteration"),x2(DK,"onAnimationStart"),x2("dblclick","onDoubleClick"),x2("focusin","onFocus"),x2("focusout","onBlur"),x2(rU,"onTransitionRun"),x2(nU,"onTransitionStart"),x2(tU,"onTransitionCancel"),x2(PK,"onTransitionEnd")})(),U7("onMouseEnter",["mouseout","mouseover"]),U7("onMouseLeave",["mouseout","mouseover"]),U7("onPointerEnter",["pointerout","pointerover"]),U7("onPointerLeave",["pointerout","pointerover"]),M7("onChange","change click focusin focusout input keydown keyup selectionchange".split(" ")),M7("onSelect","focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(" ")),M7("onBeforeInput",["compositionend","keypress","textInput","paste"]),M7("onCompositionEnd","compositionend focusout keydown keypress keyup mousedown".split(" ")),M7("onCompositionStart","compositionstart focusout keydown keypress keyup mousedown".split(" ")),M7("onCompositionUpdate","compositionupdate focusout keydown keypress keyup mousedown".split(" "));var HB="abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(" "),eq=new Set("beforetoggle cancel close invalid load scroll scrollend toggle".split(" ").concat(HB)),Fz="_reactListening"+Math.random().toString(36).slice(2),sW=!1,aW=!1,Rz=!1,iW=!1,Mz=!1,Nz=!1,oW=!1,Dz={},MV=/\r\n?/g,NV=/\u0000|\uFFFD/g,n9="http://www.w3.org/1999/xlink",ZH="http://www.w3.org/XML/1998/namespace",DV="javascript:throw new Error('React form unexpectedly submitted.')",PV="suppressHydrationWarning",t9="&",Pz="/&",XB="$",YB="/$",j9="$?",e9="$~",R0="$!",AV="html",CV="body",TV="head",GH="F!",rW="F",nW="loading",EV="style",M8=0,M0=1,Az=2,BH=null,$H=null,tW={dialog:!0,webview:!0},zH=null,jB=void 0,eW=typeof setTimeout==="function"?setTimeout:void 0,wV=typeof clearTimeout==="function"?clearTimeout:void 0,ZG=-1,Z_=typeof Promise==="function"?Promise:void 0,IV=typeof queueMicrotask==="function"?queueMicrotask:typeof Z_<"u"?function(Z){return Z_.resolve(null).then(Z).catch(WL)}:eW,QH=null,GG=0,KB=1,G_=2,B_=3,r5=4,n5=new Map,$_=new Set,N8=BZ.d;BZ.d={f:function(){var Z=N8.f(),G=kG();return Z||G},r:function(Z){var G=x4(Z);G!==null&&G.tag===5&&G.type==="form"?RX(G):N8.r(Z)},D:function(Z){N8.D(Z),Wj("dns-prefetch",Z,null)},C:function(Z,G){N8.C(Z,G),Wj("preconnect",Z,G)},L:function(Z,G,B){N8.L(Z,G,B);var $=N0;if($&&Z&&G){var z='link[rel="preload"][as="'+D2(G)+'"]';G==="image"?B&&B.imageSrcSet?(z+='[imagesrcset="'+D2(B.imageSrcSet)+'"]',typeof B.imageSizes==="string"&&(z+='[imagesizes="'+D2(B.imageSizes)+'"]')):z+='[href="'+D2(Z)+'"]':z+='[href="'+D2(Z)+'"]';var Q=z;switch(G){case"style":Q=bG(Z);break;case"script":Q=fG(Z)}n5.has(Q)||(Z=k7({rel:"preload",href:G==="image"&&B&&B.imageSrcSet?void 0:Z,as:G},B),n5.set(Q,Z),$.querySelector(z)!==null||G==="style"&&$.querySelector(O1(Q))||G==="script"&&$.querySelector(F1(Q))||(G=$.createElement("link"),T2(G,"link",Z),Q4(G),$.head.appendChild(G)))}},m:function(Z,G){N8.m(Z,G);var B=N0;if(B&&Z){var $=G&&typeof G.as==="string"?G.as:"script",z='link[rel="modulepreload"][as="'+D2($)+'"][href="'+D2(Z)+'"]',Q=z;switch($){case"audioworklet":case"paintworklet":case"serviceworker":case"sharedworker":case"worker":case"script":Q=fG(Z)}if(!n5.has(Q)&&(Z=k7({rel:"modulepreload",href:Z},G),n5.set(Q,Z),B.querySelector(z)===null)){switch($){case"audioworklet":case"paintworklet":case"serviceworker":case"sharedworker":case"worker":case"script":if(B.querySelector(F1(Q)))return}$=B.createElement("link"),T2($,"link",Z),Q4($),B.head.appendChild($)}}},X:function(Z,G){N8.X(Z,G);var B=N0;if(B&&Z){var $=E4(B).hoistableScripts,z=fG(Z),Q=$.get(z);Q||(Q=B.querySelector(F1(z)),Q||(Z=k7({src:Z,async:!0},G),(G=n5.get(z))&&TJ(Z,G),Q=B.createElement("script"),Q4(Q),T2(Q,"link",Z),B.head.appendChild(Q)),Q={type:"script",instance:Q,count:1,state:null},$.set(z,Q))}},S:function(Z,G,B){N8.S(Z,G,B);var $=N0;if($&&Z){var z=E4($).hoistableStyles,Q=bG(Z);G=G||"default";var q=z.get(Q);if(!q){var X={loading:GG,preload:null};if(q=$.querySelector(O1(Q)))X.loading=KB|r5;else{Z=k7({rel:"stylesheet",href:Z,"data-precedence":G},B),(B=n5.get(Q))&&CJ(Z,B);var j=q=$.createElement("link");Q4(j),T2(j,"link",Z),j._p=new Promise(function(U,k){j.onload=U,j.onerror=k}),j.addEventListener("load",function(){X.loading|=KB}),j.addEventListener("error",function(){X.loading|=G_}),X.loading|=r5,R$(q,G,$)}q={type:"stylesheet",instance:q,count:1,state:X},z.set(Q,q)}}},M:function(Z,G){N8.M(Z,G);var B=N0;if(B&&Z){var $=E4(B).hoistableScripts,z=fG(Z),Q=$.get(z);Q||(Q=B.querySelector(F1(z)),Q||(Z=k7({src:Z,async:!0,type:"module"},G),(G=n5.get(z))&&TJ(Z,G),Q=B.createElement("script"),Q4(Q),T2(Q,"link",Z),B.head.appendChild(Q)),Q={type:"script",instance:Q,count:1,state:null},$.set(z,Q))}}};var N0=typeof document>"u"?null:document,Cz=null,xV=60000,SV=800,vV=500,JH=0,qH=null,Tz=null,BG=iL,WB={$$typeof:w6,Provider:null,Consumer:null,_currentValue:BG,_currentValue2:BG,_threadCount:0},z_="%c%s%c",Q_="background: #e6e6e6;background: light-dark(rgba(0,0,0,0.1), rgba(255,255,255,0.25));color: #000000;color: light-dark(#000000, #ffffff);border-radius: 2px",J_="",Ez=" ",kV=Function.prototype.bind,q_=!1,H_=null,X_=null,Y_=null,j_=null,K_=null,W_=null,__=null,L_=null,U_=null,V_=null;H_=function(Z,G,B,$){G=J(Z,G),G!==null&&(B=H(G.memoizedState,B,0,$),G.memoizedState=B,G.baseState=B,Z.memoizedProps=k7({},Z.memoizedProps),B=Z2(Z,2),B!==null&&bZ(B,Z,2))},X_=function(Z,G,B){G=J(Z,G),G!==null&&(B=W(G.memoizedState,B,0),G.memoizedState=B,G.baseState=B,Z.memoizedProps=k7({},Z.memoizedProps),B=Z2(Z,2),B!==null&&bZ(B,Z,2))},Y_=function(Z,G,B,$){G=J(Z,G),G!==null&&(B=Y(G.memoizedState,B,$),G.memoizedState=B,G.baseState=B,Z.memoizedProps=k7({},Z.memoizedProps),B=Z2(Z,2),B!==null&&bZ(B,Z,2))},j_=function(Z,G,B){Z.pendingProps=H(Z.memoizedProps,G,0,B),Z.alternate&&(Z.alternate.pendingProps=Z.pendingProps),G=Z2(Z,2),G!==null&&bZ(G,Z,2)},K_=function(Z,G){Z.pendingProps=W(Z.memoizedProps,G,0),Z.alternate&&(Z.alternate.pendingProps=Z.pendingProps),G=Z2(Z,2),G!==null&&bZ(G,Z,2)},W_=function(Z,G,B){Z.pendingProps=Y(Z.memoizedProps,G,B),Z.alternate&&(Z.alternate.pendingProps=Z.pendingProps),G=Z2(Z,2),G!==null&&bZ(G,Z,2)},__=function(Z){var G=Z2(Z,2);G!==null&&bZ(G,Z,2)},L_=function(Z){var G=S7(),B=Z2(Z,G);B!==null&&bZ(B,Z,G)},U_=function(Z){A=Z},V_=function(Z){O=Z};var wz=!0,Iz=null,HH=!1,K9=null,W9=null,_9=null,_B=new Map,LB=new Map,L9=[],yV="mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset".split(" "),xz=null;if(A$.prototype.render=vJ.prototype.render=function(Z){var G=this._internalRoot;if(G===null)throw Error("Cannot update an unmounted root.");var B=arguments;typeof B[1]==="function"?console.error("does not support the second callback argument. To execute a side effect after rendering, declare it in a component body with useEffect()."):h(B[1])?console.error("You passed a container to the second argument of root.render(...). You don't need to pass it again since you already passed it to create the root."):typeof B[1]<"u"&&console.error("You passed a second argument to root.render(...) but it only accepts one argument."),B=Z;var $=G.current,z=O5($);EJ($,z,B,G,null,null)},A$.prototype.unmount=vJ.prototype.unmount=function(){var Z=arguments;if(typeof Z[0]==="function"&&console.error("does not support a callback argument. To execute a side effect after rendering, declare it in a component body with useEffect()."),Z=this._internalRoot,Z!==null){this._internalRoot=null;var G=Z.containerInfo;(i7&(W2|C5))!==R2&&console.error("Attempted to synchronously unmount a root while React was already rendering. React cannot finish unmounting the root until the current render has completed, which may lead to a race condition."),EJ(Z.current,2,null,Z,null,null),kG(),G[l8]=null}},A$.prototype.unstable_scheduleHydration=function(Z){if(Z){var G=E();Z={blockedOn:null,target:Z,priority:G};for(var B=0;B<L9.length&&G!==0&&G<L9[B].priority;B++);L9.splice(B,0,Z),B===0&&Tj(Z)}},function(){var Z=kJ.version;if(Z!=="19.2.8")throw Error(`Incompatible React versions: The "react" and "react-dom" packages must have the exact same version. Instead got:
  - react:      `+(Z+`
  - react-dom:  19.2.8
Learn more: https://react.dev/warnings/version-mismatch`))}(),typeof Map==="function"&&Map.prototype!=null&&typeof Map.prototype.forEach==="function"&&typeof Set==="function"&&Set.prototype!=null&&typeof Set.prototype.clear==="function"&&typeof Set.prototype.forEach==="function"||console.error("React depends on Map and Set built-in types. Make sure that you load a polyfill in older browsers. https://react.dev/link/react-polyfills"),BZ.findDOMNode=function(Z){var G=Z._reactInternals;if(G===void 0){if(typeof Z.render==="function")throw Error("Unable to find node on an unmounted component.");throw Z=Object.keys(Z).join(","),Error("Argument appears to not be a ReactComponent. Keys: "+Z)}return Z=g7(G),Z=Z!==null?h7(Z):null,Z=Z===null?null:Z.stateNode,Z},!function(){var Z={bundleType:1,version:"19.2.8",rendererPackageName:"react-dom",currentDispatcherRef:l,reconcilerVersion:"19.2.8"};return Z.overrideHookState=H_,Z.overrideHookStateDeletePath=X_,Z.overrideHookStateRenamePath=Y_,Z.overrideProps=j_,Z.overridePropsDeletePath=K_,Z.overridePropsRenamePath=W_,Z.scheduleUpdate=__,Z.scheduleRetry=L_,Z.setErrorHandler=U_,Z.setSuspenseHandler=V_,Z.scheduleRefresh=p,Z.scheduleRoot=o,Z.setRefreshHandler=q4,Z.getCurrentFiber=mL,U4(Z)}()&&k6&&window.top===window.self&&(-1<navigator.userAgent.indexOf("Chrome")&&navigator.userAgent.indexOf("Edge")===-1||-1<navigator.userAgent.indexOf("Firefox"))){var O_=window.location.protocol;/^(https?|file):$/.test(O_)&&console.info("%cDownload the React DevTools for a better development experience: https://react.dev/link/react-devtools"+(O_==="file:"?`
You might need to use a local HTTP server (instead of file://): https://react.dev/link/react-devtools-faq`:""),"font-weight:bold")}kz.createRoot=function(Z,G){if(!h(Z))throw Error("Target container is not a DOM element.");xj(Z);var B=!1,$="",z=EX,Q=wX,q=IX;return G!==null&&G!==void 0&&(G.hydrate?console.warn("hydrate through createRoot is deprecated. Use ReactDOMClient.hydrateRoot(container, <App />) instead."):typeof G==="object"&&G!==null&&G.$$typeof===E6&&console.error(`You passed a JSX element to createRoot. You probably meant to call root.render instead. Example usage:

  let root = createRoot(domContainer);
  root.render(<App />);`),G.unstable_strictMode===!0&&(B=!0),G.identifierPrefix!==void 0&&($=G.identifierPrefix),G.onUncaughtError!==void 0&&(z=G.onUncaughtError),G.onCaughtError!==void 0&&(Q=G.onCaughtError),G.onRecoverableError!==void 0&&(q=G.onRecoverableError)),G=Rj(Z,1,!1,null,null,B,$,null,z,Q,q,Ij),Z[l8]=G.current,_J(Z),new vJ(G)},kz.hydrateRoot=function(Z,G,B){if(!h(Z))throw Error("Target container is not a DOM element.");xj(Z),G===void 0&&console.error("Must provide initial children as second argument to hydrateRoot. Example usage: hydrateRoot(domContainer, <App />)");var $=!1,z="",Q=EX,q=wX,X=IX,j=null;return B!==null&&B!==void 0&&(B.unstable_strictMode===!0&&($=!0),B.identifierPrefix!==void 0&&(z=B.identifierPrefix),B.onUncaughtError!==void 0&&(Q=B.onUncaughtError),B.onCaughtError!==void 0&&(q=B.onCaughtError),B.onRecoverableError!==void 0&&(X=B.onRecoverableError),B.formState!==void 0&&(j=B.formState)),G=Rj(Z,1,!0,G,B!=null?B:null,$,z,j,Q,q,X,Ij),G.context=Mj(null),B=G.current,$=O5(B),$=S4($),z=k8($),z.callback=null,y8(B,z,$),L6($,"hydrateRoot()",null),B=$,G.current.lanes=B,o4(G,B),C6(G),Z[l8]=G.current,_J(Z),new A$(G)},kz.version="19.2.8",typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"&&typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop==="function"&&__REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop(Error())})()});var w_=h6((jM,E_)=>{E_.exports=T_()});var I_=h6((yz)=>{(function(){function J(s){if(s==null)return null;if(typeof s==="function")return s.$$typeof===l4?null:s.displayName||s.name||null;if(typeof s==="string")return s;switch(s){case h:return"Fragment";case I4:return"Profiler";case t:return"StrictMode";case h7:return"Suspense";case T4:return"SuspenseList";case Y4:return"Activity"}if(typeof s==="object")switch(typeof s.tag==="number"&&console.error("Received an unexpected object in getComponentNameFromType(). This is likely a bug in React. Please file an issue."),s.$$typeof){case q4:return"Portal";case i4:return s.displayName||"Context";case u4:return(s._context.displayName||"Context")+".Consumer";case g7:var c4=s.render;return s=s.displayName,s||(s=c4.displayName||c4.name||"",s=s!==""?"ForwardRef("+s+")":"ForwardRef"),s;case p4:return c4=s.displayName||null,c4!==null?c4:J(s.type)||"Memo";case N7:c4=s._payload,s=s._init;try{return J(s(c4))}catch(Q7){}}return null}function H(s){return""+s}function Y(s){try{H(s);var c4=!1}catch(EZ){c4=!0}if(c4){c4=console;var Q7=c4.error,W7=typeof Symbol==="function"&&Symbol.toStringTag&&s[Symbol.toStringTag]||s.constructor.name||"Object";return Q7.call(c4,"The provided key is an unsupported type %s. This value must be coerced to a string before using it here.",W7),H(s)}}function K(s){if(s===h)return"<>";if(typeof s==="object"&&s!==null&&s.$$typeof===N7)return"<...>";try{var c4=J(s);return c4?"<"+c4+">":"<...>"}catch(Q7){return"<...>"}}function W(){var s=d4.A;return s===null?null:s.getOwner()}function O(){return Error("react-stack-top-frame")}function A(s){if(b4.call(s,"key")){var c4=Object.getOwnPropertyDescriptor(s,"key").get;if(c4&&c4.isReactWarning)return!1}return s.key!==void 0}function C(s,c4){function Q7(){L4||(L4=!0,console.error("%s: `key` is not a prop. Trying to access it will result in `undefined` being returned. If you need to access the same value within the child component, you should pass it as a different prop. (https://react.dev/link/special-props)",c4))}Q7.isReactWarning=!0,Object.defineProperty(s,"key",{get:Q7,configurable:!0})}function x(){var s=J(this.type);return O4[s]||(O4[s]=!0,console.error("Accessing element.ref was removed in React 19. ref is now a regular prop. It will be removed from the JSX Element type in a future release.")),s=this.props.ref,s!==void 0?s:null}function J4(s,c4,Q7,W7,EZ,I2){var u7=Q7.ref;return s={$$typeof:p,type:s,key:c4,props:Q7,_owner:W7},(u7!==void 0?u7:null)!==null?Object.defineProperty(s,"ref",{enumerable:!1,get:x}):Object.defineProperty(s,"ref",{enumerable:!1,value:null}),s._store={},Object.defineProperty(s._store,"validated",{configurable:!1,enumerable:!1,writable:!0,value:0}),Object.defineProperty(s,"_debugInfo",{configurable:!1,enumerable:!1,writable:!0,value:null}),Object.defineProperty(s,"_debugStack",{configurable:!1,enumerable:!1,writable:!0,value:EZ}),Object.defineProperty(s,"_debugTask",{configurable:!1,enumerable:!1,writable:!0,value:I2}),Object.freeze&&(Object.freeze(s.props),Object.freeze(s)),s}function b(s,c4,Q7,W7,EZ,I2){var u7=c4.children;if(u7!==void 0)if(W7)if(n4(u7)){for(W7=0;W7<u7.length;W7++)g(u7[W7]);Object.freeze&&Object.freeze(u7)}else console.error("React.jsx: Static children should always be an array. You are likely explicitly calling React.jsxs or React.jsxDEV. Use the Babel transform instead.");else g(u7);if(b4.call(c4,"key")){u7=J(s);var AZ=Object.keys(c4).filter(function(Z5){return Z5!=="key"});W7=0<AZ.length?"{key: someKey, "+AZ.join(": ..., ")+": ...}":"{key: someKey}",R7[u7+W7]||(AZ=0<AZ.length?"{"+AZ.join(": ..., ")+": ...}":"{}",console.error(`A props object containing a "key" prop is being spread into JSX:
  let props = %s;
  <%s {...props} />
React keys must be passed directly to JSX without using spread:
  let props = %s;
  <%s key={someKey} {...props} />`,W7,u7,AZ,u7),R7[u7+W7]=!0)}if(u7=null,Q7!==void 0&&(Y(Q7),u7=""+Q7),A(c4)&&(Y(c4.key),u7=""+c4.key),"key"in c4){Q7={};for(var eZ in c4)eZ!=="key"&&(Q7[eZ]=c4[eZ])}else Q7=c4;return u7&&C(Q7,typeof s==="function"?s.displayName||s.name||"Unknown":s),J4(s,u7,Q7,W(),EZ,I2)}function g(s){R(s)?s._store&&(s._store.validated=1):typeof s==="object"&&s!==null&&s.$$typeof===N7&&(s._payload.status==="fulfilled"?R(s._payload.value)&&s._payload.value._store&&(s._payload.value._store.validated=1):s._store&&(s._store.validated=1))}function R(s){return typeof s==="object"&&s!==null&&s.$$typeof===p}var o=E5(),p=Symbol.for("react.transitional.element"),q4=Symbol.for("react.portal"),h=Symbol.for("react.fragment"),t=Symbol.for("react.strict_mode"),I4=Symbol.for("react.profiler"),u4=Symbol.for("react.consumer"),i4=Symbol.for("react.context"),g7=Symbol.for("react.forward_ref"),h7=Symbol.for("react.suspense"),T4=Symbol.for("react.suspense_list"),p4=Symbol.for("react.memo"),N7=Symbol.for("react.lazy"),Y4=Symbol.for("react.activity"),l4=Symbol.for("react.client.reference"),d4=o.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE,b4=Object.prototype.hasOwnProperty,n4=Array.isArray,B4=console.createTask?console.createTask:function(){return null};o={react_stack_bottom_frame:function(s){return s()}};var L4,O4={},$4=o.react_stack_bottom_frame.bind(o,O)(),C4=B4(K(O)),R7={};yz.Fragment=h,yz.jsx=function(s,c4,Q7){var W7=1e4>d4.recentlyCreatedOwnerStacks++;return b(s,c4,Q7,!1,W7?Error("react-stack-top-frame"):$4,W7?B4(K(s)):C4)},yz.jsxs=function(s,c4,Q7){var W7=1e4>d4.recentlyCreatedOwnerStacks++;return b(s,c4,Q7,!0,W7?Error("react-stack-top-frame"):$4,W7?B4(K(s)):C4)}})()});var n2=h6((WM,x_)=>{x_.exports=I_()});var P3=PZ(E5(),1),A3=PZ(w_(),1);var m=PZ(E5(),1),$3=PZ(vz(),1),mZ=PZ(E5(),1),A4=PZ(n2(),1),vZ=PZ(n2(),1),d6=PZ(E5(),1),J3=PZ(vz(),1),qG=PZ(n2(),1),NH=PZ(n2(),1),t7=PZ(E5(),1),V=PZ(n2(),1),RZ=PZ(n2(),1),hZ=PZ(E5(),1),L=PZ(n2(),1),F7=PZ(E5(),1),n7=PZ(n2(),1),R3=PZ(E5(),1),w5=PZ(n2(),1),PB=PZ(n2(),1),M3=PZ(E5(),1),E0=PZ(n2(),1),w0=PZ(n2(),1),y4=PZ(n2(),1),W4=PZ(n2(),1),uV=`.styles-module__popup___IhzrD svg[fill=none] {
  fill: none !important;
}
.styles-module__popup___IhzrD svg[fill=none] :not([fill]) {
  fill: none !important;
}

@keyframes styles-module__popupEnter___AuQDN {
  from {
    opacity: 0;
    transform: translateX(-50%) scale(0.95) translateY(4px);
  }
  to {
    opacity: 1;
    transform: translateX(-50%) scale(1) translateY(0);
  }
}
@keyframes styles-module__popupExit___JJKQX {
  from {
    opacity: 1;
    transform: translateX(-50%) scale(1) translateY(0);
  }
  to {
    opacity: 0;
    transform: translateX(-50%) scale(0.95) translateY(4px);
  }
}
@keyframes styles-module__shake___jdbWe {
  0%, 100% {
    transform: translateX(-50%) scale(1) translateY(0) translateX(0);
  }
  20% {
    transform: translateX(-50%) scale(1) translateY(0) translateX(-3px);
  }
  40% {
    transform: translateX(-50%) scale(1) translateY(0) translateX(3px);
  }
  60% {
    transform: translateX(-50%) scale(1) translateY(0) translateX(-2px);
  }
  80% {
    transform: translateX(-50%) scale(1) translateY(0) translateX(2px);
  }
}
.styles-module__popup___IhzrD {
  position: fixed;
  transform: translateX(-50%);
  width: 280px;
  padding: 0.75rem 1rem 14px;
  background: #1a1a1a;
  border-radius: 16px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.08);
  z-index: 100001;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  will-change: transform, opacity;
  opacity: 0;
}
.styles-module__popup___IhzrD.styles-module__enter___L7U7N {
  animation: styles-module__popupEnter___AuQDN 0.2s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
}
.styles-module__popup___IhzrD.styles-module__entered___COX-w {
  opacity: 1;
  transform: translateX(-50%) scale(1) translateY(0);
}
.styles-module__popup___IhzrD.styles-module__exit___5eGjE {
  animation: styles-module__popupExit___JJKQX 0.15s ease-in forwards;
}
.styles-module__popup___IhzrD.styles-module__entered___COX-w.styles-module__shake___jdbWe {
  animation: styles-module__shake___jdbWe 0.25s ease-out;
}

.styles-module__header___wWsSi {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5625rem;
}

.styles-module__element___fTV2z {
  font-size: 0.75rem;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.5);
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
}

.styles-module__headerToggle___WpW0b {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  flex: 1;
  min-width: 0;
  text-align: left;
}
.styles-module__headerToggle___WpW0b .styles-module__element___fTV2z {
  flex: 1;
}

.styles-module__chevron___ZZJlR {
  color: rgba(255, 255, 255, 0.5);
  transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  flex-shrink: 0;
}
.styles-module__chevron___ZZJlR.styles-module__expanded___2Hxgv {
  transform: rotate(90deg);
}

.styles-module__stylesWrapper___pnHgy {
  display: grid;
  grid-template-rows: 0fr;
  transition: grid-template-rows 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
.styles-module__stylesWrapper___pnHgy.styles-module__expanded___2Hxgv {
  grid-template-rows: 1fr;
}

.styles-module__stylesInner___YYZe2 {
  overflow: hidden;
}

.styles-module__stylesBlock___VfQKn {
  background: rgba(255, 255, 255, 0.05);
  border-radius: 0.375rem;
  padding: 0.5rem 0.625rem;
  margin-bottom: 0.5rem;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.6875rem;
  line-height: 1.5;
}

.styles-module__styleLine___1YQiD {
  color: rgba(255, 255, 255, 0.85);
  word-break: break-word;
}

.styles-module__styleProperty___84L1i {
  color: #c792ea;
}

.styles-module__styleValue___q51-h {
  color: rgba(255, 255, 255, 0.85);
}

.styles-module__timestamp___Dtpsv {
  font-size: 0.625rem;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.35);
  font-variant-numeric: tabular-nums;
  margin-left: 0.5rem;
  flex-shrink: 0;
}

.styles-module__quote___mcMmQ {
  font-size: 12px;
  font-style: italic;
  color: rgba(255, 255, 255, 0.6);
  margin-bottom: 0.5rem;
  padding: 0.4rem 0.5rem;
  background: rgba(255, 255, 255, 0.05);
  border-radius: 0.25rem;
  line-height: 1.45;
}

.styles-module__textarea___jrSae {
  box-sizing: border-box;
  width: 100%;
  padding: 0.5rem 0.625rem;
  font-size: 0.8125rem;
  font-family: inherit;
  background: rgba(255, 255, 255, 0.05);
  color: #fff;
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 8px;
  resize: none;
  outline: none;
  transition: border-color 0.15s ease;
}
.styles-module__textarea___jrSae:focus {
  border-color: var(--agentation-color-blue);
}
.styles-module__textarea___jrSae.styles-module__green___99l3h:focus {
  border-color: var(--agentation-color-green);
}
.styles-module__textarea___jrSae::placeholder {
  color: rgba(255, 255, 255, 0.35);
}
.styles-module__textarea___jrSae::-webkit-scrollbar {
  width: 6px;
}
.styles-module__textarea___jrSae::-webkit-scrollbar-track {
  background: transparent;
}
.styles-module__textarea___jrSae::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 3px;
}

.styles-module__actions___D6x3f {
  display: flex;
  justify-content: flex-end;
  gap: 0.375rem;
  margin-top: 0.5rem;
}

.styles-module__cancel___hRjnL,
.styles-module__submit___K-mIR {
  padding: 0.4rem 0.875rem;
  font-size: 0.75rem;
  font-weight: 500;
  border-radius: 1rem;
  border: none;
  cursor: pointer;
  transition: background-color 0.15s ease, color 0.15s ease, opacity 0.15s ease;
}

.styles-module__cancel___hRjnL {
  background: transparent;
  color: rgba(255, 255, 255, 0.5);
}
.styles-module__cancel___hRjnL:hover {
  background: rgba(255, 255, 255, 0.1);
  color: rgba(255, 255, 255, 0.8);
}

.styles-module__submit___K-mIR {
  color: white;
}
.styles-module__submit___K-mIR:hover:not(:disabled) {
  filter: brightness(0.9);
}
.styles-module__submit___K-mIR:disabled {
  cursor: not-allowed;
}

.styles-module__deleteWrapper___oSjdo {
  margin-right: auto;
}

.styles-module__deleteButton___4VuAE {
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: none;
  background: transparent;
  color: rgba(255, 255, 255, 0.4);
  transition: background-color 0.15s ease, color 0.15s ease, transform 0.1s ease;
}
.styles-module__deleteButton___4VuAE:hover {
  background-color: color-mix(in srgb, var(--agentation-color-red) 25%, transparent);
  color: var(--agentation-color-red);
}
.styles-module__deleteButton___4VuAE:active {
  transform: scale(0.92);
}

.styles-module__light___6AaSQ.styles-module__popup___IhzrD {
  background: #fff;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.12), 0 0 0 1px rgba(0, 0, 0, 0.06);
}
.styles-module__light___6AaSQ .styles-module__element___fTV2z {
  color: rgba(0, 0, 0, 0.6);
}
.styles-module__light___6AaSQ .styles-module__timestamp___Dtpsv {
  color: rgba(0, 0, 0, 0.4);
}
.styles-module__light___6AaSQ .styles-module__chevron___ZZJlR {
  color: rgba(0, 0, 0, 0.4);
}
.styles-module__light___6AaSQ .styles-module__stylesBlock___VfQKn {
  background: rgba(0, 0, 0, 0.03);
}
.styles-module__light___6AaSQ .styles-module__styleLine___1YQiD {
  color: rgba(0, 0, 0, 0.75);
}
.styles-module__light___6AaSQ .styles-module__styleProperty___84L1i {
  color: #7c3aed;
}
.styles-module__light___6AaSQ .styles-module__styleValue___q51-h {
  color: rgba(0, 0, 0, 0.75);
}
.styles-module__light___6AaSQ .styles-module__quote___mcMmQ {
  color: rgba(0, 0, 0, 0.55);
  background: rgba(0, 0, 0, 0.04);
}
.styles-module__light___6AaSQ .styles-module__textarea___jrSae {
  background: rgba(0, 0, 0, 0.03);
  color: #1a1a1a;
  border-color: rgba(0, 0, 0, 0.12);
}
.styles-module__light___6AaSQ .styles-module__textarea___jrSae::placeholder {
  color: rgba(0, 0, 0, 0.4);
}
.styles-module__light___6AaSQ .styles-module__textarea___jrSae::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.15);
}
.styles-module__light___6AaSQ .styles-module__cancel___hRjnL {
  color: rgba(0, 0, 0, 0.5);
}
.styles-module__light___6AaSQ .styles-module__cancel___hRjnL:hover {
  background: rgba(0, 0, 0, 0.06);
  color: rgba(0, 0, 0, 0.75);
}
.styles-module__light___6AaSQ .styles-module__deleteButton___4VuAE {
  color: rgba(0, 0, 0, 0.4);
}
.styles-module__light___6AaSQ .styles-module__deleteButton___4VuAE:hover {
  background-color: color-mix(in srgb, var(--agentation-color-red) 25%, transparent);
  color: var(--agentation-color-red);
}`,dV={popup:"styles-module__popup___IhzrD",enter:"styles-module__enter___L7U7N",popupEnter:"styles-module__popupEnter___AuQDN",entered:"styles-module__entered___COX-w",exit:"styles-module__exit___5eGjE",popupExit:"styles-module__popupExit___JJKQX",shake:"styles-module__shake___jdbWe",header:"styles-module__header___wWsSi",element:"styles-module__element___fTV2z",headerToggle:"styles-module__headerToggle___WpW0b",chevron:"styles-module__chevron___ZZJlR",expanded:"styles-module__expanded___2Hxgv",stylesWrapper:"styles-module__stylesWrapper___pnHgy",stylesInner:"styles-module__stylesInner___YYZe2",stylesBlock:"styles-module__stylesBlock___VfQKn",styleLine:"styles-module__styleLine___1YQiD",styleProperty:"styles-module__styleProperty___84L1i",styleValue:"styles-module__styleValue___q51-h",timestamp:"styles-module__timestamp___Dtpsv",quote:"styles-module__quote___mcMmQ",textarea:"styles-module__textarea___jrSae",green:"styles-module__green___99l3h",actions:"styles-module__actions___D6x3f",cancel:"styles-module__cancel___hRjnL",submit:"styles-module__submit___K-mIR",deleteWrapper:"styles-module__deleteWrapper___oSjdo",deleteButton:"styles-module__deleteButton___4VuAE",light:"styles-module__light___6AaSQ"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-annotation-popup-css-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-annotation-popup-css-styles",document.head.appendChild(J);J.textContent=uV}var FZ=dV,pV=`.icon-transitions-module__iconState___uqK9J {
  transition: opacity 0.2s ease, transform 0.2s ease;
  transform-origin: center;
}

.icon-transitions-module__iconStateFast___HxlMm {
  transition: opacity 0.15s ease, transform 0.15s ease;
  transform-origin: center;
}

.icon-transitions-module__iconFade___nPwXg {
  transition: opacity 0.2s ease;
}

.icon-transitions-module__iconFadeFast___Ofb2t {
  transition: opacity 0.15s ease;
}

.icon-transitions-module__visible___PlHsU {
  opacity: 1 !important;
}

.icon-transitions-module__visibleScaled___8Qog- {
  opacity: 1 !important;
  transform: scale(1);
}

.icon-transitions-module__hidden___ETykt {
  opacity: 0 !important;
}

.icon-transitions-module__hiddenScaled___JXn-m {
  opacity: 0 !important;
  transform: scale(0.8);
}

.icon-transitions-module__sending___uaLN- {
  opacity: 0.5 !important;
  transform: scale(0.8);
}`,cV={iconState:"icon-transitions-module__iconState___uqK9J",iconStateFast:"icon-transitions-module__iconStateFast___HxlMm",iconFade:"icon-transitions-module__iconFade___nPwXg",iconFadeFast:"icon-transitions-module__iconFadeFast___Ofb2t",visible:"icon-transitions-module__visible___PlHsU",visibleScaled:"icon-transitions-module__visibleScaled___8Qog-",hidden:"icon-transitions-module__hidden___ETykt",hiddenScaled:"icon-transitions-module__hiddenScaled___JXn-m",sending:"icon-transitions-module__sending___uaLN-"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-components-icon-transitions");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-components-icon-transitions",document.head.appendChild(J);J.textContent=pV}var _Z=cV;var lV=({size:J=16})=>A4.jsx("svg",{width:J,height:J,viewBox:"0 0 16 16",fill:"none",children:A4.jsx("path",{d:"M8 3v10M3 8h10",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round"})});var sV=({size:J=24,style:H={}})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",style:H,children:[A4.jsxs("g",{clipPath:"url(#clip0_list_sparkle)",children:[A4.jsx("path",{d:"M11.5 12L5.5 12",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M18.5 6.75L5.5 6.75",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M9.25 17.25L5.5 17.25",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M16 12.75L16.5179 13.9677C16.8078 14.6494 17.3506 15.1922 18.0323 15.4821L19.25 16L18.0323 16.5179C17.3506 16.8078 16.8078 17.3506 16.5179 18.0323L16 19.25L15.4821 18.0323C15.1922 17.3506 14.6494 16.8078 13.9677 16.5179L12.75 16L13.9677 15.4821C14.6494 15.1922 15.1922 14.6494 15.4821 13.9677L16 12.75Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinejoin:"round"})]}),A4.jsx("defs",{children:A4.jsx("clipPath",{id:"clip0_list_sparkle",children:A4.jsx("rect",{width:"24",height:"24",fill:"white"})})})]}),aV=({size:J=20,...H})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 20 20",fill:"none",xmlns:"http://www.w3.org/2000/svg",...H,children:[A4.jsx("circle",{cx:"10",cy:"10",r:"5.375",stroke:"currentColor",strokeWidth:"1.25"}),A4.jsx("path",{d:"M8.5 8.5C8.73 7.85 9.31 7.49 10 7.5C10.86 7.51 11.5 8.13 11.5 9C11.5 10.08 10 10.5 10 10.5V10.75",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("circle",{cx:"10",cy:"12.625",r:"0.625",fill:"currentColor"})]});var iV=({size:J=24,copied:H=!1,tint:Y})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",style:Y?{color:Y,transition:"color 0.3s ease"}:void 0,children:[A4.jsxs("g",{className:`${_Z.iconState} ${H?_Z.hiddenScaled:_Z.visibleScaled}`,children:[A4.jsx("path",{d:"M4.75 11.25C4.75 10.4216 5.42157 9.75 6.25 9.75H12.75C13.5784 9.75 14.25 10.4216 14.25 11.25V17.75C14.25 18.5784 13.5784 19.25 12.75 19.25H6.25C5.42157 19.25 4.75 18.5784 4.75 17.75V11.25Z",stroke:"currentColor",strokeWidth:"1.5"}),A4.jsx("path",{d:"M17.25 14.25H17.75C18.5784 14.25 19.25 13.5784 19.25 12.75V6.25C19.25 5.42157 18.5784 4.75 17.75 4.75H11.25C10.4216 4.75 9.75 5.42157 9.75 6.25V6.75",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round"})]}),A4.jsxs("g",{className:`${_Z.iconState} ${H?_Z.visibleScaled:_Z.hiddenScaled}`,children:[A4.jsx("path",{d:"M12 20C7.58172 20 4 16.4182 4 12C4 7.58172 7.58172 4 12 4C16.4182 4 20 7.58172 20 12C20 16.4182 16.4182 20 12 20Z",stroke:"var(--agentation-color-green)",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M15 10L11 14.25L9.25 12.25",stroke:"var(--agentation-color-green)",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})]})]}),oV=({size:J=24,state:H="idle"})=>{let Y=H==="idle",K=H==="sent",W=H==="failed",O=H==="sending";return A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:[A4.jsx("g",{className:`${_Z.iconStateFast} ${Y?_Z.visibleScaled:O?_Z.sending:_Z.hiddenScaled}`,children:A4.jsx("path",{d:"M9.875 14.125L12.3506 19.6951C12.7184 20.5227 13.9091 20.4741 14.2083 19.6193L18.8139 6.46032C19.0907 5.6695 18.3305 4.90933 17.5397 5.18611L4.38072 9.79174C3.52589 10.0909 3.47731 11.2816 4.30494 11.6494L9.875 14.125ZM9.875 14.125L13.375 10.625",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})}),A4.jsxs("g",{className:`${_Z.iconStateFast} ${K?_Z.visibleScaled:_Z.hiddenScaled}`,children:[A4.jsx("path",{d:"M12 20C7.58172 20 4 16.4182 4 12C4 7.58172 7.58172 4 12 4C16.4182 4 20 7.58172 20 12C20 16.4182 16.4182 20 12 20Z",stroke:"var(--agentation-color-green)",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M15 10L11 14.25L9.25 12.25",stroke:"var(--agentation-color-green)",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})]}),A4.jsxs("g",{className:`${_Z.iconStateFast} ${W?_Z.visibleScaled:_Z.hiddenScaled}`,children:[A4.jsx("path",{d:"M12 20C7.58172 20 4 16.4182 4 12C4 7.58172 7.58172 4 12 4C16.4182 4 20 7.58172 20 12C20 16.4182 16.4182 20 12 20Z",stroke:"var(--agentation-color-red)",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M12 8V12",stroke:"var(--agentation-color-red)",strokeWidth:"1.5",strokeLinecap:"round"}),A4.jsx("circle",{cx:"12",cy:"15",r:"0.5",fill:"var(--agentation-color-red)",stroke:"var(--agentation-color-red)",strokeWidth:"1"})]})]})};var rV=({size:J=24,isOpen:H=!0})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:[A4.jsxs("g",{className:`${_Z.iconFade} ${H?_Z.visible:_Z.hidden}`,children:[A4.jsx("path",{d:"M3.91752 12.7539C3.65127 12.2996 3.65037 11.7515 3.9149 11.2962C4.9042 9.59346 7.72688 5.49994 12 5.49994C16.2731 5.49994 19.0958 9.59346 20.0851 11.2962C20.3496 11.7515 20.3487 12.2996 20.0825 12.7539C19.0908 14.4459 16.2694 18.4999 12 18.4999C7.73064 18.4999 4.90918 14.4459 3.91752 12.7539Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M12 14.8261C13.5608 14.8261 14.8261 13.5608 14.8261 12C14.8261 10.4392 13.5608 9.17392 12 9.17392C10.4392 9.17392 9.17391 10.4392 9.17391 12C9.17391 13.5608 10.4392 14.8261 12 14.8261Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})]}),A4.jsxs("g",{className:`${_Z.iconFade} ${H?_Z.hidden:_Z.visible}`,children:[A4.jsx("path",{d:"M18.6025 9.28503C18.9174 8.9701 19.4364 8.99481 19.7015 9.35271C20.1484 9.95606 20.4943 10.507 20.7342 10.9199C21.134 11.6086 21.1329 12.4454 20.7303 13.1328C20.2144 14.013 19.2151 15.5225 17.7723 16.8193C16.3293 18.1162 14.3852 19.2497 12.0008 19.25C11.4192 19.25 10.8638 19.1823 10.3355 19.0613C9.77966 18.934 9.63498 18.2525 10.0382 17.8493C10.2412 17.6463 10.5374 17.573 10.8188 17.6302C11.1993 17.7076 11.5935 17.75 12.0008 17.75C13.8848 17.7497 15.4867 16.8568 16.7693 15.7041C18.0522 14.5511 18.9606 13.1867 19.4363 12.375C19.5656 12.1543 19.5659 11.8943 19.4373 11.6729C19.2235 11.3049 18.921 10.8242 18.5364 10.3003C18.3085 9.98991 18.3302 9.5573 18.6025 9.28503ZM12.0008 4.75C12.5814 4.75006 13.1358 4.81803 13.6632 4.93953C14.2182 5.06741 14.362 5.74812 13.9593 6.15091C13.7558 6.35435 13.4589 6.42748 13.1771 6.36984C12.7983 6.29239 12.4061 6.25006 12.0008 6.25C10.1167 6.25 8.51415 7.15145 7.23028 8.31543C5.94678 9.47919 5.03918 10.8555 4.56426 11.6729C4.43551 11.8945 4.43582 12.1542 4.56524 12.375C4.77587 12.7343 5.07189 13.2012 5.44718 13.7105C5.67623 14.0213 5.65493 14.4552 5.38193 14.7282C5.0671 15.0431 4.54833 15.0189 4.28292 14.6614C3.84652 14.0736 3.50813 13.5369 3.27129 13.1328C2.86831 12.4451 2.86717 11.6088 3.26739 10.9199C3.78185 10.0345 4.77959 8.51239 6.22247 7.2041C7.66547 5.89584 9.61202 4.75 12.0008 4.75Z",fill:"currentColor"}),A4.jsx("path",{d:"M5 19L19 5",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round"})]})]}),nV=({size:J=24,isPaused:H=!1})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:[A4.jsxs("g",{className:`${_Z.iconFadeFast} ${H?_Z.hidden:_Z.visible}`,children:[A4.jsx("path",{d:"M8 6L8 18",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round"}),A4.jsx("path",{d:"M16 18L16 6",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round"})]}),A4.jsx("path",{className:`${_Z.iconFadeFast} ${H?_Z.visible:_Z.hidden}`,d:"M17.75 10.701C18.75 11.2783 18.75 12.7217 17.75 13.299L8.75 18.4952C7.75 19.0725 6.5 18.3509 6.5 17.1962L6.5 6.80384C6.5 5.64914 7.75 4.92746 8.75 5.50481L17.75 10.701Z",stroke:"currentColor",strokeWidth:"1.5"})]});var tV=({size:J=16})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:[A4.jsx("path",{d:"M10.6504 5.81117C10.9939 4.39628 13.0061 4.39628 13.3496 5.81117C13.5715 6.72517 14.6187 7.15891 15.4219 6.66952C16.6652 5.91193 18.0881 7.33479 17.3305 8.57815C16.8411 9.38134 17.2748 10.4285 18.1888 10.6504C19.6037 10.9939 19.6037 13.0061 18.1888 13.3496C17.2748 13.5715 16.8411 14.6187 17.3305 15.4219C18.0881 16.6652 16.6652 18.0881 15.4219 17.3305C14.6187 16.8411 13.5715 17.2748 13.3496 18.1888C13.0061 19.6037 10.9939 19.6037 10.6504 18.1888C10.4285 17.2748 9.38135 16.8411 8.57815 17.3305C7.33479 18.0881 5.91193 16.6652 6.66952 15.4219C7.15891 14.6187 6.72517 13.5715 5.81117 13.3496C4.39628 13.0061 4.39628 10.9939 5.81117 10.6504C6.72517 10.4285 7.15891 9.38134 6.66952 8.57815C5.91193 7.33479 7.33479 5.91192 8.57815 6.66952C9.38135 7.15891 10.4285 6.72517 10.6504 5.81117Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("circle",{cx:"12",cy:"12",r:"2.5",stroke:"currentColor",strokeWidth:"1.5"})]});var eV=({size:J=16})=>A4.jsx("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:A4.jsx("path",{d:"M13.5 4C14.7426 4 15.75 5.00736 15.75 6.25V7H18.5C18.9142 7 19.25 7.33579 19.25 7.75C19.25 8.16421 18.9142 8.5 18.5 8.5H17.9678L17.6328 16.2217C17.61 16.7475 17.5912 17.1861 17.5469 17.543C17.5015 17.9087 17.4225 18.2506 17.2461 18.5723C16.9747 19.0671 16.5579 19.4671 16.0518 19.7168C15.7227 19.8791 15.3772 19.9422 15.0098 19.9717C14.6514 20.0004 14.2126 20 13.6865 20H10.3135C9.78735 20 9.34856 20.0004 8.99023 19.9717C8.62278 19.9422 8.27729 19.8791 7.94824 19.7168C7.44205 19.4671 7.02532 19.0671 6.75391 18.5723C6.57751 18.2506 6.49853 17.9087 6.45312 17.543C6.40883 17.1861 6.39005 16.7475 6.36719 16.2217L6.03223 8.5H5.5C5.08579 8.5 4.75 8.16421 4.75 7.75C4.75 7.33579 5.08579 7 5.5 7H8.25V6.25C8.25 5.00736 9.25736 4 10.5 4H13.5ZM7.86621 16.1562C7.89013 16.7063 7.90624 17.0751 7.94141 17.3584C7.97545 17.6326 8.02151 17.7644 8.06934 17.8516C8.19271 18.0763 8.38239 18.2577 8.6123 18.3711C8.70153 18.4151 8.83504 18.4545 9.11035 18.4766C9.39482 18.4994 9.76335 18.5 10.3135 18.5H13.6865C14.2367 18.5 14.6052 18.4994 14.8896 18.4766C15.165 18.4545 15.2985 18.4151 15.3877 18.3711C15.6176 18.2577 15.8073 18.0763 15.9307 17.8516C15.9785 17.7644 16.0245 17.6326 16.0586 17.3584C16.0938 17.0751 16.1099 16.7063 16.1338 16.1562L16.4668 8.5H7.5332L7.86621 16.1562ZM9.97656 10.75C10.3906 10.7371 10.7371 11.0626 10.75 11.4766L10.875 15.4766C10.8879 15.8906 10.5624 16.2371 10.1484 16.25C9.73443 16.2629 9.38794 15.9374 9.375 15.5234L9.25 11.5234C9.23706 11.1094 9.56255 10.7629 9.97656 10.75ZM14.0244 10.75C14.4384 10.7635 14.7635 11.1105 14.75 11.5244L14.6201 15.5244C14.6066 15.9384 14.2596 16.2634 13.8457 16.25C13.4317 16.2365 13.1067 15.8896 13.1201 15.4756L13.251 11.4756C13.2645 11.0617 13.6105 10.7366 14.0244 10.75ZM10.5 5.5C10.0858 5.5 9.75 5.83579 9.75 6.25V7H14.25V6.25C14.25 5.83579 13.9142 5.5 13.5 5.5H10.5Z",fill:"currentColor"})});var z3=({size:J=16})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:[A4.jsxs("g",{clipPath:"url(#clip0_2_53)",children:[A4.jsx("path",{d:"M16.25 16.25L7.75 7.75",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M7.75 16.25L16.25 7.75",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})]}),A4.jsx("defs",{children:A4.jsx("clipPath",{id:"clip0_2_53",children:A4.jsx("rect",{width:"24",height:"24",fill:"white"})})})]}),ZO=({size:J=24})=>A4.jsx("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:A4.jsx("path",{d:"M16.7198 6.21973C17.0127 5.92683 17.4874 5.92683 17.7803 6.21973C18.0732 6.51262 18.0732 6.9874 17.7803 7.28027L13.0606 12L17.7803 16.7197C18.0732 17.0126 18.0732 17.4874 17.7803 17.7803C17.4875 18.0731 17.0127 18.0731 16.7198 17.7803L12.0001 13.0605L7.28033 17.7803C6.98746 18.0731 6.51268 18.0731 6.21979 17.7803C5.92689 17.4874 5.92689 17.0126 6.21979 16.7197L10.9395 12L6.21979 7.28027C5.92689 6.98738 5.92689 6.51262 6.21979 6.21973C6.51268 5.92683 6.98744 5.92683 7.28033 6.21973L12.0001 10.9395L16.7198 6.21973Z",fill:"currentColor"})}),GO=({size:J=16})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 20 20",fill:"none",children:[A4.jsx("path",{d:"M9.99999 12.7082C11.4958 12.7082 12.7083 11.4956 12.7083 9.99984C12.7083 8.50407 11.4958 7.2915 9.99999 7.2915C8.50422 7.2915 7.29166 8.50407 7.29166 9.99984C7.29166 11.4956 8.50422 12.7082 9.99999 12.7082Z",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M10 3.9585V5.05698",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M10 14.9429V16.0414",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M5.7269 5.72656L6.50682 6.50649",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M13.4932 13.4932L14.2731 14.2731",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M3.95834 10H5.05683",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M14.9432 10H16.0417",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M5.7269 14.2731L6.50682 13.4932",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"}),A4.jsx("path",{d:"M13.4932 6.50649L14.2731 5.72656",stroke:"currentColor",strokeWidth:"1.25",strokeLinecap:"round",strokeLinejoin:"round"})]}),BO=({size:J=16})=>A4.jsx("svg",{width:J,height:J,viewBox:"0 0 20 20",fill:"none",children:A4.jsx("path",{d:"M15.5 10.4955C15.4037 11.5379 15.0124 12.5314 14.3721 13.3596C13.7317 14.1878 12.8688 14.8165 11.8841 15.1722C10.8995 15.5278 9.83397 15.5957 8.81217 15.3679C7.79038 15.1401 6.8546 14.6259 6.11434 13.8857C5.37408 13.1454 4.85995 12.2096 4.63211 11.1878C4.40427 10.166 4.47215 9.10048 4.82781 8.11585C5.18346 7.13123 5.81218 6.26825 6.64039 5.62791C7.4686 4.98756 8.46206 4.59634 9.5045 4.5C8.89418 5.32569 8.60049 6.34302 8.67685 7.36695C8.75321 8.39087 9.19454 9.35339 9.92058 10.0794C10.6466 10.8055 11.6091 11.2468 12.6331 11.3231C13.657 11.3995 14.6743 11.1058 15.5 10.4955Z",stroke:"currentColor",strokeWidth:"1.13793",strokeLinecap:"round",strokeLinejoin:"round"})}),$O=({size:J=16})=>A4.jsx("svg",{width:J,height:J,viewBox:"0 0 16 16",fill:"none",xmlns:"http://www.w3.org/2000/svg",children:A4.jsx("path",{d:"M11.3799 6.9572L9.05645 4.63375M11.3799 6.9572L6.74949 11.5699C6.61925 11.6996 6.45577 11.791 6.277 11.8339L4.29549 12.3092C3.93194 12.3964 3.60478 12.0683 3.69297 11.705L4.16585 9.75693C4.20893 9.57947 4.29978 9.4172 4.42854 9.28771L9.05645 4.63375M11.3799 6.9572L12.3455 5.98759C12.9839 5.34655 12.9839 4.31002 12.3455 3.66897C11.7033 3.02415 10.6594 3.02415 10.0172 3.66897L9.06126 4.62892L9.05645 4.63375",stroke:"currentColor",strokeWidth:"0.9",strokeLinecap:"round",strokeLinejoin:"round"})}),zO=({size:J=24})=>A4.jsx("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",xmlns:"http://www.w3.org/2000/svg",children:A4.jsx("path",{d:"M13.5 4C14.7426 4 15.75 5.00736 15.75 6.25V7H18.5C18.9142 7 19.25 7.33579 19.25 7.75C19.25 8.16421 18.9142 8.5 18.5 8.5H17.9678L17.6328 16.2217C17.61 16.7475 17.5912 17.1861 17.5469 17.543C17.5015 17.9087 17.4225 18.2506 17.2461 18.5723C16.9747 19.0671 16.5579 19.4671 16.0518 19.7168C15.7227 19.8791 15.3772 19.9422 15.0098 19.9717C14.6514 20.0004 14.2126 20 13.6865 20H10.3135C9.78735 20 9.34856 20.0004 8.99023 19.9717C8.62278 19.9422 8.27729 19.8791 7.94824 19.7168C7.44205 19.4671 7.02532 19.0671 6.75391 18.5723C6.57751 18.2506 6.49853 17.9087 6.45312 17.543C6.40883 17.1861 6.39005 16.7475 6.36719 16.2217L6.03223 8.5H5.5C5.08579 8.5 4.75 8.16421 4.75 7.75C4.75 7.33579 5.08579 7 5.5 7H8.25V6.25C8.25 5.00736 9.25736 4 10.5 4H13.5ZM7.86621 16.1562C7.89013 16.7063 7.90624 17.0751 7.94141 17.3584C7.97545 17.6326 8.02151 17.7644 8.06934 17.8516C8.19271 18.0763 8.38239 18.2577 8.6123 18.3711C8.70153 18.4151 8.83504 18.4545 9.11035 18.4766C9.39482 18.4994 9.76335 18.5 10.3135 18.5H13.6865C14.2367 18.5 14.6052 18.4994 14.8896 18.4766C15.165 18.4545 15.2985 18.4151 15.3877 18.3711C15.6176 18.2577 15.8073 18.0763 15.9307 17.8516C15.9785 17.7644 16.0245 17.6326 16.0586 17.3584C16.0938 17.0751 16.1099 16.7063 16.1338 16.1562L16.4668 8.5H7.5332L7.86621 16.1562ZM9.97656 10.75C10.3906 10.7371 10.7371 11.0626 10.75 11.4766L10.875 15.4766C10.8879 15.8906 10.5624 16.2371 10.1484 16.25C9.73443 16.2629 9.38794 15.9374 9.375 15.5234L9.25 11.5234C9.23706 11.1094 9.56255 10.7629 9.97656 10.75ZM14.0244 10.75C14.4383 10.7635 14.7635 11.1105 14.75 11.5244L14.6201 15.5244C14.6066 15.9384 14.2596 16.2634 13.8457 16.25C13.4317 16.2365 13.1067 15.8896 13.1201 15.4756L13.251 11.4756C13.2645 11.0617 13.6105 10.7366 14.0244 10.75ZM10.5 5.5C10.0858 5.5 9.75 5.83579 9.75 6.25V7H14.25V6.25C14.25 5.83579 13.9142 5.5 13.5 5.5H10.5Z",fill:"currentColor"})}),QO=({size:J=16})=>A4.jsx("svg",{width:J,height:J,viewBox:"0 0 16 16",fill:"none",xmlns:"http://www.w3.org/2000/svg",children:A4.jsx("path",{d:"M8.5 3.5L4 8L8.5 12.5",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})});var JO=({size:J=24})=>A4.jsxs("svg",{width:J,height:J,viewBox:"0 0 24 24",fill:"none",children:[A4.jsx("rect",{x:"3",y:"3",width:"18",height:"18",rx:"2",stroke:"currentColor",strokeWidth:"1.5"}),A4.jsx("line",{x1:"3",y1:"9",x2:"21",y2:"9",stroke:"currentColor",strokeWidth:"1.5"}),A4.jsx("line",{x1:"9",y1:"9",x2:"9",y2:"21",stroke:"currentColor",strokeWidth:"1.5"})]}),Q3=["data-feedback-toolbar","data-annotation-popup","data-annotation-marker"],XH=Q3.flatMap((J)=>[`:not([${J}])`,`:not([${J}] *)`]).join(""),MH="feedback-freeze-styles",YH="__agentation_freeze";function qO(){if(typeof window>"u")return{frozen:!1,installed:!0,origSetTimeout:setTimeout,origSetInterval:setInterval,origRAF:(H)=>0,pausedAnimations:[],frozenTimeoutQueue:[],frozenRAFQueue:[]};let J=window;if(!J[YH])J[YH]={frozen:!1,installed:!1,origSetTimeout:null,origSetInterval:null,origRAF:null,pausedAnimations:[],frozenTimeoutQueue:[],frozenRAFQueue:[]};return J[YH]}var p7=qO();if(typeof window<"u"&&!p7.installed)p7.origSetTimeout=window.setTimeout.bind(window),p7.origSetInterval=window.setInterval.bind(window),p7.origRAF=window.requestAnimationFrame.bind(window),window.setTimeout=(J,H,...Y)=>{if(typeof J==="string")return p7.origSetTimeout(J,H);return p7.origSetTimeout((...K)=>{if(p7.frozen)p7.frozenTimeoutQueue.push(()=>J(...K));else J(...K)},H,...Y)},window.setInterval=(J,H,...Y)=>{if(typeof J==="string")return p7.origSetInterval(J,H);return p7.origSetInterval((...K)=>{if(!p7.frozen)J(...K)},H,...Y)},window.requestAnimationFrame=(J)=>{return p7.origRAF((H)=>{if(p7.frozen)p7.frozenRAFQueue.push(J);else J(H)})},p7.installed=!0;var{origSetTimeout:q7,origSetInterval:HO,origRAF:C0}=p7;function XO(J){if(!J)return!1;return Q3.some((H)=>!!J.closest?.(`[${H}]`))}function YO(){if(typeof document>"u")return;if(p7.frozen)return;p7.frozen=!0,p7.frozenTimeoutQueue=[],p7.frozenRAFQueue=[];let J=document.getElementById(MH);if(!J)J=document.createElement("style"),J.id=MH;J.textContent=`
    *${XH},
    *${XH}::before,
    *${XH}::after {
      animation-play-state: paused !important;
      transition: none !important;
    }
  `,document.head.appendChild(J),p7.pausedAnimations=[];try{document.getAnimations().forEach((H)=>{if(H.playState!=="running")return;let Y=H.effect?.target;if(!XO(Y))H.pause(),p7.pausedAnimations.push(H)})}catch{}document.querySelectorAll("video").forEach((H)=>{if(!H.paused)H.dataset.wasPaused="false",H.pause()})}function S_(){if(typeof document>"u")return;if(!p7.frozen)return;p7.frozen=!1;let J=p7.frozenTimeoutQueue;p7.frozenTimeoutQueue=[];for(let Y of J)p7.origSetTimeout(()=>{if(p7.frozen){p7.frozenTimeoutQueue.push(Y);return}try{Y()}catch(K){console.warn("[agentation] Error replaying queued timeout:",K)}},0);let H=p7.frozenRAFQueue;p7.frozenRAFQueue=[];for(let Y of H)p7.origRAF((K)=>{if(p7.frozen){p7.frozenRAFQueue.push(Y);return}Y(K)});for(let Y of p7.pausedAnimations)try{Y.play()}catch(K){console.warn("[agentation] Error resuming animation:",K)}p7.pausedAnimations=[],document.getElementById(MH)?.remove(),document.querySelectorAll("video").forEach((Y)=>{if(Y.dataset.wasPaused==="false")Y.play().catch(()=>{}),delete Y.dataset.wasPaused})}function jH(J){if(!J)return;let H=(Y)=>Y.stopImmediatePropagation();document.addEventListener("focusin",H,!0),document.addEventListener("focusout",H,!0);try{J.focus()}finally{document.removeEventListener("focusin",H,!0),document.removeEventListener("focusout",H,!0)}}var iz=mZ.forwardRef(function({element:H,timestamp:Y,selectedText:K,placeholder:W="What should change?",initialValue:O="",submitLabel:A="Add",onSubmit:C,onCancel:x,onDelete:J4,style:b,accentColor:g="#3c82f7",isExiting:R=!1,lightMode:o=!1,computedStyles:p},q4){let[h,t]=mZ.useState(O),[I4,u4]=mZ.useState(!1),[i4,g7]=mZ.useState("initial"),[h7,T4]=mZ.useState(!1),[p4,N7]=mZ.useState(!1),Y4=mZ.useRef(null),l4=mZ.useRef(null),d4=mZ.useRef(null),b4=mZ.useRef(null);mZ.useEffect(()=>{if(R&&i4!=="exit")g7("exit")},[R,i4]),mZ.useEffect(()=>{q7(()=>{g7("enter")},0);let C4=q7(()=>{g7("entered")},200),R7=q7(()=>{let s=Y4.current;if(s)jH(s),s.selectionStart=s.selectionEnd=s.value.length,s.scrollTop=s.scrollHeight},50);return()=>{if(clearTimeout(C4),clearTimeout(R7),d4.current)clearTimeout(d4.current);if(b4.current)clearTimeout(b4.current)}},[]);let n4=mZ.useCallback(()=>{if(b4.current)clearTimeout(b4.current);u4(!0),b4.current=q7(()=>{u4(!1),jH(Y4.current)},250)},[]);mZ.useImperativeHandle(q4,()=>({shake:n4}),[n4]);let B4=mZ.useCallback(()=>{g7("exit"),d4.current=q7(()=>{x()},150)},[x]),L4=mZ.useCallback(()=>{if(!h.trim())return;C(h.trim())},[h,C]),O4=mZ.useCallback((C4)=>{if(C4.stopPropagation(),C4.nativeEvent.isComposing)return;if(C4.key==="Enter"&&!C4.shiftKey)C4.preventDefault(),L4();if(C4.key==="Escape")B4()},[L4,B4]),$4=[FZ.popup,o?FZ.light:"",i4==="enter"?FZ.enter:"",i4==="entered"?FZ.entered:"",i4==="exit"?FZ.exit:"",I4?FZ.shake:""].filter(Boolean).join(" ");return vZ.jsxs("div",{ref:l4,className:$4,"data-annotation-popup":!0,style:b,onClick:(C4)=>C4.stopPropagation(),children:[vZ.jsxs("div",{className:FZ.header,children:[p&&Object.keys(p).length>0?vZ.jsxs("button",{className:FZ.headerToggle,onClick:()=>{let C4=p4;if(N7(!p4),C4)q7(()=>jH(Y4.current),0)},type:"button",children:[vZ.jsx("svg",{className:`${FZ.chevron} ${p4?FZ.expanded:""}`,width:"14",height:"14",viewBox:"0 0 14 14",fill:"none",xmlns:"http://www.w3.org/2000/svg",children:vZ.jsx("path",{d:"M5.5 10.25L9 7.25L5.75 4",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})}),vZ.jsx("span",{className:FZ.element,children:H})]}):vZ.jsx("span",{className:FZ.element,children:H}),Y&&vZ.jsx("span",{className:FZ.timestamp,children:Y})]}),p&&Object.keys(p).length>0&&vZ.jsx("div",{className:`${FZ.stylesWrapper} ${p4?FZ.expanded:""}`,children:vZ.jsx("div",{className:FZ.stylesInner,children:vZ.jsx("div",{className:FZ.stylesBlock,children:Object.entries(p).map(([C4,R7])=>vZ.jsxs("div",{className:FZ.styleLine,children:[vZ.jsx("span",{className:FZ.styleProperty,children:C4.replace(/([A-Z])/g,"-$1").toLowerCase()}),": ",vZ.jsx("span",{className:FZ.styleValue,children:R7}),";"]},C4))})})}),K&&vZ.jsxs("div",{className:FZ.quote,children:["“",K.slice(0,80),K.length>80?"...":"","”"]}),vZ.jsx("textarea",{ref:Y4,className:FZ.textarea,style:{borderColor:h7?g:void 0},placeholder:W,value:h,onChange:(C4)=>t(C4.target.value),onFocus:()=>T4(!0),onBlur:()=>T4(!1),rows:2,onKeyDown:O4}),vZ.jsxs("div",{className:FZ.actions,children:[J4&&vZ.jsx("div",{className:FZ.deleteWrapper,children:vZ.jsx("button",{className:FZ.deleteButton,onClick:J4,type:"button",children:vZ.jsx(zO,{size:22})})}),vZ.jsx("button",{className:FZ.cancel,onClick:B4,children:"Cancel"}),vZ.jsx("button",{className:FZ.submit,style:{backgroundColor:g,opacity:h.trim()?1:0.4},onClick:L4,disabled:!h.trim(),children:A})]})]})}),jO=({content:J,children:H,...Y})=>{let[K,W]=d6.useState(!1),[O,A]=d6.useState(!1),[C,x]=d6.useState({top:0,right:0}),J4=d6.useRef(null),b=d6.useRef(null),g=d6.useRef(null),R=()=>{if(J4.current){let q4=J4.current.getBoundingClientRect();x({top:q4.top+q4.height/2,right:window.innerWidth-q4.left+8})}},o=()=>{if(A(!0),g.current)clearTimeout(g.current),g.current=null;R(),b.current=q7(()=>{W(!0)},500)},p=()=>{if(b.current)clearTimeout(b.current),b.current=null;W(!1),g.current=q7(()=>{A(!1)},150)};return d6.useEffect(()=>{return()=>{if(b.current)clearTimeout(b.current);if(g.current)clearTimeout(g.current)}},[]),qG.jsxs(qG.Fragment,{children:[qG.jsx("span",{ref:J4,onMouseEnter:o,onMouseLeave:p,...Y,children:H}),O&&J3.createPortal(qG.jsx("div",{"data-feedback-toolbar":!0,style:{position:"fixed",top:C.top,right:C.right,transform:"translateY(-50%)",padding:"6px 10px",background:"#383838",color:"rgba(255, 255, 255, 0.7)",fontSize:"11px",fontWeight:400,lineHeight:"14px",borderRadius:"10px",width:"180px",textAlign:"left",zIndex:100020,pointerEvents:"none",boxShadow:"0px 1px 8px rgba(0, 0, 0, 0.28)",opacity:K?1:0,transition:"opacity 0.15s ease"},children:J}),document.body)]})},KO=`.styles-module__tooltip___mcXL2 {
  display: flex;
  justify-content: center;
  align-items: center;
  cursor: help;
}

.styles-module__tooltipIcon___Nq2nD {
  transform: translateY(0.5px);
  color: #fff;
  opacity: 0.2;
  transition: opacity 0.15s ease;
  will-change: transform;
}
.styles-module__tooltip___mcXL2:hover .styles-module__tooltipIcon___Nq2nD {
  opacity: 0.5;
}
[data-agentation-theme=light] .styles-module__tooltipIcon___Nq2nD {
  color: #000;
}`,WO={tooltip:"styles-module__tooltip___mcXL2",tooltipIcon:"styles-module__tooltipIcon___Nq2nD"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-help-tooltip-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-help-tooltip-styles",document.head.appendChild(J);J.textContent=KO}var v_=WO,JG=({content:J})=>{return NH.jsx(jO,{className:v_.tooltip,content:J,children:NH.jsx(aV,{className:v_.tooltipIcon})})},f4={navigation:{width:800,height:56},hero:{width:800,height:320},header:{width:800,height:80},section:{width:800,height:400},sidebar:{width:240,height:400},footer:{width:800,height:160},modal:{width:480,height:300},card:{width:280,height:240},text:{width:400,height:120},image:{width:320,height:200},video:{width:480,height:270},table:{width:560,height:220},grid:{width:600,height:300},list:{width:300,height:180},chart:{width:400,height:240},button:{width:140,height:40},input:{width:280,height:56},form:{width:360,height:320},tabs:{width:480,height:240},dropdown:{width:200,height:200},toggle:{width:44,height:24},search:{width:320,height:44},avatar:{width:48,height:48},badge:{width:80,height:28},breadcrumb:{width:300,height:24},pagination:{width:300,height:36},progress:{width:240,height:8},divider:{width:600,height:1},accordion:{width:400,height:200},carousel:{width:600,height:300},toast:{width:320,height:64},tooltip:{width:180,height:40},pricing:{width:300,height:360},testimonial:{width:360,height:200},cta:{width:600,height:160},alert:{width:400,height:56},banner:{width:800,height:48},stat:{width:200,height:120},stepper:{width:480,height:48},tag:{width:72,height:28},rating:{width:160,height:28},map:{width:480,height:300},timeline:{width:360,height:320},fileUpload:{width:360,height:180},codeBlock:{width:480,height:200},calendar:{width:300,height:300},notification:{width:360,height:72},productCard:{width:280,height:360},profile:{width:280,height:200},drawer:{width:320,height:400},popover:{width:240,height:160},logo:{width:120,height:40},faq:{width:560,height:320},gallery:{width:560,height:360},checkbox:{width:20,height:20},radio:{width:20,height:20},slider:{width:240,height:32},datePicker:{width:300,height:320},skeleton:{width:320,height:120},chip:{width:96,height:32},icon:{width:24,height:24},spinner:{width:32,height:32},feature:{width:360,height:200},team:{width:560,height:280},login:{width:360,height:360},contact:{width:400,height:320}},q3=[{section:"Layout",items:[{type:"navigation",label:"Navigation",...f4.navigation},{type:"header",label:"Header",...f4.header},{type:"hero",label:"Hero",...f4.hero},{type:"section",label:"Section",...f4.section},{type:"sidebar",label:"Sidebar",...f4.sidebar},{type:"footer",label:"Footer",...f4.footer},{type:"modal",label:"Modal",...f4.modal},{type:"banner",label:"Banner",...f4.banner},{type:"drawer",label:"Drawer",...f4.drawer},{type:"popover",label:"Popover",...f4.popover},{type:"divider",label:"Divider",...f4.divider}]},{section:"Content",items:[{type:"card",label:"Card",...f4.card},{type:"text",label:"Text",...f4.text},{type:"image",label:"Image",...f4.image},{type:"video",label:"Video",...f4.video},{type:"table",label:"Table",...f4.table},{type:"grid",label:"Grid",...f4.grid},{type:"list",label:"List",...f4.list},{type:"chart",label:"Chart",...f4.chart},{type:"codeBlock",label:"Code Block",...f4.codeBlock},{type:"map",label:"Map",...f4.map},{type:"timeline",label:"Timeline",...f4.timeline},{type:"calendar",label:"Calendar",...f4.calendar},{type:"accordion",label:"Accordion",...f4.accordion},{type:"carousel",label:"Carousel",...f4.carousel},{type:"logo",label:"Logo",...f4.logo},{type:"faq",label:"FAQ",...f4.faq},{type:"gallery",label:"Gallery",...f4.gallery}]},{section:"Controls",items:[{type:"button",label:"Button",...f4.button},{type:"input",label:"Input",...f4.input},{type:"search",label:"Search",...f4.search},{type:"form",label:"Form",...f4.form},{type:"tabs",label:"Tabs",...f4.tabs},{type:"dropdown",label:"Dropdown",...f4.dropdown},{type:"toggle",label:"Toggle",...f4.toggle},{type:"stepper",label:"Stepper",...f4.stepper},{type:"rating",label:"Rating",...f4.rating},{type:"fileUpload",label:"File Upload",...f4.fileUpload},{type:"checkbox",label:"Checkbox",...f4.checkbox},{type:"radio",label:"Radio",...f4.radio},{type:"slider",label:"Slider",...f4.slider},{type:"datePicker",label:"Date Picker",...f4.datePicker}]},{section:"Elements",items:[{type:"avatar",label:"Avatar",...f4.avatar},{type:"badge",label:"Badge",...f4.badge},{type:"tag",label:"Tag",...f4.tag},{type:"breadcrumb",label:"Breadcrumb",...f4.breadcrumb},{type:"pagination",label:"Pagination",...f4.pagination},{type:"progress",label:"Progress",...f4.progress},{type:"alert",label:"Alert",...f4.alert},{type:"toast",label:"Toast",...f4.toast},{type:"notification",label:"Notification",...f4.notification},{type:"tooltip",label:"Tooltip",...f4.tooltip},{type:"stat",label:"Stat",...f4.stat},{type:"skeleton",label:"Skeleton",...f4.skeleton},{type:"chip",label:"Chip",...f4.chip},{type:"icon",label:"Icon",...f4.icon},{type:"spinner",label:"Spinner",...f4.spinner}]},{section:"Blocks",items:[{type:"pricing",label:"Pricing",...f4.pricing},{type:"testimonial",label:"Testimonial",...f4.testimonial},{type:"cta",label:"CTA",...f4.cta},{type:"productCard",label:"Product Card",...f4.productCard},{type:"profile",label:"Profile",...f4.profile},{type:"feature",label:"Feature",...f4.feature},{type:"team",label:"Team",...f4.team},{type:"login",label:"Login",...f4.login},{type:"contact",label:"Contact",...f4.contact}]}],j6={};for(let J of q3)for(let H of J.items)j6[H.type]=H;function X4({w:J,h:H=3,strong:Y}){return V.jsx("div",{style:{width:typeof J==="number"?`${J}px`:J,height:H,borderRadius:2,background:Y?"var(--agd-bar-strong)":"var(--agd-bar)",flexShrink:0}})}function XZ({w:J,h:H,radius:Y=3,style:K}){return V.jsx("div",{style:{width:typeof J==="number"?`${J}px`:J,height:typeof H==="number"?`${H}px`:H,borderRadius:Y,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",flexShrink:0,...K}})}function e2({size:J}){return V.jsx("div",{style:{width:J,height:J,borderRadius:"50%",border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",flexShrink:0}})}function _O({width:J,height:H}){let Y=Math.max(8,H*0.2);return V.jsxs("div",{style:{display:"flex",alignItems:"center",height:"100%",padding:`0 ${Y}px`,gap:J*0.02},children:[V.jsx(XZ,{w:Math.max(20,H*0.5),h:Math.max(12,H*0.4),radius:2}),V.jsxs("div",{style:{flex:1,display:"flex",gap:J*0.03,marginLeft:J*0.04},children:[V.jsx(X4,{w:J*0.06}),V.jsx(X4,{w:J*0.07}),V.jsx(X4,{w:J*0.05}),V.jsx(X4,{w:J*0.06})]}),V.jsx(XZ,{w:J*0.1,h:Math.min(28,H*0.5),radius:4})]})}function LO({width:J,height:H,text:Y}){return V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",gap:H*0.05},children:[Y?V.jsx("span",{style:{fontSize:Math.min(20,H*0.08),fontWeight:600,color:"var(--agd-text-3)",textAlign:"center",maxWidth:"80%"},children:Y}):V.jsx(X4,{w:J*0.5,h:Math.max(6,H*0.04),strong:!0}),V.jsx(X4,{w:J*0.6}),V.jsx(X4,{w:J*0.4}),V.jsx(XZ,{w:Math.min(140,J*0.2),h:Math.min(36,H*0.12),radius:6,style:{marginTop:H*0.06}})]})}function UO({width:J,height:H}){let Y=Math.max(3,Math.floor(H/36));return V.jsxs("div",{style:{padding:J*0.08,display:"flex",flexDirection:"column",gap:H*0.03},children:[V.jsx(X4,{w:J*0.6,h:4,strong:!0}),Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{display:"flex",alignItems:"center",gap:6},children:[V.jsx(XZ,{w:10,h:10,radius:2}),V.jsx(X4,{w:J*(0.4+W*17%30/100)})]},W))]})}function VO({width:J,height:H}){let Y=Math.max(2,Math.min(4,Math.floor(J/160)));return V.jsx("div",{style:{display:"flex",padding:`${H*0.12}px ${J*0.03}px`,gap:J*0.05},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:4},children:[V.jsx(X4,{w:"60%",h:3,strong:!0}),V.jsx(X4,{w:"80%",h:2}),V.jsx(X4,{w:"70%",h:2}),V.jsx(X4,{w:"60%",h:2})]},W))})}function OO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column"},children:[V.jsxs("div",{style:{padding:"10px 12px",borderBottom:"1px solid var(--agd-stroke)",display:"flex",alignItems:"center",justifyContent:"space-between"},children:[V.jsx(X4,{w:J*0.3,h:4,strong:!0}),V.jsx("div",{style:{width:14,height:14,border:"1px solid var(--agd-stroke)",borderRadius:3}})]}),V.jsxs("div",{style:{flex:1,padding:12,display:"flex",flexDirection:"column",gap:6},children:[V.jsx(X4,{w:"90%"}),V.jsx(X4,{w:"70%"}),V.jsx(X4,{w:"80%"})]}),V.jsxs("div",{style:{padding:"10px 12px",borderTop:"1px solid var(--agd-stroke)",display:"flex",justifyContent:"flex-end",gap:8},children:[V.jsx(XZ,{w:70,h:26,radius:4}),V.jsx(XZ,{w:70,h:26,radius:4,style:{background:"var(--agd-bar)"}})]})]})}function FO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column"},children:[V.jsx("div",{style:{height:"40%",background:"var(--agd-fill)",borderBottom:"1px dashed var(--agd-stroke)"}}),V.jsxs("div",{style:{flex:1,padding:10,display:"flex",flexDirection:"column",gap:5},children:[V.jsx(X4,{w:"70%",h:4,strong:!0}),V.jsx(X4,{w:"95%",h:2}),V.jsx(X4,{w:"85%",h:2}),V.jsx(X4,{w:"50%",h:2})]})]})}function RO({width:J,height:H,text:Y}){if(Y)return V.jsx("div",{style:{padding:4,fontSize:Math.min(14,H*0.3),lineHeight:1.5,color:"var(--agd-text-3)",wordBreak:"break-word",overflow:"hidden"},children:Y});let K=Math.max(2,Math.floor(H/18));return V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:6,padding:4},children:[V.jsx(X4,{w:J*0.6,h:5,strong:!0}),Array.from({length:K},(W,O)=>V.jsx(X4,{w:`${70+O*13%25}%`,h:2},O))]})}function MO({width:J,height:H}){return V.jsx("div",{style:{height:"100%",position:"relative"},children:V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,preserveAspectRatio:"none",fill:"none",children:[V.jsx("line",{x1:"0",y1:"0",x2:J,y2:H,stroke:"var(--agd-stroke)",strokeWidth:"1"}),V.jsx("line",{x1:J,y1:"0",x2:"0",y2:H,stroke:"var(--agd-stroke)",strokeWidth:"1"}),V.jsx("circle",{cx:J*0.3,cy:H*0.3,r:Math.min(J,H)*0.08,fill:"var(--agd-fill)",stroke:"var(--agd-stroke)",strokeWidth:"0.8"})]})})}function NO({width:J,height:H}){let Y=Math.max(2,Math.min(5,Math.floor(J/100))),K=Math.max(2,Math.min(6,Math.floor(H/32)));return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column"},children:[V.jsx("div",{style:{display:"flex",borderBottom:"1px solid var(--agd-stroke)",padding:"6px 0"},children:Array.from({length:Y},(W,O)=>V.jsx("div",{style:{flex:1,padding:"0 8px"},children:V.jsx(X4,{w:"70%",h:3,strong:!0})},O))}),Array.from({length:K},(W,O)=>V.jsx("div",{style:{display:"flex",borderBottom:"1px solid rgba(255,255,255,0.03)",padding:"6px 0"},children:Array.from({length:Y},(A,C)=>V.jsx("div",{style:{flex:1,padding:"0 8px"},children:V.jsx(X4,{w:`${50+(O*7+C*13)%40}%`,h:2})},C))},O))]})}function DO({width:J,height:H}){let Y=Math.max(2,Math.floor(H/28));return V.jsx("div",{style:{display:"flex",flexDirection:"column",gap:4,padding:4},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{display:"flex",alignItems:"center",gap:8,padding:"4px 0"},children:[V.jsx(e2,{size:8}),V.jsx(X4,{w:`${55+W*17%35}%`,h:2})]},W))})}function PO({width:J,height:H,text:Y}){return V.jsx("div",{style:{height:"100%",borderRadius:Math.min(8,H/3),border:"1px solid var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",justifyContent:"center"},children:Y?V.jsx("span",{style:{fontSize:Math.min(13,H*0.4),fontWeight:500,color:"var(--agd-text-3)",letterSpacing:"-0.01em"},children:Y}):V.jsx(X4,{w:Math.max(20,J*0.5),h:3,strong:!0})})}function AO({width:J,height:H}){return V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:4,height:"100%",justifyContent:"center"},children:[V.jsx(X4,{w:Math.min(80,J*0.3),h:2}),V.jsx("div",{style:{height:Math.min(36,H*0.6),borderRadius:4,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",paddingLeft:8},children:V.jsx(X4,{w:"40%",h:2})})]})}function CO({width:J,height:H}){let Y=Math.max(2,Math.min(5,Math.floor(H/56)));return V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:H*0.04,padding:8},children:[Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:4},children:[V.jsx(X4,{w:60+W*17%30,h:2}),V.jsx(XZ,{w:"100%",h:28,radius:4})]},W)),V.jsx(XZ,{w:Math.min(120,J*0.35),h:30,radius:6,style:{marginTop:8,alignSelf:"flex-end",background:"var(--agd-bar)"}})]})}function TO({width:J,height:H}){let Y=Math.max(2,Math.min(4,Math.floor(J/120)));return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column"},children:[V.jsx("div",{style:{display:"flex",gap:2,borderBottom:"1px solid var(--agd-stroke)"},children:Array.from({length:Y},(K,W)=>V.jsx("div",{style:{padding:"8px 12px",borderBottom:W===0?"2px solid var(--agd-bar-strong)":"none"},children:V.jsx(X4,{w:60,h:3,strong:W===0})},W))}),V.jsxs("div",{style:{flex:1,padding:12,display:"flex",flexDirection:"column",gap:6},children:[V.jsx(X4,{w:"80%",h:2}),V.jsx(X4,{w:"65%",h:2}),V.jsx(X4,{w:"75%",h:2})]})]})}function EO({width:J,height:H}){let Y=Math.min(J,H)/2;return V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",children:[V.jsx("circle",{cx:J/2,cy:H/2,r:Y-1,stroke:"var(--agd-stroke)",fill:"var(--agd-fill)",strokeWidth:"1.5",strokeDasharray:"3 2"}),V.jsx("circle",{cx:J/2,cy:H*0.38,r:Y*0.28,stroke:"var(--agd-stroke)",fill:"var(--agd-fill)",strokeWidth:"0.8"}),V.jsx("path",{d:`M${J/2-Y*0.55} ${H*0.78} C${J/2-Y*0.55} ${H*0.55} ${J/2+Y*0.55} ${H*0.55} ${J/2+Y*0.55} ${H*0.78}`,stroke:"var(--agd-stroke)",fill:"var(--agd-fill)",strokeWidth:"0.8"})]})}function wO({width:J,height:H}){return V.jsx("div",{style:{height:"100%",borderRadius:H/2,border:"1px solid var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",justifyContent:"center"},children:V.jsx(X4,{w:Math.max(16,J*0.5),h:2,strong:!0})})}function IO({width:J,height:H}){return V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",gap:H*0.08},children:[V.jsx(X4,{w:J*0.5,h:Math.max(5,H*0.06),strong:!0}),V.jsx(X4,{w:J*0.35})]})}function xO({width:J,height:H}){return V.jsxs("div",{style:{display:"flex",flexDirection:"column",height:"100%",gap:H*0.04,padding:J*0.04},children:[V.jsx(X4,{w:J*0.3,h:4,strong:!0}),V.jsx(X4,{w:J*0.7}),V.jsx(X4,{w:J*0.5}),V.jsxs("div",{style:{flex:1,display:"flex",gap:J*0.03,marginTop:H*0.06},children:[V.jsx(XZ,{w:"33%",h:"100%",radius:4}),V.jsx(XZ,{w:"33%",h:"100%",radius:4}),V.jsx(XZ,{w:"33%",h:"100%",radius:4})]})]})}function SO({width:J,height:H}){let Y=Math.max(2,Math.min(4,Math.floor(J/140))),K=Math.max(1,Math.min(3,Math.floor(H/120)));return V.jsx("div",{style:{display:"grid",gridTemplateColumns:`repeat(${Y}, 1fr)`,gridTemplateRows:`repeat(${K}, 1fr)`,gap:6,height:"100%"},children:Array.from({length:Y*K},(W,O)=>V.jsx(XZ,{w:"100%",h:"100%",radius:4},O))})}function vO({width:J,height:H}){let Y=Math.max(2,Math.floor((H-32)/28));return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column"},children:[V.jsx("div",{style:{padding:"6px 8px",borderBottom:"1px solid var(--agd-stroke)"},children:V.jsx(X4,{w:J*0.5,h:3,strong:!0})}),V.jsx("div",{style:{flex:1,padding:4,display:"flex",flexDirection:"column",gap:2},children:Array.from({length:Y},(K,W)=>V.jsx("div",{style:{padding:"4px 6px",borderRadius:3,background:W===0?"var(--agd-fill)":"transparent"},children:V.jsx(X4,{w:`${50+W*17%35}%`,h:2,strong:W===0})},W))})]})}function kO({width:J,height:H}){let Y=Math.min(J,H)/2;return V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",children:[V.jsx("rect",{x:"1",y:"1",width:J-2,height:H-2,rx:Y,stroke:"var(--agd-stroke)",strokeWidth:"1"}),V.jsx("circle",{cx:J-Y,cy:H/2,r:Y*0.7,fill:"var(--agd-bar)"})]})}function yO({width:J,height:H}){let Y=Math.min(H/2,20);return V.jsxs("div",{style:{height:"100%",borderRadius:Y,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",padding:`0 ${Y*0.6}px`,gap:6},children:[V.jsx(e2,{size:Math.min(14,H*0.4)}),V.jsx(X4,{w:"50%",h:2})]})}function gO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",borderRadius:8,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",padding:"0 10px",gap:8},children:[V.jsx(e2,{size:Math.min(20,H*0.5)}),V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:"60%",h:3,strong:!0}),V.jsx(X4,{w:"80%",h:2})]}),V.jsx("div",{style:{width:14,height:14,border:"1px solid var(--agd-stroke)",borderRadius:3,flexShrink:0}})]})}function bO({width:J,height:H}){return V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",children:[V.jsx("rect",{x:"0",y:"0",width:J,height:H,rx:H/2,stroke:"var(--agd-stroke)",strokeWidth:"0.8"}),V.jsx("rect",{x:"1",y:"1",width:J*0.65,height:H-2,rx:(H-2)/2,fill:"var(--agd-bar)"})]})}function fO({width:J,height:H}){let Y=Math.max(3,Math.min(7,Math.floor(J/50))),K=J/(Y*2);return V.jsx("div",{style:{height:"100%",display:"flex",alignItems:"flex-end",justifyContent:"space-around",padding:"0 4px",borderBottom:"1px solid var(--agd-stroke)"},children:Array.from({length:Y},(W,O)=>{let A=30+(O*37+17)%55;return V.jsx(XZ,{w:K,h:`${A}%`,radius:2},O)})})}function mO({width:J,height:H}){let Y=Math.min(J,H)*0.12;return V.jsxs("div",{style:{height:"100%",position:"relative",display:"flex",alignItems:"center",justifyContent:"center"},children:[V.jsx(XZ,{w:"100%",h:"100%",radius:4}),V.jsx("div",{style:{position:"absolute",width:Y*2,height:Y*2,borderRadius:"50%",border:"1.5px solid var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",justifyContent:"center"},children:V.jsx("div",{style:{width:0,height:0,borderLeft:`${Y*0.6}px solid var(--agd-bar-strong)`,borderTop:`${Y*0.4}px solid transparent`,borderBottom:`${Y*0.4}px solid transparent`,marginLeft:Y*0.15}})})]})}function hO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",alignItems:"center"},children:[V.jsx("div",{style:{flex:1,width:"100%",borderRadius:6,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",justifyContent:"center"},children:V.jsx(X4,{w:"60%",h:2})}),V.jsx("div",{style:{width:8,height:8,background:"var(--agd-fill)",border:"1px dashed var(--agd-stroke)",borderTop:"none",borderLeft:"none",transform:"rotate(45deg)",marginTop:-5}})]})}function uO({width:J,height:H}){let Y=Math.max(2,Math.min(4,Math.floor(J/80)));return V.jsx("div",{style:{display:"flex",alignItems:"center",height:"100%",gap:4},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{display:"flex",alignItems:"center",gap:4},children:[W>0&&V.jsx("span",{style:{color:"var(--agd-stroke)",fontSize:10},children:"/"}),V.jsx(X4,{w:40+W*13%20,h:2,strong:W===Y-1})]},W))})}function dO({width:J,height:H}){let Y=Math.max(3,Math.min(5,Math.floor(J/40))),K=Math.min(28,H*0.8);return V.jsx("div",{style:{display:"flex",alignItems:"center",justifyContent:"center",height:"100%",gap:4},children:Array.from({length:Y},(W,O)=>V.jsx(XZ,{w:K,h:K,radius:4,style:O===1?{background:"var(--agd-bar)"}:void 0},O))})}function pO({width:J}){return V.jsx("div",{style:{display:"flex",alignItems:"center",height:"100%"},children:V.jsx("div",{style:{width:"100%",height:1,background:"var(--agd-stroke)"}})})}function cO({width:J,height:H}){let Y=Math.max(2,Math.min(4,Math.floor(H/40)));return V.jsx("div",{style:{display:"flex",flexDirection:"column",height:"100%"},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{borderBottom:"1px solid var(--agd-stroke)",padding:"8px 6px",display:"flex",alignItems:"center",justifyContent:"space-between",flex:W===0?2:1},children:[V.jsx(X4,{w:`${40+W*17%25}%`,h:3,strong:!0}),V.jsx("span",{style:{fontSize:8,color:"var(--agd-stroke)"},children:W===0?"▼":"▶"})]},W))})}function lO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",gap:6},children:[V.jsxs("div",{style:{flex:1,display:"flex",gap:6,alignItems:"center"},children:[V.jsx("span",{style:{fontSize:12,color:"var(--agd-stroke)"},children:"‹"}),V.jsx(XZ,{w:"100%",h:"100%",radius:4}),V.jsx("span",{style:{fontSize:12,color:"var(--agd-stroke)"},children:"›"})]}),V.jsxs("div",{style:{display:"flex",justifyContent:"center",gap:4},children:[V.jsx(e2,{size:5}),V.jsx(e2,{size:5}),V.jsx(e2,{size:5})]})]})}function sO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",alignItems:"center",padding:10,gap:H*0.04},children:[V.jsx(X4,{w:J*0.4,h:3,strong:!0}),V.jsx(X4,{w:J*0.3,h:6,strong:!0}),V.jsx("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:4,width:"100%",padding:"8px 0"},children:Array.from({length:4},(Y,K)=>V.jsxs("div",{style:{display:"flex",alignItems:"center",gap:4},children:[V.jsx(e2,{size:5}),V.jsx(X4,{w:`${50+K*17%35}%`,h:2})]},K))}),V.jsx(XZ,{w:J*0.7,h:Math.min(32,H*0.1),radius:6,style:{background:"var(--agd-bar)"}})]})}function aO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",padding:10,gap:8},children:[V.jsx("span",{style:{fontSize:18,lineHeight:1,color:"var(--agd-stroke)",fontFamily:"serif"},children:"“"}),V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:4},children:[V.jsx(X4,{w:"90%",h:2}),V.jsx(X4,{w:"75%",h:2}),V.jsx(X4,{w:"60%",h:2})]}),V.jsxs("div",{style:{display:"flex",alignItems:"center",gap:6},children:[V.jsx(e2,{size:20}),V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:2},children:[V.jsx(X4,{w:60,h:3,strong:!0}),V.jsx(X4,{w:40,h:2})]})]})]})}function iO({width:J,height:H}){return V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",gap:H*0.08},children:[V.jsx(X4,{w:J*0.5,h:Math.max(4,H*0.05),strong:!0}),V.jsx(X4,{w:J*0.35}),V.jsx(XZ,{w:Math.min(140,J*0.25),h:Math.min(32,H*0.15),radius:6,style:{marginTop:H*0.04,background:"var(--agd-bar)"}})]})}function oO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",borderRadius:6,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",padding:"0 10px",gap:8},children:[V.jsx("div",{style:{width:16,height:16,borderRadius:"50%",border:"1.5px solid var(--agd-bar-strong)",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0},children:V.jsx("div",{style:{width:2,height:6,background:"var(--agd-bar-strong)",borderRadius:1}})}),V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:"40%",h:3,strong:!0}),V.jsx(X4,{w:"70%",h:2})]})]})}function rO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",background:"var(--agd-fill)",display:"flex",alignItems:"center",justifyContent:"center",gap:8,padding:"0 12px"},children:[V.jsx(X4,{w:J*0.4,h:3,strong:!0}),V.jsx(XZ,{w:60,h:Math.min(24,H*0.6),radius:4})]})}function nO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:H*0.06},children:[V.jsx(X4,{w:J*0.5,h:2}),V.jsx(X4,{w:J*0.4,h:Math.max(8,H*0.18),strong:!0}),V.jsx(X4,{w:J*0.3,h:2})]})}function tO({width:J,height:H}){let Y=Math.max(3,Math.min(5,Math.floor(J/100))),K=Math.min(12,H*0.35);return V.jsx("div",{style:{display:"flex",alignItems:"center",justifyContent:"space-between",height:"100%",padding:"0 8px"},children:Array.from({length:Y},(W,O)=>V.jsxs("div",{style:{display:"flex",alignItems:"center",gap:0,flex:1},children:[V.jsx("div",{style:{width:K,height:K,borderRadius:"50%",border:"1.5px solid var(--agd-stroke)",background:O===0?"var(--agd-bar)":"transparent",flexShrink:0}}),O<Y-1&&V.jsx("div",{style:{flex:1,height:1,background:"var(--agd-stroke)",margin:"0 4px"}})]},O))})}function eO({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",borderRadius:4,border:"1px solid var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",justifyContent:"center",gap:4,padding:"0 6px"},children:[V.jsx(X4,{w:Math.max(16,J*0.5),h:2,strong:!0}),V.jsx("div",{style:{width:8,height:8,borderRadius:"50%",border:"1px solid var(--agd-stroke)",flexShrink:0}})]})}function ZF({width:J,height:H}){let K=Math.min(H*0.7,J/7.5);return V.jsx("div",{style:{display:"flex",alignItems:"center",justifyContent:"center",height:"100%",gap:K*0.2},children:Array.from({length:5},(W,O)=>V.jsx("svg",{width:K,height:K,viewBox:"0 0 16 16",fill:"none",children:V.jsx("path",{d:"M8 1.5l2 4 4.5.7-3.25 3.1.75 4.5L8 11.4l-4 2.4.75-4.5L1.5 6.2 6 5.5z",stroke:"var(--agd-stroke)",strokeWidth:"0.8",fill:O<3?"var(--agd-bar)":"none"})},O))})}function GF({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",position:"relative",borderRadius:4,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",overflow:"hidden"},children:[V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",style:{position:"absolute",inset:0},children:[V.jsx("line",{x1:0,y1:H*0.3,x2:J,y2:H*0.7,stroke:"var(--agd-stroke)",strokeWidth:"0.5",opacity:".2"}),V.jsx("line",{x1:0,y1:H*0.6,x2:J,y2:H*0.2,stroke:"var(--agd-stroke)",strokeWidth:"0.5",opacity:".15"}),V.jsx("line",{x1:J*0.4,y1:0,x2:J*0.6,y2:H,stroke:"var(--agd-stroke)",strokeWidth:"0.5",opacity:".15"})]}),V.jsx("div",{style:{position:"absolute",left:"50%",top:"40%",transform:"translate(-50%, -100%)"},children:V.jsxs("svg",{width:"16",height:"22",viewBox:"0 0 16 22",fill:"none",children:[V.jsx("path",{d:"M8 0C3.6 0 0 3.6 0 8c0 6 8 14 8 14s8-8 8-14c0-4.4-3.6-8-8-8z",fill:"var(--agd-bar)",opacity:".4"}),V.jsx("circle",{cx:"8",cy:"8",r:"3",fill:"var(--agd-fill)"})]})})]})}function BF({width:J,height:H}){let Y=Math.max(3,Math.min(5,Math.floor(H/60)));return V.jsxs("div",{style:{display:"flex",height:"100%",padding:"8px 0"},children:[V.jsx("div",{style:{width:16,display:"flex",flexDirection:"column",alignItems:"center"},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",flex:1},children:[V.jsx(e2,{size:8}),W<Y-1&&V.jsx("div",{style:{flex:1,width:1,background:"var(--agd-stroke)"}})]},W))}),V.jsx("div",{style:{flex:1,display:"flex",flexDirection:"column",justifyContent:"space-around",paddingLeft:8},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:`${35+W*13%25}%`,h:3,strong:!0}),V.jsx(X4,{w:`${50+W*17%30}%`,h:2})]},W))})]})}function $F({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",borderRadius:8,border:"2px dashed var(--agd-stroke)",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:H*0.06},children:[V.jsxs("svg",{width:"24",height:"24",viewBox:"0 0 24 24",fill:"none",children:[V.jsx("path",{d:"M12 16V4m0 0l-4 4m4-4l4 4",stroke:"var(--agd-stroke)",strokeWidth:"1.5"}),V.jsx("path",{d:"M4 17v2a1 1 0 001 1h14a1 1 0 001-1v-2",stroke:"var(--agd-stroke)",strokeWidth:"1.5"})]}),V.jsx(X4,{w:J*0.4,h:2}),V.jsx(X4,{w:J*0.25,h:2})]})}function zF({width:J,height:H}){let Y=Math.max(3,Math.min(8,Math.floor(H/20)));return V.jsxs("div",{style:{height:"100%",borderRadius:6,background:"var(--agd-fill)",border:"1px solid var(--agd-stroke)",padding:8,display:"flex",flexDirection:"column",gap:4},children:[V.jsxs("div",{style:{display:"flex",gap:3,marginBottom:4},children:[V.jsx(e2,{size:6}),V.jsx(e2,{size:6}),V.jsx(e2,{size:6})]}),Array.from({length:Y},(K,W)=>V.jsx("div",{style:{display:"flex",gap:6,paddingLeft:W>0&&W<Y-1?12:0},children:V.jsx(X4,{w:`${25+W*23%50}%`,h:2,strong:W===0})},W))]})}function QF({width:J,height:H}){let W=Math.min((J-16)/7,(H-40)/6);return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column"},children:[V.jsxs("div",{style:{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"6px 8px"},children:[V.jsx("span",{style:{fontSize:8,color:"var(--agd-stroke)"},children:"‹"}),V.jsx(X4,{w:J*0.3,h:3,strong:!0}),V.jsx("span",{style:{fontSize:8,color:"var(--agd-stroke)"},children:"›"})]}),V.jsxs("div",{style:{display:"grid",gridTemplateColumns:"repeat(7, 1fr)",gap:2,padding:"0 4px",flex:1},children:[Array.from({length:7},(O,A)=>V.jsx("div",{style:{display:"flex",alignItems:"center",justifyContent:"center",height:W*0.6},children:V.jsx(X4,{w:W*0.5,h:2})},`h${A}`)),Array.from({length:35},(O,A)=>V.jsx("div",{style:{display:"flex",alignItems:"center",justifyContent:"center",height:W},children:V.jsx("div",{style:{width:W*0.6,height:W*0.6,borderRadius:"50%",background:A===12?"var(--agd-bar)":"transparent",display:"flex",alignItems:"center",justifyContent:"center"},children:V.jsx("div",{style:{width:2,height:2,borderRadius:1,background:"var(--agd-bar-strong)",opacity:A===12?1:0.3}})})},A))]})]})}function JF({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",borderRadius:8,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",padding:"0 10px",gap:8},children:[V.jsx(e2,{size:Math.min(32,H*0.55)}),V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:"50%",h:3,strong:!0}),V.jsx(X4,{w:"75%",h:2})]}),V.jsx(X4,{w:30,h:2})]})}function qF({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column"},children:[V.jsx("div",{style:{height:"50%",background:"var(--agd-fill)",borderBottom:"1px dashed var(--agd-stroke)"}}),V.jsxs("div",{style:{flex:1,padding:10,display:"flex",flexDirection:"column",gap:5},children:[V.jsx(X4,{w:"65%",h:4,strong:!0}),V.jsx(X4,{w:"40%",h:3}),V.jsx("div",{style:{flex:1}}),V.jsxs("div",{style:{display:"flex",alignItems:"center",justifyContent:"space-between"},children:[V.jsx(X4,{w:"30%",h:5,strong:!0}),V.jsx(XZ,{w:Math.min(70,J*0.3),h:26,radius:4,style:{background:"var(--agd-bar)"}})]})]})]})}function HF({width:J,height:H}){let Y=Math.min(48,H*0.3);return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:H*0.06},children:[V.jsx(e2,{size:Y}),V.jsx(X4,{w:J*0.45,h:4,strong:!0}),V.jsx(X4,{w:J*0.3,h:2}),V.jsxs("div",{style:{display:"flex",gap:J*0.08,marginTop:H*0.04},children:[V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",gap:2},children:[V.jsx(X4,{w:20,h:3,strong:!0}),V.jsx(X4,{w:28,h:2})]}),V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",gap:2},children:[V.jsx(X4,{w:20,h:3,strong:!0}),V.jsx(X4,{w:28,h:2})]}),V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",gap:2},children:[V.jsx(X4,{w:20,h:3,strong:!0}),V.jsx(X4,{w:28,h:2})]})]})]})}function XF({width:J,height:H}){let Y=Math.max(J*0.6,80),K=Math.max(3,Math.floor(H/40));return V.jsxs("div",{style:{height:"100%",display:"flex"},children:[V.jsx("div",{style:{width:J-Y,background:"var(--agd-fill)",opacity:0.3}}),V.jsxs("div",{style:{flex:1,borderLeft:"1px solid var(--agd-stroke)",display:"flex",flexDirection:"column",padding:J*0.04},children:[V.jsxs("div",{style:{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:H*0.06},children:[V.jsx(X4,{w:Y*0.4,h:4,strong:!0}),V.jsx("div",{style:{width:12,height:12,border:"1px solid var(--agd-stroke)",borderRadius:3}})]}),Array.from({length:K},(W,O)=>V.jsx("div",{style:{padding:"6px 0"},children:V.jsx(X4,{w:`${50+O*17%35}%`,h:2,strong:O===0})},O))]})]})}function YF({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",alignItems:"center"},children:[V.jsxs("div",{style:{flex:1,width:"100%",borderRadius:8,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",padding:10,display:"flex",flexDirection:"column",gap:5},children:[V.jsx(X4,{w:"70%",h:3,strong:!0}),V.jsx(X4,{w:"90%",h:2}),V.jsx(X4,{w:"60%",h:2})]}),V.jsx("div",{style:{width:10,height:10,background:"var(--agd-fill)",border:"1px dashed var(--agd-stroke)",borderTop:"none",borderLeft:"none",transform:"rotate(45deg)",marginTop:-6}})]})}function jF({width:J,height:H}){let Y=Math.min(H*0.7,J*0.3);return V.jsxs("div",{style:{height:"100%",display:"flex",alignItems:"center",gap:J*0.08},children:[V.jsx(XZ,{w:Y,h:Y,radius:Y*0.25}),V.jsx(X4,{w:J*0.45,h:Math.max(4,H*0.2),strong:!0})]})}function KF({width:J,height:H}){let Y=Math.max(2,Math.min(5,Math.floor(H/56)));return V.jsx("div",{style:{display:"flex",flexDirection:"column",height:"100%"},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{borderBottom:"1px solid var(--agd-stroke)",padding:"8px 6px",display:"flex",alignItems:"center",justifyContent:"space-between",flex:W===0?2:1},children:[V.jsxs("div",{style:{display:"flex",alignItems:"center",gap:6},children:[V.jsx("span",{style:{fontSize:9,fontWeight:700,color:"var(--agd-stroke)"},children:"Q"}),V.jsx(X4,{w:J*(0.3+W*13%25/100),h:3,strong:!0})]}),V.jsx("span",{style:{fontSize:8,color:"var(--agd-stroke)"},children:W===0?"▼":"▶"})]},W))})}function WF({width:J,height:H}){let Y=Math.max(2,Math.min(4,Math.floor(J/120))),K=Math.max(1,Math.min(3,Math.floor(H/120)));return V.jsx("div",{style:{display:"grid",gridTemplateColumns:`repeat(${Y}, 1fr)`,gridTemplateRows:`repeat(${K}, 1fr)`,gap:4,height:"100%"},children:Array.from({length:Y*K},(W,O)=>V.jsx("div",{style:{borderRadius:4,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",position:"relative",overflow:"hidden"},children:V.jsxs("svg",{width:"100%",height:"100%",viewBox:"0 0 100 100",preserveAspectRatio:"none",fill:"none",children:[V.jsx("line",{x1:"0",y1:"0",x2:"100",y2:"100",stroke:"var(--agd-stroke)",strokeWidth:"0.5"}),V.jsx("line",{x1:"100",y1:"0",x2:"0",y2:"100",stroke:"var(--agd-stroke)",strokeWidth:"0.5"})]})},O))})}function _F({width:J,height:H}){let Y=Math.min(J,H);return V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",children:[V.jsx("rect",{x:"1",y:(H-Y+2)/2,width:Y-2,height:Y-2,rx:Y*0.15,stroke:"var(--agd-stroke)",strokeWidth:"1.5"}),V.jsx("path",{d:`M${Y*0.25} ${H/2}l${Y*0.2} ${Y*0.2} ${Y*0.3}-${Y*0.35}`,stroke:"var(--agd-bar)",strokeWidth:"1.5",fill:"none",strokeLinecap:"round",strokeLinejoin:"round"})]})}function LF({width:J,height:H}){let Y=Math.min(J,H)/2-1;return V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",children:[V.jsx("circle",{cx:J/2,cy:H/2,r:Y,stroke:"var(--agd-stroke)",strokeWidth:"1.5"}),V.jsx("circle",{cx:J/2,cy:H/2,r:Y*0.45,fill:"var(--agd-bar)"})]})}function UF({width:J,height:H}){let Y=Math.max(2,H*0.12),K=Math.min(H*0.35,10),W=J*0.55;return V.jsxs("div",{style:{height:"100%",display:"flex",alignItems:"center",position:"relative"},children:[V.jsx("div",{style:{width:"100%",height:Y,borderRadius:Y/2,background:"var(--agd-fill)",border:"1px solid var(--agd-stroke)",position:"relative"},children:V.jsx("div",{style:{width:W,height:"100%",borderRadius:Y/2,background:"var(--agd-bar)"}})}),V.jsx("div",{style:{position:"absolute",left:W-K,width:K*2,height:K*2,borderRadius:"50%",border:"1.5px solid var(--agd-stroke)",background:"var(--agd-fill)"}})]})}function VF({width:J,height:H}){let Y=Math.min(36,H*0.15),K=7,W=4,O=Math.min((J-16)/7,(H-Y-40)/5);return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",gap:4},children:[V.jsxs("div",{style:{height:Y,borderRadius:4,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",padding:"0 8px",justifyContent:"space-between"},children:[V.jsx(X4,{w:"40%",h:2}),V.jsxs("svg",{width:"12",height:"12",viewBox:"0 0 16 16",fill:"none",children:[V.jsx("rect",{x:"2",y:"3",width:"12",height:"11",rx:"1",stroke:"var(--agd-stroke)",strokeWidth:"1"}),V.jsx("line",{x1:"2",y1:"6",x2:"14",y2:"6",stroke:"var(--agd-stroke)",strokeWidth:"0.5"})]})]}),V.jsxs("div",{style:{flex:1,borderRadius:6,border:"1px dashed var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",flexDirection:"column"},children:[V.jsxs("div",{style:{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"4px 6px"},children:[V.jsx("span",{style:{fontSize:7,color:"var(--agd-stroke)"},children:"‹"}),V.jsx(X4,{w:J*0.25,h:2,strong:!0}),V.jsx("span",{style:{fontSize:7,color:"var(--agd-stroke)"},children:"›"})]}),V.jsx("div",{style:{display:"grid",gridTemplateColumns:"repeat(7, 1fr)",gap:1,padding:"0 4px",flex:1},children:Array.from({length:28},(A,C)=>V.jsx("div",{style:{display:"flex",alignItems:"center",justifyContent:"center",height:O},children:V.jsx("div",{style:{width:O*0.5,height:O*0.5,borderRadius:"50%",background:C===10?"var(--agd-bar)":"transparent"},children:V.jsx("div",{style:{width:"100%",height:"100%",display:"flex",alignItems:"center",justifyContent:"center"},children:V.jsx("div",{style:{width:1.5,height:1.5,borderRadius:1,background:"var(--agd-bar-strong)",opacity:C===10?1:0.25}})})})},C))})]})]})}function OF({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",gap:H*0.08,padding:4},children:[V.jsx("div",{style:{width:"100%",height:H*0.2,borderRadius:4,background:"var(--agd-fill)"}}),V.jsx("div",{style:{width:"70%",height:Math.max(6,H*0.1),borderRadius:3,background:"var(--agd-fill)"}}),V.jsx("div",{style:{width:"90%",height:Math.max(4,H*0.06),borderRadius:3,background:"var(--agd-fill)"}}),V.jsx("div",{style:{width:"50%",height:Math.max(4,H*0.06),borderRadius:3,background:"var(--agd-fill)"}})]})}function FF({width:J,height:H}){return V.jsx("div",{style:{height:"100%",display:"flex",alignItems:"center",gap:6},children:V.jsxs("div",{style:{height:"100%",flex:1,borderRadius:H/2,border:"1px solid var(--agd-stroke)",background:"var(--agd-fill)",display:"flex",alignItems:"center",padding:`0 ${H*0.3}px`,gap:4},children:[V.jsx(X4,{w:"60%",h:2,strong:!0}),V.jsx("div",{style:{width:Math.max(6,H*0.3),height:Math.max(6,H*0.3),borderRadius:"50%",border:"1px solid var(--agd-stroke)",flexShrink:0,marginLeft:"auto"}})]})})}function RF({width:J,height:H}){let Y=Math.min(J,H);return V.jsx("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",children:V.jsx("path",{d:`M${J/2} ${(H-Y)/2+Y*0.1}l${Y*0.12} ${Y*0.25} ${Y*0.28} ${Y*0.04}-${Y*0.2} ${Y*0.2} ${Y*0.05} ${Y*0.28}-${Y*0.25}-${Y*0.12}-${Y*0.25} ${Y*0.12} ${Y*0.05}-${Y*0.28}-${Y*0.2}-${Y*0.2} ${Y*0.28}-${Y*0.04}z`,stroke:"var(--agd-stroke)",strokeWidth:"1",fill:"var(--agd-fill)"})})}function MF({width:J,height:H}){let Y=Math.min(J,H)/2-2;return V.jsxs("svg",{width:"100%",height:"100%",viewBox:`0 0 ${J} ${H}`,fill:"none",children:[V.jsx("circle",{cx:J/2,cy:H/2,r:Y,stroke:"var(--agd-stroke)",strokeWidth:"1.5",opacity:".2"}),V.jsx("path",{d:`M${J/2} ${H/2-Y}a${Y} ${Y} 0 0 1 ${Y} ${Y}`,stroke:"var(--agd-bar-strong)",strokeWidth:"1.5",strokeLinecap:"round"})]})}function NF({width:J,height:H}){let Y=Math.min(36,H*0.25,J*0.12),K=Math.max(1,Math.min(3,Math.floor(H/80)));return V.jsx("div",{style:{display:"flex",flexDirection:"column",height:"100%",justifyContent:"space-around",padding:8},children:Array.from({length:K},(W,O)=>V.jsxs("div",{style:{display:"flex",gap:J*0.04,alignItems:"flex-start"},children:[V.jsx(XZ,{w:Y,h:Y,radius:Y*0.25}),V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:4},children:[V.jsx(X4,{w:`${40+O*13%20}%`,h:3,strong:!0}),V.jsx(X4,{w:`${60+O*17%25}%`,h:2})]})]},O))})}function DF({width:J,height:H}){let Y=Math.max(2,Math.min(4,Math.floor(J/120))),K=Math.min(36,H*0.25);return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",alignItems:"center",gap:H*0.06,padding:H*0.06},children:[V.jsx(X4,{w:J*0.3,h:4,strong:!0}),V.jsx("div",{style:{display:"flex",gap:J*0.06,justifyContent:"center",flex:1,alignItems:"center"},children:Array.from({length:Y},(W,O)=>V.jsxs("div",{style:{display:"flex",flexDirection:"column",alignItems:"center",gap:6},children:[V.jsx(e2,{size:K}),V.jsx(X4,{w:J*0.12,h:3,strong:!0}),V.jsx(X4,{w:J*0.08,h:2})]},O))})]})}function PF({width:J,height:H}){let Y=Math.max(2,Math.min(3,Math.floor(H/80)));return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",alignItems:"center",padding:J*0.06,gap:H*0.04},children:[V.jsx(X4,{w:J*0.5,h:Math.max(5,H*0.04),strong:!0}),V.jsx(X4,{w:J*0.35,h:2}),V.jsx("div",{style:{width:"100%",display:"flex",flexDirection:"column",gap:H*0.03,marginTop:H*0.04},children:Array.from({length:Y},(K,W)=>V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:Math.min(60,J*0.2),h:2}),V.jsx(XZ,{w:"100%",h:Math.min(32,H*0.1),radius:4})]},W))}),V.jsx(XZ,{w:"100%",h:Math.min(36,H*0.12),radius:6,style:{marginTop:H*0.03,background:"var(--agd-bar)"}}),V.jsx(X4,{w:J*0.4,h:2})]})}function AF({width:J,height:H}){return V.jsxs("div",{style:{height:"100%",display:"flex",flexDirection:"column",padding:J*0.04,gap:H*0.03},children:[V.jsx(X4,{w:J*0.4,h:4,strong:!0}),V.jsx(X4,{w:J*0.6,h:2}),V.jsxs("div",{style:{display:"flex",gap:6,marginTop:H*0.03},children:[V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:50,h:2}),V.jsx(XZ,{w:"100%",h:Math.min(28,H*0.1),radius:4})]}),V.jsxs("div",{style:{flex:1,display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:40,h:2}),V.jsx(XZ,{w:"100%",h:Math.min(28,H*0.1),radius:4})]})]}),V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:3},children:[V.jsx(X4,{w:50,h:2}),V.jsx(XZ,{w:"100%",h:Math.min(28,H*0.1),radius:4})]}),V.jsxs("div",{style:{display:"flex",flexDirection:"column",gap:3,flex:1},children:[V.jsx(X4,{w:60,h:2}),V.jsx(XZ,{w:"100%",h:"100%",radius:4})]}),V.jsx(XZ,{w:Math.min(120,J*0.3),h:Math.min(30,H*0.1),radius:6,style:{alignSelf:"flex-end",background:"var(--agd-bar)"}})]})}var CF={navigation:_O,hero:LO,sidebar:UO,footer:VO,modal:OO,card:FO,text:RO,image:MO,table:NO,list:DO,button:PO,input:AO,form:CO,tabs:TO,avatar:EO,badge:wO,header:IO,section:xO,grid:SO,dropdown:vO,toggle:kO,search:yO,toast:gO,progress:bO,chart:fO,video:mO,tooltip:hO,breadcrumb:uO,pagination:dO,divider:pO,accordion:cO,carousel:lO,pricing:sO,testimonial:aO,cta:iO,alert:oO,banner:rO,stat:nO,stepper:tO,tag:eO,rating:ZF,map:GF,timeline:BF,fileUpload:$F,codeBlock:zF,calendar:QF,notification:JF,productCard:qF,profile:HF,drawer:XF,popover:YF,logo:jF,faq:KF,gallery:WF,checkbox:_F,radio:LF,slider:UF,datePicker:VF,skeleton:OF,chip:FF,icon:RF,spinner:MF,feature:NF,team:DF,login:PF,contact:AF};function TF({type:J,width:H,height:Y,text:K}){let W=CF[J];if(!W)return V.jsx("div",{style:{width:"100%",height:"100%",display:"flex",alignItems:"center",justifyContent:"center"},children:V.jsx("span",{style:{fontSize:10,fontWeight:600,color:"var(--agd-text-3)",textTransform:"uppercase",letterSpacing:"0.06em",opacity:0.5},children:J})});return V.jsx("div",{style:{width:"100%",height:"100%",padding:8,position:"relative",pointerEvents:"none"},children:V.jsx(W,{width:H,height:Y,text:K})})}var EF=`svg[fill=none] {
  fill: none !important;
}

.styles-module__overlayExiting___iEmYr {
  opacity: 0 !important;
  transition: opacity 0.25s ease !important;
  pointer-events: none !important;
}

.styles-module__overlay___aWh-q {
  position: fixed;
  inset: 0;
  z-index: 99995;
  pointer-events: auto;
  cursor: default;
  animation: styles-module__overlayFadeIn___aECVy 0.15s ease;
  --agd-stroke: rgba(59, 130, 246, 0.35);
  --agd-fill: rgba(59, 130, 246, 0.06);
  --agd-bar: rgba(59, 130, 246, 0.18);
  --agd-bar-strong: rgba(59, 130, 246, 0.28);
  --agd-text-3: rgba(255, 255, 255, 0.6);
  --agd-surface: #fff;
}
.styles-module__overlay___aWh-q.styles-module__light___ORIft {
  --agd-surface: #fff;
}
.styles-module__overlay___aWh-q:not(.styles-module__light___ORIft) {
  --agd-surface: #141414;
}
.styles-module__overlay___aWh-q.styles-module__wireframe___itvQU {
  --agd-stroke: rgba(249, 115, 22, 0.35);
  --agd-fill: rgba(249, 115, 22, 0.06);
  --agd-bar: rgba(249, 115, 22, 0.18);
  --agd-bar-strong: rgba(249, 115, 22, 0.28);
}
.styles-module__overlay___aWh-q.styles-module__placing___45yD8 {
  cursor: crosshair;
}
.styles-module__overlay___aWh-q.styles-module__passthrough___xaFeE {
  pointer-events: none;
}

.styles-module__blankCanvas___t2Eue {
  position: fixed;
  inset: 0;
  z-index: 99994;
  background: #fff;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.25s ease;
}
.styles-module__blankCanvas___t2Eue.styles-module__visible___OKKqX {
  opacity: var(--canvas-opacity, 1);
  pointer-events: auto;
}
.styles-module__blankCanvas___t2Eue::after {
  content: "";
  position: absolute;
  inset: 0;
  background-image: radial-gradient(circle, rgba(0, 0, 0, 0.08) 1px, transparent 1px);
  background-size: 24px 24px;
  background-position: 12px 12px;
  pointer-events: none;
  transition: opacity 0.2s ease;
}
.styles-module__blankCanvas___t2Eue.styles-module__gridActive___OZ-cf::after {
  opacity: 1;
  background-image: radial-gradient(circle, rgba(0, 0, 0, 0.22) 1px, transparent 1px);
}

.styles-module__paletteHeader___-Q5gQ {
  padding: 0 1rem 0.375rem;
}

.styles-module__paletteHeaderTitle___oHqZC {
  font-size: 0.8125rem;
  font-weight: 500;
  color: #fff;
  letter-spacing: -0.0094em;
}
.styles-module__light___ORIft .styles-module__paletteHeaderTitle___oHqZC {
  color: rgba(0, 0, 0, 0.85);
}

.styles-module__paletteHeaderDesc___6i74T {
  font-size: 0.6875rem;
  font-weight: 300;
  color: rgba(255, 255, 255, 0.45);
  margin-top: 2px;
  line-height: 14px;
}
.styles-module__light___ORIft .styles-module__paletteHeaderDesc___6i74T {
  color: rgba(0, 0, 0, 0.45);
}
.styles-module__paletteHeaderDesc___6i74T a {
  color: rgba(255, 255, 255, 0.8);
  text-decoration: underline dotted;
  text-decoration-color: rgba(255, 255, 255, 0.2);
  text-underline-offset: 2px;
  transition: color 0.15s ease;
}
.styles-module__paletteHeaderDesc___6i74T a:hover {
  color: #fff;
}
.styles-module__light___ORIft .styles-module__paletteHeaderDesc___6i74T a {
  color: rgba(0, 0, 0, 0.6);
  text-decoration-color: rgba(0, 0, 0, 0.2);
}
.styles-module__light___ORIft .styles-module__paletteHeaderDesc___6i74T a:hover {
  color: rgba(0, 0, 0, 0.85);
}

.styles-module__wireframePurposeWrap___To-tS {
  display: grid;
  grid-template-rows: 1fr;
  transition: grid-template-rows 0.2s ease, opacity 0.15s ease;
  opacity: 1;
}
.styles-module__wireframePurposeWrap___To-tS.styles-module__collapsed___Ms9vS {
  grid-template-rows: 0fr;
  opacity: 0;
}

.styles-module__wireframePurposeInner___Lrahs {
  overflow: hidden;
}

.styles-module__wireframePurposeInput___7EtBN {
  display: block;
  width: calc(100% - 2rem);
  margin: 0.25rem 1rem 0.375rem;
  padding: 0.375rem 0.5rem;
  font-size: 0.8125rem;
  font-family: inherit;
  color: rgba(255, 255, 255, 0.85);
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 0.375rem;
  resize: none;
  outline: none;
  transition: border-color 0.15s ease;
  letter-spacing: -0.0094em;
}
.styles-module__wireframePurposeInput___7EtBN::placeholder {
  color: rgba(255, 255, 255, 0.3);
}
.styles-module__wireframePurposeInput___7EtBN:focus {
  border-color: rgba(255, 255, 255, 0.3);
  background: rgba(255, 255, 255, 0.05);
}
.styles-module__light___ORIft .styles-module__wireframePurposeInput___7EtBN {
  color: rgba(0, 0, 0, 0.7);
  background: rgba(0, 0, 0, 0.03);
  border-color: rgba(0, 0, 0, 0.1);
}
.styles-module__light___ORIft .styles-module__wireframePurposeInput___7EtBN::placeholder {
  color: rgba(0, 0, 0, 0.3);
}
.styles-module__light___ORIft .styles-module__wireframePurposeInput___7EtBN:focus {
  border-color: rgba(0, 0, 0, 0.25);
  background: rgba(0, 0, 0, 0.05);
}

.styles-module__canvasToggle___-QqSy {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.375rem;
  margin: 0.25rem 1rem 0.25rem;
  padding: 0.375rem 0.5rem;
  border-radius: 0.5rem;
  cursor: pointer;
  border: 1px dashed rgba(255, 255, 255, 0.1);
  background: transparent;
  transition: background 0.15s ease, border-color 0.15s ease;
}
.styles-module__canvasToggle___-QqSy:hover {
  background: rgba(255, 255, 255, 0.04);
  border-color: rgba(255, 255, 255, 0.15);
}
.styles-module__canvasToggle___-QqSy.styles-module__active___hosp7 {
  background: #f97316;
  border-color: transparent;
  border-style: solid;
  box-shadow: none;
}
.styles-module__light___ORIft .styles-module__canvasToggle___-QqSy {
  border-color: rgba(0, 0, 0, 0.08);
}
.styles-module__light___ORIft .styles-module__canvasToggle___-QqSy:hover {
  background: rgba(0, 0, 0, 0.02);
  border-color: rgba(0, 0, 0, 0.12);
}
.styles-module__light___ORIft .styles-module__canvasToggle___-QqSy.styles-module__active___hosp7 {
  background: #f97316;
  border-color: transparent;
  border-style: solid;
  box-shadow: none;
}

.styles-module__canvasToggleIcon___7pJ82 {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  color: rgba(255, 255, 255, 0.35);
}
.styles-module__active___hosp7 .styles-module__canvasToggleIcon___7pJ82 {
  color: rgba(255, 255, 255, 0.85);
}
.styles-module__light___ORIft .styles-module__canvasToggleIcon___7pJ82 {
  color: rgba(0, 0, 0, 0.25);
}
.styles-module__light___ORIft .styles-module__active___hosp7 .styles-module__canvasToggleIcon___7pJ82 {
  color: rgba(255, 255, 255, 0.85);
}

.styles-module__canvasToggleLabel___OanpY {
  font-size: 0.8125rem;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.6);
  letter-spacing: -0.0094em;
}
.styles-module__active___hosp7 .styles-module__canvasToggleLabel___OanpY {
  color: #fff;
}
.styles-module__light___ORIft .styles-module__canvasToggleLabel___OanpY {
  color: rgba(0, 0, 0, 0.5);
}
.styles-module__light___ORIft .styles-module__active___hosp7 .styles-module__canvasToggleLabel___OanpY {
  color: #fff;
}

.styles-module__canvasPurposeWrap___hj6zk {
  display: grid;
  grid-template-rows: 1fr;
  transition: grid-template-rows 0.2s ease, opacity 0.15s ease;
  opacity: 1;
}
.styles-module__canvasPurposeWrap___hj6zk.styles-module__collapsed___Ms9vS {
  grid-template-rows: 0fr;
  opacity: 0;
}

.styles-module__canvasPurposeInner___VWiyu {
  overflow: hidden;
}

.styles-module__canvasPurposeToggle___byDH2 {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  margin: 0.375rem 1rem 0.375rem 1.1875rem;
}
.styles-module__canvasPurposeToggle___byDH2 input[type=checkbox] {
  position: absolute;
  opacity: 0;
  width: 0;
  height: 0;
}

.styles-module__canvasPurposeCheck___xqd7l {
  position: relative;
  width: 14px;
  height: 14px;
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.05);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: background 0.25s ease, border-color 0.25s ease;
}
.styles-module__canvasPurposeCheck___xqd7l svg {
  color: #1a1a1a;
  opacity: 1;
  transition: opacity 0.15s ease;
}
.styles-module__canvasPurposeCheck___xqd7l.styles-module__checked___-1JGH {
  border-color: rgba(255, 255, 255, 0.3);
  background: rgb(255, 255, 255);
}
.styles-module__light___ORIft .styles-module__canvasPurposeCheck___xqd7l {
  border: 1px solid rgba(0, 0, 0, 0.15);
  background: #fff;
}
.styles-module__light___ORIft .styles-module__canvasPurposeCheck___xqd7l.styles-module__checked___-1JGH {
  border-color: #1a1a1a;
  background: #1a1a1a;
}
.styles-module__light___ORIft .styles-module__canvasPurposeCheck___xqd7l.styles-module__checked___-1JGH svg {
  color: #fff;
}

.styles-module__canvasPurposeLabel___Zu-tD {
  font-size: 0.8125rem;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.5);
  letter-spacing: -0.0094em;
  display: flex;
  align-items: center;
  gap: 0.25rem;
}
.styles-module__light___ORIft .styles-module__canvasPurposeLabel___Zu-tD {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__canvasPurposeHelp___jijwR {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: help;
}
.styles-module__canvasPurposeHelp___jijwR svg {
  color: rgba(255, 255, 255, 0.2);
  transform: translateY(2px);
  transition: color 0.15s ease;
}
.styles-module__canvasPurposeHelp___jijwR:hover svg {
  color: rgba(255, 255, 255, 0.5);
}
.styles-module__light___ORIft .styles-module__canvasPurposeHelp___jijwR svg {
  color: rgba(0, 0, 0, 0.2);
}
.styles-module__light___ORIft .styles-module__canvasPurposeHelp___jijwR:hover svg {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__placement___zcxv8 {
  position: absolute;
  border: 1.5px dashed rgba(59, 130, 246, 0.4);
  border-radius: 6px;
  background: rgba(59, 130, 246, 0.08);
  cursor: grab;
  transition: box-shadow 0.15s, border-color 0.15s, opacity 0.15s ease, transform 0.15s ease;
  user-select: none;
  pointer-events: auto;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.08);
  animation: styles-module__placementEnter___TdRhf 0.25s cubic-bezier(0.34, 1.2, 0.64, 1);
}
.styles-module__placement___zcxv8:active {
  cursor: grabbing;
}
.styles-module__placement___zcxv8:hover {
  border-color: rgba(59, 130, 246, 0.5);
  background: rgba(59, 130, 246, 0.1);
  box-shadow: 0 2px 8px rgba(59, 130, 246, 0.12);
}
.styles-module__placement___zcxv8.styles-module__selected___6yrp6 {
  border-color: #3c82f7;
  border-style: solid;
  background: rgba(59, 130, 246, 0.1);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15), 0 2px 8px rgba(59, 130, 246, 0.15);
}
.styles-module__placement___zcxv8.styles-module__selected___6yrp6:hover {
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15), 0 2px 8px rgba(59, 130, 246, 0.15);
}
.styles-module__wireframe___itvQU .styles-module__placement___zcxv8 {
  border-color: rgba(249, 115, 22, 0.4);
  background: rgba(249, 115, 22, 0.08);
}
.styles-module__wireframe___itvQU .styles-module__placement___zcxv8:hover {
  border-color: rgba(249, 115, 22, 0.5);
  background: rgba(249, 115, 22, 0.1);
  box-shadow: 0 2px 8px rgba(249, 115, 22, 0.12);
}
.styles-module__wireframe___itvQU .styles-module__placement___zcxv8.styles-module__selected___6yrp6 {
  border-color: #f97316;
  background: rgba(249, 115, 22, 0.1);
  box-shadow: 0 0 0 2px rgba(249, 115, 22, 0.15), 0 2px 8px rgba(249, 115, 22, 0.15);
}
.styles-module__wireframe___itvQU .styles-module__placement___zcxv8.styles-module__selected___6yrp6:hover {
  box-shadow: 0 0 0 2px rgba(249, 115, 22, 0.15), 0 2px 8px rgba(249, 115, 22, 0.15);
}
.styles-module__placement___zcxv8.styles-module__dragging___le6KZ {
  opacity: 0.85;
  z-index: 50;
}
.styles-module__placement___zcxv8.styles-module__exiting___YrM8F {
  opacity: 0;
  transform: scale(0.97);
  pointer-events: none;
  animation: none;
  transition: opacity 0.2s ease, transform 0.2s cubic-bezier(0.32, 0.72, 0, 1);
}

.styles-module__placementContent___f64A4 {
  width: 100%;
  height: 100%;
  overflow: hidden;
  pointer-events: none;
}

.styles-module__placementLabel___0KvWl {
  position: absolute;
  top: -18px;
  left: 0;
  font-size: 10px;
  font-weight: 600;
  color: rgba(59, 130, 246, 0.7);
  white-space: nowrap;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  text-shadow: 0 0 4px rgba(255, 255, 255, 0.8), 0 0 8px rgba(255, 255, 255, 0.5);
}
.styles-module__selected___6yrp6 .styles-module__placementLabel___0KvWl {
  color: #3c82f7;
}
.styles-module__wireframe___itvQU .styles-module__placementLabel___0KvWl {
  color: rgba(249, 115, 22, 0.7);
}
.styles-module__wireframe___itvQU .styles-module__selected___6yrp6 .styles-module__placementLabel___0KvWl {
  color: #f97316;
}

.styles-module__placementAnnotation___78pTr {
  position: absolute;
  bottom: -18px;
  left: 0;
  right: 0;
  font-weight: 450;
  color: rgba(0, 0, 0, 0.5);
  font-size: 10px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  text-shadow: 0 0 4px rgba(255, 255, 255, 0.9), 0 0 8px rgba(255, 255, 255, 0.6);
  opacity: 0;
  transform: translateY(-2px);
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.styles-module__placementAnnotation___78pTr.styles-module__annotationVisible___mrUyA {
  opacity: 1;
  transform: translateY(0);
}

.styles-module__sectionAnnotation___aUIs0 {
  position: absolute;
  bottom: -18px;
  left: 0;
  right: 0;
  font-weight: 450;
  color: rgba(59, 130, 246, 0.6);
  font-size: 10px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  text-shadow: 0 0 4px rgba(255, 255, 255, 0.9), 0 0 8px rgba(255, 255, 255, 0.6);
  opacity: 0;
  transform: translateY(-2px);
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.styles-module__sectionAnnotation___aUIs0.styles-module__annotationVisible___mrUyA {
  opacity: 1;
  transform: translateY(0);
}

.styles-module__handle___Ikbxm {
  position: absolute;
  width: 8px;
  height: 8px;
  background: #fff;
  border: 1.5px solid #3c82f7;
  border-radius: 2px;
  z-index: 12;
  box-shadow: 0 0 0 0.5px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.12);
  opacity: 0;
  transform: scale(0.3);
  pointer-events: none;
  will-change: opacity, transform;
  transition: opacity 0.2s ease-out, transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.styles-module__placement___zcxv8:hover .styles-module__handle___Ikbxm, .styles-module__sectionOutline___s0hy-:hover .styles-module__handle___Ikbxm, .styles-module__ghostOutline___po-kO:hover .styles-module__handle___Ikbxm, .styles-module__placement___zcxv8:active .styles-module__handle___Ikbxm, .styles-module__sectionOutline___s0hy-:active .styles-module__handle___Ikbxm, .styles-module__ghostOutline___po-kO:active .styles-module__handle___Ikbxm, .styles-module__selected___6yrp6 .styles-module__handle___Ikbxm {
  opacity: 1;
  transform: scale(1);
  pointer-events: auto;
}
.styles-module__sectionOutline___s0hy- .styles-module__handle___Ikbxm {
  border-color: inherit;
}
.styles-module__wireframe___itvQU .styles-module__handle___Ikbxm {
  border-color: #f97316;
}

.styles-module__handleNw___4TMIj {
  top: -4px;
  left: -4px;
  cursor: nw-resize;
}

.styles-module__handleNe___mnsTh {
  top: -4px;
  right: -4px;
  cursor: ne-resize;
}

.styles-module__handleSe___oSFnk {
  bottom: -4px;
  right: -4px;
  cursor: se-resize;
}

.styles-module__handleSw___pi--Z {
  bottom: -4px;
  left: -4px;
  cursor: sw-resize;
}

.styles-module__handleN___aBA-Q, .styles-module__handleE___0hM5u, .styles-module__handleS___JjDRv, .styles-module__handleW___ERWGQ {
  opacity: 0 !important;
  pointer-events: none !important;
}

.styles-module__edgeHandle___XxXdT {
  position: absolute;
  z-index: 11;
  display: flex;
  align-items: center;
  justify-content: center;
}
.styles-module__edgeHandle___XxXdT::after {
  content: "";
  position: absolute;
  border-radius: 4px;
  background: #3c82f7;
}
.styles-module__wireframe___itvQU .styles-module__edgeHandle___XxXdT::after {
  background: #f97316;
}
.styles-module__edgeHandle___XxXdT::after {
  opacity: 0;
  transition: opacity 0.1s ease, transform 0.1s ease;
  transform: scale(0.8);
}
.styles-module__edgeHandle___XxXdT:hover::after {
  opacity: 0.85;
  transform: scale(1);
}
.styles-module__edgeHandle___XxXdT svg {
  position: relative;
  z-index: 1;
  opacity: 0;
  transition: opacity 0.1s ease;
  filter: drop-shadow(0 0 2px var(--agd-surface));
}
.styles-module__edgeHandle___XxXdT:hover svg {
  opacity: 1;
}

.styles-module__edgeN___-JJDj, .styles-module__edgeS___66lMX {
  left: 12px;
  right: 12px;
  height: 12px;
  cursor: n-resize;
}
.styles-module__edgeN___-JJDj::after, .styles-module__edgeS___66lMX::after {
  width: 24px;
  height: 4px;
}

.styles-module__edgeN___-JJDj {
  top: -6px;
}

.styles-module__edgeS___66lMX {
  bottom: -6px;
  cursor: s-resize;
}

.styles-module__edgeE___1bGDa, .styles-module__edgeW___lHQNo {
  top: 12px;
  bottom: 12px;
  width: 12px;
  cursor: e-resize;
}
.styles-module__edgeE___1bGDa::after, .styles-module__edgeW___lHQNo::after {
  width: 4px;
  height: 24px;
}

.styles-module__edgeE___1bGDa {
  right: -6px;
}

.styles-module__edgeW___lHQNo {
  left: -6px;
  cursor: w-resize;
}

.styles-module__deleteButton___LkGCb {
  position: absolute;
  top: -8px;
  right: -8px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(8px);
  border: 1px solid rgba(0, 0, 0, 0.08);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  color: rgba(0, 0, 0, 0.35);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  line-height: 1;
  z-index: 15;
  pointer-events: none;
  opacity: 0;
  transform: scale(0.8);
  will-change: opacity, transform;
  transition: opacity 0.2s ease-out, transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1), background 0.12s ease, color 0.12s ease, border-color 0.12s ease, box-shadow 0.12s ease;
}
.styles-module__placement___zcxv8:hover .styles-module__deleteButton___LkGCb, .styles-module__selected___6yrp6 .styles-module__deleteButton___LkGCb, .styles-module__sectionOutline___s0hy-:hover .styles-module__deleteButton___LkGCb, .styles-module__sectionOutline___s0hy-.styles-module__selected___6yrp6 .styles-module__deleteButton___LkGCb, .styles-module__ghostOutline___po-kO:hover .styles-module__deleteButton___LkGCb, .styles-module__ghostOutline___po-kO.styles-module__selected___6yrp6 .styles-module__deleteButton___LkGCb {
  opacity: 1;
  transform: scale(1);
  pointer-events: auto;
}
.styles-module__deleteButton___LkGCb:hover {
  background: #ef4444;
  color: #fff;
  border-color: #ef4444;
  box-shadow: 0 1px 4px rgba(239, 68, 68, 0.3);
  transform: scale(1.1);
}
.styles-module__overlay___aWh-q:not(.styles-module__light___ORIft) .styles-module__deleteButton___LkGCb, .styles-module__rearrangeOverlay___-3R3t:not(.styles-module__light___ORIft) .styles-module__deleteButton___LkGCb {
  background: rgba(40, 40, 40, 0.9);
  border-color: rgba(255, 255, 255, 0.1);
  color: rgba(255, 255, 255, 0.5);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.25);
}
.styles-module__overlay___aWh-q:not(.styles-module__light___ORIft) .styles-module__deleteButton___LkGCb:hover, .styles-module__rearrangeOverlay___-3R3t:not(.styles-module__light___ORIft) .styles-module__deleteButton___LkGCb:hover {
  background: #ef4444;
  color: #fff;
  border-color: #ef4444;
}

.styles-module__drawBox___BrVAa {
  position: fixed;
  pointer-events: none;
  z-index: 99996;
  border: 2px solid #3c82f7;
  border-radius: 6px;
  background: rgba(59, 130, 246, 0.15);
}

.styles-module__selectBox___Iu8kB {
  position: fixed;
  pointer-events: none;
  z-index: 99996;
  border: 1px dashed #3c82f7;
  background: rgba(59, 130, 246, 0.08);
  border-radius: 2px;
}

.styles-module__sizeIndicator___7zJ4y {
  position: fixed;
  pointer-events: none;
  z-index: 100001;
  font-size: 10px;
  color: #fff;
  background: #3c82f7;
  padding: 2px 6px;
  border-radius: 4px;
  white-space: nowrap;
  font-weight: 500;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
}

.styles-module__guideLine___DUQY2 {
  pointer-events: none;
  z-index: 100001;
  background: #f0f;
  opacity: 0.5;
}

.styles-module__dragPreview___onPbU {
  position: fixed;
  z-index: 100002;
  pointer-events: none;
  border: 1.5px dashed #3c82f7;
  border-radius: 6px;
  background: rgba(59, 130, 246, 0.1);
  backdrop-filter: blur(8px);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
  font-weight: 600;
  color: #3c82f7;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  box-shadow: 0 4px 16px rgba(59, 130, 246, 0.15);
  transition: width 0.08s ease, height 0.08s ease, opacity 0.08s ease;
}

.styles-module__dragPreviewWireframe___jsg0G {
  border-color: #f97316;
  background: rgba(249, 115, 22, 0.1);
  color: #f97316;
  box-shadow: 0 4px 16px rgba(249, 115, 22, 0.15);
}

.styles-module__palette___C7iSH {
  position: absolute;
  right: 5px;
  bottom: calc(100% + 0.5rem);
  width: 256px;
  overflow: hidden;
  background: #1c1c1c;
  border: none;
  border-radius: 1rem;
  padding: 13px 0 16px;
  box-shadow: 0 1px 8px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.04);
  z-index: 100001;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  cursor: default;
  opacity: 0;
  filter: blur(5px);
}
.styles-module__palette___C7iSH .styles-module__paletteItem___6TlnA,
.styles-module__palette___C7iSH .styles-module__paletteItemLabel___6ncO4,
.styles-module__palette___C7iSH .styles-module__paletteSectionTitle___PqnjX,
.styles-module__palette___C7iSH .styles-module__paletteFooter___QYnAG {
  transition: background 0.25s ease, color 0.25s ease, border-color 0.25s ease;
}
.styles-module__palette___C7iSH.styles-module__enter___6LYk5 {
  opacity: 1;
  transform: translateY(0);
  filter: blur(0px);
  transition: opacity 0.2s ease, transform 0.2s ease, filter 0.2s ease;
}
.styles-module__palette___C7iSH.styles-module__exit___iSGRw {
  opacity: 0;
  transform: translateY(6px);
  filter: blur(5px);
  pointer-events: none;
  transition: opacity 0.1s ease, transform 0.1s ease, filter 0.1s ease;
}
.styles-module__palette___C7iSH.styles-module__light___ORIft {
  background: #fff;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08), 0 4px 16px rgba(0, 0, 0, 0.06), 0 0 0 1px rgba(0, 0, 0, 0.04);
}

.styles-module__paletteSection___V8DEA {
  padding: 0 1rem;
}
.styles-module__paletteSection___V8DEA + .styles-module__paletteSection___V8DEA {
  margin-top: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid rgba(255, 255, 255, 0.07);
}
.styles-module__light___ORIft .styles-module__paletteSection___V8DEA + .styles-module__paletteSection___V8DEA {
  border-top-color: rgba(0, 0, 0, 0.07);
}

.styles-module__paletteSectionTitle___PqnjX {
  font-size: 0.6875rem;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.5);
  letter-spacing: -0.0094em;
  padding: 0 0 3px 3px;
}
.styles-module__light___ORIft .styles-module__paletteSectionTitle___PqnjX {
  color: rgba(0, 0, 0, 0.4);
}

.styles-module__paletteItem___6TlnA {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.25rem 0.25rem;
  margin-bottom: 1px;
  border-radius: 0.375rem;
  cursor: pointer;
  transition: background-color 0.15s ease, border-color 0.15s ease;
  border: 1px solid transparent;
  user-select: none;
  min-height: 24px;
}
.styles-module__paletteItem___6TlnA:hover {
  background: rgba(255, 255, 255, 0.1);
}
.styles-module__paletteItem___6TlnA.styles-module__active___hosp7 {
  background: #3c82f7;
  border-color: transparent;
}
.styles-module__paletteItem___6TlnA.styles-module__wireframe___itvQU.styles-module__active___hosp7 {
  background: #f97316;
}
.styles-module__light___ORIft .styles-module__paletteItem___6TlnA:hover {
  background: rgba(0, 0, 0, 0.05);
}
.styles-module__light___ORIft .styles-module__paletteItem___6TlnA.styles-module__active___hosp7 {
  background: #3c82f7;
  border-color: transparent;
}
.styles-module__light___ORIft .styles-module__paletteItem___6TlnA.styles-module__wireframe___itvQU.styles-module__active___hosp7 {
  background: #f97316;
}

.styles-module__paletteItemIcon___0NPQK {
  width: 20px;
  height: 16px;
  border-radius: 2px;
  border: 1px dashed rgba(255, 255, 255, 0.15);
  background: rgba(255, 255, 255, 0.04);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  overflow: hidden;
  color: rgba(255, 255, 255, 0.45);
}
.styles-module__paletteItemIcon___0NPQK svg {
  display: block;
  width: 20px;
  height: 16px;
}
.styles-module__active___hosp7 .styles-module__paletteItemIcon___0NPQK {
  border-color: rgba(255, 255, 255, 0.3);
  background: rgba(255, 255, 255, 0.15);
  color: #fff;
}
.styles-module__light___ORIft .styles-module__paletteItemIcon___0NPQK {
  border-color: rgba(0, 0, 0, 0.12);
  background: rgba(0, 0, 0, 0.02);
  color: rgba(0, 0, 0, 0.4);
}
.styles-module__light___ORIft .styles-module__active___hosp7 .styles-module__paletteItemIcon___0NPQK {
  border-color: rgba(255, 255, 255, 0.3);
  background: rgba(255, 255, 255, 0.15);
  color: #fff;
}

.styles-module__paletteItemLabel___6ncO4 {
  font-size: 0.8125rem;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.85);
  letter-spacing: -0.0094em;
  line-height: 1;
  min-width: 0;
}
.styles-module__active___hosp7 .styles-module__paletteItemLabel___6ncO4 {
  color: #fff;
  font-weight: 600;
}
.styles-module__light___ORIft .styles-module__paletteItemLabel___6ncO4 {
  color: rgba(0, 0, 0, 0.7);
}
.styles-module__light___ORIft .styles-module__active___hosp7 .styles-module__paletteItemLabel___6ncO4 {
  color: #fff;
  font-weight: 600;
}

.styles-module__placeScroll___7sClM {
  max-height: 240px;
  overflow-y: auto;
  overflow-x: hidden;
  padding-top: 0.25rem;
}
.styles-module__placeScroll___7sClM.styles-module__fadeTop___KT9tF {
  -webkit-mask-image: linear-gradient(to bottom, transparent 0, black 32px);
  mask-image: linear-gradient(to bottom, transparent 0, black 32px);
}
.styles-module__placeScroll___7sClM.styles-module__fadeBottom___x3ShT {
  -webkit-mask-image: linear-gradient(to bottom, black calc(100% - 32px), transparent 100%);
  mask-image: linear-gradient(to bottom, black calc(100% - 32px), transparent 100%);
}
.styles-module__placeScroll___7sClM.styles-module__fadeTop___KT9tF.styles-module__fadeBottom___x3ShT {
  -webkit-mask-image: linear-gradient(to bottom, transparent 0, black 32px, black calc(100% - 32px), transparent 100%);
  mask-image: linear-gradient(to bottom, transparent 0, black 32px, black calc(100% - 32px), transparent 100%);
}
.styles-module__placeScroll___7sClM::-webkit-scrollbar {
  width: 3px;
}
.styles-module__placeScroll___7sClM::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.12);
  border-radius: 2px;
}
.styles-module__light___ORIft .styles-module__placeScroll___7sClM::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.1);
}

.styles-module__paletteFooterWrap___71-fI {
  display: grid;
  grid-template-rows: 1fr;
  transition: grid-template-rows 0.25s cubic-bezier(0.32, 0.72, 0, 1);
}
.styles-module__paletteFooterWrap___71-fI.styles-module__footerHidden___fJUik {
  grid-template-rows: 0fr;
}

.styles-module__paletteFooterInnerContent___VC26h {
  opacity: 1;
  transform: translateY(0);
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.styles-module__footerHidden___fJUik .styles-module__paletteFooterInnerContent___VC26h {
  opacity: 0;
  transform: translateY(4px);
}

.styles-module__paletteFooterInner___dfylY {
  overflow: hidden;
}

.styles-module__paletteFooter___QYnAG {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 24px;
  padding: 0 1rem;
  margin-top: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid rgba(255, 255, 255, 0.07);
}
.styles-module__light___ORIft .styles-module__paletteFooter___QYnAG {
  border-top-color: rgba(0, 0, 0, 0.07);
}

.styles-module__paletteFooterCount___D3Fia {
  font-size: 0.8125rem;
  font-weight: 400;
  letter-spacing: -0.0094em;
  color: rgba(255, 255, 255, 0.5);
}
.styles-module__light___ORIft .styles-module__paletteFooterCount___D3Fia {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__paletteFooterClear___ybBoa {
  font-size: 0.8125rem;
  font-weight: 400;
  letter-spacing: -0.0094em;
  color: rgba(255, 255, 255, 0.5);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  font-family: inherit;
  transition: color 0.15s ease;
}
.styles-module__paletteFooterClear___ybBoa:hover {
  color: rgba(255, 255, 255, 0.7);
}
.styles-module__light___ORIft .styles-module__paletteFooterClear___ybBoa {
  color: rgba(0, 0, 0, 0.5);
}
.styles-module__light___ORIft .styles-module__paletteFooterClear___ybBoa:hover {
  color: rgba(0, 0, 0, 0.6);
}

.styles-module__paletteFooterActions___fLzv8 {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.styles-module__rollingWrap___S75jM {
  display: inline-block;
  overflow: hidden;
  height: 1.15em;
  position: relative;
  vertical-align: bottom;
}

.styles-module__rollingNum___1RKDx {
  position: absolute;
  left: 0;
  top: 0;
}

.styles-module__exitUp___AFDRW {
  animation: styles-module__numExitUp___FRQqx 0.25s cubic-bezier(0.32, 0.72, 0, 1) forwards;
}

.styles-module__enterUp___CPlXb {
  animation: styles-module__numEnterUp___2Yd-w 0.25s cubic-bezier(0.32, 0.72, 0, 1) forwards;
}

.styles-module__exitDown___-1yAy {
  animation: styles-module__numExitDown___xm5by 0.25s cubic-bezier(0.32, 0.72, 0, 1) forwards;
}

.styles-module__enterDown___DDuFR {
  animation: styles-module__numEnterDown___hpxBk 0.25s cubic-bezier(0.32, 0.72, 0, 1) forwards;
}

@keyframes styles-module__numExitUp___FRQqx {
  from {
    transform: translateY(0);
    opacity: 1;
  }
  to {
    transform: translateY(-110%);
    opacity: 0;
  }
}
@keyframes styles-module__numEnterUp___2Yd-w {
  from {
    transform: translateY(110%);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}
@keyframes styles-module__numExitDown___xm5by {
  from {
    transform: translateY(0);
    opacity: 1;
  }
  to {
    transform: translateY(110%);
    opacity: 0;
  }
}
@keyframes styles-module__numEnterDown___hpxBk {
  from {
    transform: translateY(-110%);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}
.styles-module__rearrangeOverlay___-3R3t {
  position: fixed;
  inset: 0;
  z-index: 99995;
  pointer-events: none;
  cursor: default;
  user-select: none;
  animation: styles-module__overlayFadeIn___aECVy 0.15s ease;
}

.styles-module__hoverHighlight___8eT-v {
  position: fixed;
  pointer-events: none;
  z-index: 99994;
  border: 2px dashed rgba(59, 130, 246, 0.5);
  border-radius: 4px;
  background: rgba(59, 130, 246, 0.06);
  animation: styles-module__highlightFadeIn___Lg7KY 0.12s ease;
}

.styles-module__sectionOutline___s0hy- {
  position: fixed;
  border: 2px solid;
  border-radius: 4px;
  cursor: grab;
}
.styles-module__sectionOutline___s0hy-:active {
  cursor: grabbing;
}
.styles-module__sectionOutline___s0hy- {
  transition: box-shadow 0.15s, border-color 0.3s, background-color 0.3s, border-style 0s;
  user-select: none;
  pointer-events: auto;
  animation: styles-module__sectionEnter___-8BXT 0.2s ease;
}
.styles-module__sectionOutline___s0hy-:hover {
  box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1), 0 4px 12px rgba(0, 0, 0, 0.15);
}
.styles-module__sectionOutline___s0hy-.styles-module__selected___6yrp6 {
  border-style: solid;
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15), 0 2px 8px rgba(59, 130, 246, 0.15);
}
.styles-module__sectionOutline___s0hy-.styles-module__selected___6yrp6:hover {
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15), 0 2px 8px rgba(59, 130, 246, 0.15);
}
.styles-module__sectionOutline___s0hy-.styles-module__settled___b5U5o:not(.styles-module__selected___6yrp6) {
  border: 1.5px dashed rgba(150, 150, 150, 0.35);
  background-color: transparent !important;
  box-shadow: none;
}
.styles-module__sectionOutline___s0hy-.styles-module__settled___b5U5o:not(.styles-module__selected___6yrp6):hover {
  border-color: rgba(150, 150, 150, 0.6);
  box-shadow: none;
}
.styles-module__sectionOutline___s0hy-.styles-module__settled___b5U5o:not(.styles-module__selected___6yrp6) .styles-module__sectionLabel___F80HQ {
  opacity: 0;
  transition: opacity 0.15s ease;
}
.styles-module__sectionOutline___s0hy-.styles-module__settled___b5U5o:not(.styles-module__selected___6yrp6):hover .styles-module__sectionLabel___F80HQ {
  opacity: 1;
}
.styles-module__sectionOutline___s0hy-.styles-module__settled___b5U5o:not(.styles-module__selected___6yrp6) .styles-module__movedBadge___s8z-q,
.styles-module__sectionOutline___s0hy-.styles-module__settled___b5U5o:not(.styles-module__selected___6yrp6) .styles-module__sectionDimensions___RcJSL {
  opacity: 0;
  transition: opacity 0.15s ease;
}
.styles-module__sectionOutline___s0hy-.styles-module__settled___b5U5o:not(.styles-module__selected___6yrp6):hover .styles-module__sectionDimensions___RcJSL {
  opacity: 1;
}
.styles-module__sectionOutline___s0hy-.styles-module__exiting___YrM8F {
  opacity: 0;
  transform: scale(0.97);
  pointer-events: none;
  animation: none;
  transition: opacity 0.2s ease, transform 0.2s cubic-bezier(0.32, 0.72, 0, 1);
}

.styles-module__sectionLabel___F80HQ {
  position: absolute;
  top: 4px;
  left: 4px;
  font-size: 10px;
  font-weight: 600;
  color: #fff;
  padding: 2px 8px;
  border-radius: 4px;
  white-space: nowrap;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.2);
  max-width: calc(100% - 8px);
  overflow: hidden;
  text-overflow: ellipsis;
}

.styles-module__movedBadge___s8z-q {
  position: absolute;
  bottom: 22px;
  right: 4px;
  font-size: 9px;
  font-weight: 700;
  color: #fff;
  background: #22c55e;
  padding: 2px 6px;
  border-radius: 4px;
  white-space: nowrap;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.2);
  opacity: 0;
  transform: scale(0.8);
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.styles-module__movedBadge___s8z-q.styles-module__badgeVisible___npbdS {
  opacity: 1;
  transform: scale(1);
  transition: opacity 0.2s cubic-bezier(0.34, 1.2, 0.64, 1), transform 0.2s cubic-bezier(0.34, 1.2, 0.64, 1);
}

.styles-module__resizedBadge___u51V8 {
  background: #3c82f7;
  bottom: 40px;
}

.styles-module__sectionDimensions___RcJSL {
  position: absolute;
  bottom: 4px;
  right: 4px;
  font-size: 9px;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.7);
  background: rgba(0, 0, 0, 0.5);
  padding: 1px 5px;
  border-radius: 3px;
  white-space: nowrap;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.styles-module__light___ORIft .styles-module__sectionDimensions___RcJSL {
  color: rgba(0, 0, 0, 0.5);
  background: rgba(255, 255, 255, 0.7);
}

.styles-module__wireframeNotice___4GJyB {
  position: fixed;
  bottom: 16px;
  left: 24px;
  z-index: 99995;
  font-size: 9.5px;
  font-weight: 400;
  color: rgba(0, 0, 0, 0.4);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  pointer-events: auto;
  animation: styles-module__overlayFadeIn___aECVy 0.3s ease;
  line-height: 1.5;
  max-width: 280px;
}

.styles-module__wireframeOpacityRow___CJXzi {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.styles-module__wireframeOpacityLabel___afkfT {
  font-size: 9px;
  font-weight: 500;
  color: rgba(0, 0, 0, 0.32);
  letter-spacing: 0.02em;
  white-space: nowrap;
  user-select: none;
}

.styles-module__wireframeOpacitySlider___YcoEs {
  -webkit-appearance: none;
  appearance: none;
  width: 56px;
  height: 4px;
  background: rgba(0, 0, 0, 0.08);
  border-radius: 2px;
  outline: none;
  cursor: pointer;
  flex-shrink: 0;
  transition: background 0.15s ease;
}
.styles-module__wireframeOpacitySlider___YcoEs:hover {
  background: rgba(0, 0, 0, 0.13);
}
.styles-module__wireframeOpacitySlider___YcoEs::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #f97316;
  cursor: pointer;
  transition: background 0.15s ease;
}
.styles-module__wireframeOpacitySlider___YcoEs::-webkit-slider-thumb:hover {
  background: rgb(224.4209205021, 95.3548117155, 5.7790794979);
}
.styles-module__wireframeOpacitySlider___YcoEs::-moz-range-thumb {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #f97316;
  border: none;
  cursor: pointer;
}
.styles-module__wireframeOpacitySlider___YcoEs::-moz-range-track {
  background: rgba(0, 0, 0, 0.08);
  height: 4px;
  border-radius: 2px;
}

.styles-module__wireframeNoticeTitleRow___PJqyG {
  display: flex;
  align-items: center;
  gap: 0;
  margin-bottom: 2px;
}

.styles-module__wireframeNoticeTitle___okr08 {
  font-weight: 600;
  color: rgba(0, 0, 0, 0.55);
}

.styles-module__wireframeNoticeDivider___PNKQ6 {
  width: 1px;
  height: 8px;
  background: rgba(0, 0, 0, 0.12);
  margin: 0 8px;
  flex-shrink: 0;
}

.styles-module__wireframeStartOver___YFk-I {
  font-size: 9.5px;
  font-weight: 500;
  color: rgba(0, 0, 0, 0.35);
  cursor: pointer;
  background: none;
  border: none;
  padding: 0;
  font-family: inherit;
  text-decoration: none;
  transition: color 0.12s ease;
  white-space: nowrap;
}
.styles-module__wireframeStartOver___YFk-I:hover {
  color: rgba(0, 0, 0, 0.6);
}

.styles-module__ghostOutline___po-kO {
  position: fixed;
  border: 1.5px dashed rgba(59, 130, 246, 0.4);
  border-radius: 4px;
  background: rgba(59, 130, 246, 0.04);
  cursor: grab;
  opacity: 0.5;
  user-select: none;
  pointer-events: auto;
  animation: styles-module__ghostEnter___EC3Mb 0.25s ease;
  transition: box-shadow 0.15s, border-color 0.3s, opacity 0.25s;
}
.styles-module__ghostOutline___po-kO:active {
  cursor: grabbing;
}
.styles-module__ghostOutline___po-kO:hover {
  opacity: 0.7;
  box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.1), 0 4px 12px rgba(0, 0, 0, 0.08);
}
.styles-module__ghostOutline___po-kO.styles-module__selected___6yrp6 {
  opacity: 1;
  border-style: solid;
  border-width: 2px;
  border-color: #3c82f7;
  background: rgba(59, 130, 246, 0.08);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15), 0 2px 8px rgba(59, 130, 246, 0.15);
}
.styles-module__ghostOutline___po-kO.styles-module__exiting___YrM8F {
  opacity: 0;
  transform: scale(0.97);
  pointer-events: none;
  animation: none;
  transition: opacity 0.2s ease, transform 0.2s cubic-bezier(0.32, 0.72, 0, 1);
}

.styles-module__ghostBadge___tsQUK {
  position: absolute;
  bottom: calc(100% + 4px);
  left: -1px;
  font-size: 9px;
  font-weight: 600;
  color: rgba(59, 130, 246, 0.9);
  background: rgba(59, 130, 246, 0.08);
  border: 1px solid rgba(59, 130, 246, 0.2);
  padding: 1px 5px;
  border-radius: 3px;
  white-space: nowrap;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  letter-spacing: 0.02em;
  line-height: 1.2;
  animation: styles-module__badgeSlideIn___typJ7 0.2s ease both;
}

@keyframes styles-module__badgeSlideIn___typJ7 {
  from {
    opacity: 0;
    transform: translateY(4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
.styles-module__ghostBadgeExtra___6CVoD {
  display: inline;
  animation: styles-module__badgeExtraIn___i4W8F 0.2s ease both;
}

@keyframes styles-module__badgeExtraIn___i4W8F {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
.styles-module__originalOutline___Y6DD1 {
  position: fixed;
  border: 1.5px dashed rgba(150, 150, 150, 0.3);
  border-radius: 4px;
  background: transparent;
  pointer-events: none;
  user-select: none;
  animation: styles-module__sectionEnter___-8BXT 0.2s ease;
}

.styles-module__originalLabel___HqI9g {
  position: absolute;
  top: 4px;
  left: 4px;
  font-size: 9px;
  font-weight: 500;
  color: rgba(150, 150, 150, 0.5);
  padding: 1px 6px;
  border-radius: 3px;
  white-space: nowrap;
  pointer-events: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: rgba(150, 150, 150, 0.08);
}

.styles-module__connectorSvg___Lovld {
  position: fixed;
  inset: 0;
  width: 100vw;
  height: 100vh;
  pointer-events: none;
  z-index: 99996;
}

.styles-module__connectorLine___XeWh- {
  transition: opacity 0.2s ease;
  animation: styles-module__connectorDraw___8sK5I 0.3s ease both;
}

.styles-module__connectorDot___yvf7C {
  transform-box: fill-box;
  transform-origin: center;
  animation: styles-module__connectorDotIn___NwTUq 0.25s cubic-bezier(0.34, 1.56, 0.64, 1) 0.15s both;
}

@keyframes styles-module__connectorDraw___8sK5I {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
@keyframes styles-module__connectorDotIn___NwTUq {
  from {
    transform: scale(0);
    opacity: 0;
  }
  to {
    transform: scale(1);
    opacity: 1;
  }
}
.styles-module__connectorExiting___2lLOs {
  animation: styles-module__connectorOut___5QoPl 0.2s ease forwards;
}
.styles-module__connectorExiting___2lLOs .styles-module__connectorDot___yvf7C {
  animation: styles-module__connectorDotOut___FEq7e 0.2s ease forwards;
}

@keyframes styles-module__connectorOut___5QoPl {
  from {
    opacity: 1;
  }
  to {
    opacity: 0;
  }
}
@keyframes styles-module__connectorDotOut___FEq7e {
  from {
    transform: scale(1);
    opacity: 1;
  }
  to {
    transform: scale(0);
    opacity: 0;
  }
}
@keyframes styles-module__placementEnter___TdRhf {
  from {
    opacity: 0;
    transform: scale(0.85);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}
@keyframes styles-module__sectionEnter___-8BXT {
  from {
    opacity: 0;
    transform: scale(0.96);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}
@keyframes styles-module__highlightFadeIn___Lg7KY {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
@keyframes styles-module__overlayFadeIn___aECVy {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
@keyframes styles-module__ghostEnter___EC3Mb {
  from {
    opacity: 0;
    transform: scale(0.96);
  }
  to {
    opacity: 0.6;
    transform: scale(1);
  }
}`,wF={overlayExiting:"styles-module__overlayExiting___iEmYr",overlay:"styles-module__overlay___aWh-q",overlayFadeIn:"styles-module__overlayFadeIn___aECVy",light:"styles-module__light___ORIft",wireframe:"styles-module__wireframe___itvQU",placing:"styles-module__placing___45yD8",passthrough:"styles-module__passthrough___xaFeE",blankCanvas:"styles-module__blankCanvas___t2Eue",visible:"styles-module__visible___OKKqX",gridActive:"styles-module__gridActive___OZ-cf",paletteHeader:"styles-module__paletteHeader___-Q5gQ",paletteHeaderTitle:"styles-module__paletteHeaderTitle___oHqZC",paletteHeaderDesc:"styles-module__paletteHeaderDesc___6i74T",wireframePurposeWrap:"styles-module__wireframePurposeWrap___To-tS",collapsed:"styles-module__collapsed___Ms9vS",wireframePurposeInner:"styles-module__wireframePurposeInner___Lrahs",wireframePurposeInput:"styles-module__wireframePurposeInput___7EtBN",canvasToggle:"styles-module__canvasToggle___-QqSy",active:"styles-module__active___hosp7",canvasToggleIcon:"styles-module__canvasToggleIcon___7pJ82",canvasToggleLabel:"styles-module__canvasToggleLabel___OanpY",canvasPurposeWrap:"styles-module__canvasPurposeWrap___hj6zk",canvasPurposeInner:"styles-module__canvasPurposeInner___VWiyu",canvasPurposeToggle:"styles-module__canvasPurposeToggle___byDH2",canvasPurposeCheck:"styles-module__canvasPurposeCheck___xqd7l",checked:"styles-module__checked___-1JGH",canvasPurposeLabel:"styles-module__canvasPurposeLabel___Zu-tD",canvasPurposeHelp:"styles-module__canvasPurposeHelp___jijwR",placement:"styles-module__placement___zcxv8",placementEnter:"styles-module__placementEnter___TdRhf",selected:"styles-module__selected___6yrp6",dragging:"styles-module__dragging___le6KZ",exiting:"styles-module__exiting___YrM8F",placementContent:"styles-module__placementContent___f64A4",placementLabel:"styles-module__placementLabel___0KvWl",placementAnnotation:"styles-module__placementAnnotation___78pTr",annotationVisible:"styles-module__annotationVisible___mrUyA",sectionAnnotation:"styles-module__sectionAnnotation___aUIs0",handle:"styles-module__handle___Ikbxm",sectionOutline:"styles-module__sectionOutline___s0hy-",ghostOutline:"styles-module__ghostOutline___po-kO",handleNw:"styles-module__handleNw___4TMIj",handleNe:"styles-module__handleNe___mnsTh",handleSe:"styles-module__handleSe___oSFnk",handleSw:"styles-module__handleSw___pi--Z",handleN:"styles-module__handleN___aBA-Q",handleE:"styles-module__handleE___0hM5u",handleS:"styles-module__handleS___JjDRv",handleW:"styles-module__handleW___ERWGQ",edgeHandle:"styles-module__edgeHandle___XxXdT",edgeN:"styles-module__edgeN___-JJDj",edgeS:"styles-module__edgeS___66lMX",edgeE:"styles-module__edgeE___1bGDa",edgeW:"styles-module__edgeW___lHQNo",deleteButton:"styles-module__deleteButton___LkGCb",rearrangeOverlay:"styles-module__rearrangeOverlay___-3R3t",drawBox:"styles-module__drawBox___BrVAa",selectBox:"styles-module__selectBox___Iu8kB",sizeIndicator:"styles-module__sizeIndicator___7zJ4y",guideLine:"styles-module__guideLine___DUQY2",dragPreview:"styles-module__dragPreview___onPbU",dragPreviewWireframe:"styles-module__dragPreviewWireframe___jsg0G",palette:"styles-module__palette___C7iSH",paletteItem:"styles-module__paletteItem___6TlnA",paletteItemLabel:"styles-module__paletteItemLabel___6ncO4",paletteSectionTitle:"styles-module__paletteSectionTitle___PqnjX",paletteFooter:"styles-module__paletteFooter___QYnAG",enter:"styles-module__enter___6LYk5",exit:"styles-module__exit___iSGRw",paletteSection:"styles-module__paletteSection___V8DEA",paletteItemIcon:"styles-module__paletteItemIcon___0NPQK",placeScroll:"styles-module__placeScroll___7sClM",fadeTop:"styles-module__fadeTop___KT9tF",fadeBottom:"styles-module__fadeBottom___x3ShT",paletteFooterWrap:"styles-module__paletteFooterWrap___71-fI",footerHidden:"styles-module__footerHidden___fJUik",paletteFooterInnerContent:"styles-module__paletteFooterInnerContent___VC26h",paletteFooterInner:"styles-module__paletteFooterInner___dfylY",paletteFooterCount:"styles-module__paletteFooterCount___D3Fia",paletteFooterClear:"styles-module__paletteFooterClear___ybBoa",paletteFooterActions:"styles-module__paletteFooterActions___fLzv8",rollingWrap:"styles-module__rollingWrap___S75jM",rollingNum:"styles-module__rollingNum___1RKDx",exitUp:"styles-module__exitUp___AFDRW",numExitUp:"styles-module__numExitUp___FRQqx",enterUp:"styles-module__enterUp___CPlXb",numEnterUp:"styles-module__numEnterUp___2Yd-w",exitDown:"styles-module__exitDown___-1yAy",numExitDown:"styles-module__numExitDown___xm5by",enterDown:"styles-module__enterDown___DDuFR",numEnterDown:"styles-module__numEnterDown___hpxBk",hoverHighlight:"styles-module__hoverHighlight___8eT-v",highlightFadeIn:"styles-module__highlightFadeIn___Lg7KY",sectionEnter:"styles-module__sectionEnter___-8BXT",settled:"styles-module__settled___b5U5o",sectionLabel:"styles-module__sectionLabel___F80HQ",movedBadge:"styles-module__movedBadge___s8z-q",sectionDimensions:"styles-module__sectionDimensions___RcJSL",badgeVisible:"styles-module__badgeVisible___npbdS",resizedBadge:"styles-module__resizedBadge___u51V8",wireframeNotice:"styles-module__wireframeNotice___4GJyB",wireframeOpacityRow:"styles-module__wireframeOpacityRow___CJXzi",wireframeOpacityLabel:"styles-module__wireframeOpacityLabel___afkfT",wireframeOpacitySlider:"styles-module__wireframeOpacitySlider___YcoEs",wireframeNoticeTitleRow:"styles-module__wireframeNoticeTitleRow___PJqyG",wireframeNoticeTitle:"styles-module__wireframeNoticeTitle___okr08",wireframeNoticeDivider:"styles-module__wireframeNoticeDivider___PNKQ6",wireframeStartOver:"styles-module__wireframeStartOver___YFk-I",ghostEnter:"styles-module__ghostEnter___EC3Mb",ghostBadge:"styles-module__ghostBadge___tsQUK",badgeSlideIn:"styles-module__badgeSlideIn___typJ7",ghostBadgeExtra:"styles-module__ghostBadgeExtra___6CVoD",badgeExtraIn:"styles-module__badgeExtraIn___i4W8F",originalOutline:"styles-module__originalOutline___Y6DD1",originalLabel:"styles-module__originalLabel___HqI9g",connectorSvg:"styles-module__connectorSvg___Lovld",connectorLine:"styles-module__connectorLine___XeWh-",connectorDraw:"styles-module__connectorDraw___8sK5I",connectorDot:"styles-module__connectorDot___yvf7C",connectorDotIn:"styles-module__connectorDotIn___NwTUq",connectorExiting:"styles-module__connectorExiting___2lLOs",connectorOut:"styles-module__connectorOut___5QoPl",connectorDotOut:"styles-module__connectorDotOut___FEq7e"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-design-mode-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-design-mode-styles",document.head.appendChild(J);J.textContent=EF}var Z4=wF,D0=24,gz=5;function k_(J,H,Y,K,W){let O=1/0,A=1/0,C=J.x,x=J.x+J.width,J4=J.x+J.width/2,b=J.y,g=J.y+J.height,R=J.y+J.height/2,o=!K,p=o?[C,x,J4]:[...K.left?[C]:[],...K.right?[x]:[]],q4=o?[b,g,R]:[...K.top?[b]:[],...K.bottom?[g]:[]],h=[];for(let l4 of H)if(!Y.has(l4.id))h.push(l4);if(W)h.push(...W);for(let l4 of h){let d4=l4.x,b4=l4.x+l4.width,n4=l4.x+l4.width/2,B4=l4.y,L4=l4.y+l4.height,O4=l4.y+l4.height/2;for(let $4 of p)for(let C4 of[d4,b4,n4]){let R7=C4-$4;if(Math.abs(R7)<gz&&Math.abs(R7)<Math.abs(O))O=R7}for(let $4 of q4)for(let C4 of[B4,L4,O4]){let R7=C4-$4;if(Math.abs(R7)<gz&&Math.abs(R7)<Math.abs(A))A=R7}}let t=Math.abs(O)<gz?O:0,I4=Math.abs(A)<gz?A:0,u4=[],i4=new Set,g7=C+t,h7=x+t,T4=J4+t,p4=b+I4,N7=g+I4,Y4=R+I4;for(let l4 of h){let d4=l4.x,b4=l4.x+l4.width,n4=l4.x+l4.width/2,B4=l4.y,L4=l4.y+l4.height,O4=l4.y+l4.height/2;for(let $4 of[d4,n4,b4])for(let C4 of[g7,T4,h7])if(Math.abs(C4-$4)<0.5){let R7=`x:${Math.round($4)}`;if(!i4.has(R7))i4.add(R7),u4.push({axis:"x",pos:$4})}for(let $4 of[B4,O4,L4])for(let C4 of[p4,Y4,N7])if(Math.abs(C4-$4)<0.5){let R7=`y:${Math.round($4)}`;if(!i4.has(R7))i4.add(R7),u4.push({axis:"y",pos:$4})}}return{dx:t,dy:I4,guides:u4}}function y_(){return`dp-${Date.now()}-${Math.random().toString(36).slice(2,7)}`}function IF({placements:J,onChange:H,activeComponent:Y,onActiveComponentChange:K,isDarkMode:W,exiting:O,onInteractionChange:A,className:C,passthrough:x,extraSnapRects:J4,onSelectionChange:b,deselectSignal:g,onDragMove:R,onDragEnd:o,clearSignal:p,wireframe:q4}){let[h,t]=t7.useState(new Set),[I4,u4]=t7.useState(null),[i4,g7]=t7.useState(null),[h7,T4]=t7.useState(null),[p4,N7]=t7.useState([]),[Y4,l4]=t7.useState(null),[d4,b4]=t7.useState(!1),n4=t7.useRef(!1),[B4,L4]=t7.useState(new Set),O4=t7.useRef(new Map),$4=t7.useRef(null),C4=t7.useRef(null),R7=t7.useRef(J);R7.current=J;let s=t7.useRef(b);s.current=b;let c4=t7.useRef(R);c4.current=R;let Q7=t7.useRef(o);Q7.current=o;let W7=t7.useRef(g);t7.useEffect(()=>{if(g!==W7.current)W7.current=g,t(new Set)},[g]);let EZ=t7.useRef(p);t7.useEffect(()=>{if(p!==void 0&&p!==EZ.current){EZ.current=p;let U4=new Set(R7.current.map((D4)=>D4.id));if(U4.size>0)L4(U4),t(new Set),C4.current=null,q7(()=>{H([]),L4(new Set)},180)}},[p,H]),t7.useEffect(()=>{let U4=(D4)=>{let z7=D4.target;if(z7.tagName==="INPUT"||z7.tagName==="TEXTAREA"||z7.isContentEditable)return;if((D4.key==="Backspace"||D4.key==="Delete")&&h.size>0){D4.preventDefault();let t4=new Set(h);L4(t4),t(new Set),q7(()=>{H(R7.current.filter((b7)=>!t4.has(b7.id))),L4(new Set)},180);return}if(["ArrowUp","ArrowDown","ArrowLeft","ArrowRight"].includes(D4.key)&&h.size>0){D4.preventDefault();let t4=D4.shiftKey?20:1,b7=D4.key==="ArrowLeft"?-t4:D4.key==="ArrowRight"?t4:0,o7=D4.key==="ArrowUp"?-t4:D4.key==="ArrowDown"?t4:0;H(J.map((S7)=>h.has(S7.id)?{...S7,x:Math.max(0,S7.x+b7),y:Math.max(0,S7.y+o7)}:S7));return}if(D4.key==="Escape"){if(Y)K(null);else if(h.size>0)t(new Set);return}};return document.addEventListener("keydown",U4),()=>document.removeEventListener("keydown",U4)},[h,Y,J,H,K]);let I2=t7.useCallback((U4)=>{if(U4.button!==0)return;if(x)return;if(U4.target.closest(`.${Z4.placement}`))return;U4.preventDefault(),U4.stopPropagation();let z7=window.scrollY,J7=U4.clientX,t4=U4.clientY;if(Y){C4.current="place",A?.(!0);let b7=!1,o7=J7,S7=t4,A7=(f)=>{o7=f.clientX,S7=f.clientY;let u=Math.abs(o7-J7),G4=Math.abs(S7-t4);if(u>5||G4>5)b7=!0;if(b7){let z4=Math.min(J7,o7),S4=Math.min(t4,S7),m4=Math.abs(o7-J7),j4=Math.abs(S7-t4);u4({x:z4,y:S4,w:m4,h:j4}),T4({x:f.clientX+12,y:f.clientY+12,text:`${Math.round(m4)} × ${Math.round(j4)}`})}},o4=(f)=>{window.removeEventListener("mousemove",A7),window.removeEventListener("mouseup",o4),u4(null),T4(null),C4.current=null,A?.(!1);let u=f4[Y],G4,z4,S4,m4;if(b7)G4=Math.min(J7,o7),z4=Math.min(t4,S7)+z7,S4=Math.max(D0,Math.abs(o7-J7)),m4=Math.max(D0,Math.abs(S7-t4));else S4=u.width,m4=u.height,G4=J7-S4/2,z4=t4+z7-m4/2;G4=Math.max(0,G4),z4=Math.max(0,z4);let j4={id:y_(),type:Y,x:G4,y:z4,width:S4,height:m4,scrollY:z7,timestamp:Date.now()},_=[...J,j4];H(_),t(new Set([j4.id])),K(null)};window.addEventListener("mousemove",A7),window.addEventListener("mouseup",o4)}else{if(!U4.shiftKey)t(new Set);C4.current="select";let b7=!1,o7=(A7)=>{let o4=Math.abs(A7.clientX-J7),f=Math.abs(A7.clientY-t4);if(o4>4||f>4)b7=!0;if(b7){let u=Math.min(J7,A7.clientX),G4=Math.min(t4,A7.clientY);g7({x:u,y:G4,w:Math.abs(A7.clientX-J7),h:Math.abs(A7.clientY-t4)})}},S7=(A7)=>{if(window.removeEventListener("mousemove",o7),window.removeEventListener("mouseup",S7),C4.current=null,b7){let o4=Math.min(J7,A7.clientX),f=Math.min(t4,A7.clientY)+z7,u=Math.abs(A7.clientX-J7),G4=Math.abs(A7.clientY-t4),z4=new Set(U4.shiftKey?h:new Set);for(let S4 of J){let m4=S4.y-z7;if(S4.x+S4.width>o4&&S4.x<o4+u&&S4.y+S4.height>f&&S4.y<f+G4)z4.add(S4.id)}t(z4)}g7(null)};window.addEventListener("mousemove",o7),window.addEventListener("mouseup",S7)}},[Y,x,J,H,h]),u7=t7.useCallback((U4,D4)=>{if(U4.button!==0)return;let z7=U4.target;if(z7.closest(`.${Z4.handle}`)||z7.closest(`.${Z4.deleteButton}`))return;U4.preventDefault(),U4.stopPropagation();let J7;if(U4.shiftKey)if(J7=new Set(h),J7.has(D4))J7.delete(D4);else J7.add(D4);else if(!h.has(D4))J7=new Set([D4]);else J7=new Set(h);if(t(J7),J7.size!==h.size||[...J7].some((_)=>!h.has(_)))s.current?.(J7,U4.shiftKey);let b7=window.scrollY,o7=U4.clientX,S7=U4.clientY,A7=new Map;for(let _ of J)if(J7.has(_.id))A7.set(_.id,{x:_.x,y:_.y});C4.current="move",A?.(!0);let o4=!1,f=!1,u=J,G4=0,z4=0,S4=new Map;for(let _ of J)if(A7.has(_.id))S4.set(_.id,{w:_.width,h:_.height});let m4=(_)=>{let E=_.clientX-o7,a=_.clientY-S7;if(Math.abs(E)>2||Math.abs(a)>2)o4=!0;if(!o4)return;if(_.altKey&&!f){f=!0;let X7=[];for(let e7 of J)if(A7.has(e7.id))X7.push({...e7,id:y_(),timestamp:Date.now()});u=[...J,...X7]}let H4=1/0,e=1/0,x4=-1/0,F4=-1/0;for(let[X7,e7]of A7){let kZ=S4.get(X7);if(!kZ)continue;H4=Math.min(H4,e7.x+E),e=Math.min(e,e7.y+a),x4=Math.max(x4,e7.x+E+kZ.w),F4=Math.max(F4,e7.y+a+kZ.h)}let E4={x:H4,y:e,width:x4-H4,height:F4-e},{dx:Q4,dy:M7,guides:U7}=k_(E4,u,new Set(A7.keys()),void 0,J4);N7(U7);let H7=E+Q4,f7=a+M7;G4=H7,z4=f7,H(u.map((X7)=>{let e7=A7.get(X7.id);if(!e7)return X7;return{...X7,x:Math.max(0,e7.x+H7),y:Math.max(0,e7.y+f7)}})),c4.current?.(H7,f7)},j4=()=>{window.removeEventListener("mousemove",m4),window.removeEventListener("mouseup",j4),C4.current=null,A?.(!1),N7([]),Q7.current?.(G4,z4,o4)};window.addEventListener("mousemove",m4),window.addEventListener("mouseup",j4)},[h,J,H,A]),AZ=t7.useCallback((U4,D4,z7)=>{U4.preventDefault(),U4.stopPropagation();let J7=J.find((z4)=>z4.id===D4);if(!J7)return;t(new Set([D4])),C4.current="resize",A?.(!0);let{clientX:t4,clientY:b7}=U4,o7=J7.width,S7=J7.height,A7=J7.x,o4=J7.y,f={left:z7.includes("w"),right:z7.includes("e"),top:z7.includes("n"),bottom:z7.includes("s")},u=(z4)=>{let S4=z4.clientX-t4,m4=z4.clientY-b7,j4=o7,_=S7,E=A7,a=o4;if(z7.includes("e"))j4=Math.max(D0,o7+S4);if(z7.includes("w"))j4=Math.max(D0,o7-S4),E=A7+o7-j4;if(z7.includes("s"))_=Math.max(D0,S7+m4);if(z7.includes("n"))_=Math.max(D0,S7-m4),a=o4+S7-_;let H4={x:E,y:a,width:j4,height:_},{dx:e,dy:x4,guides:F4}=k_(H4,R7.current,new Set([D4]),f,J4);if(N7(F4),e!==0){if(f.right)j4+=e;else if(f.left)E+=e,j4-=e}if(x4!==0){if(f.bottom)_+=x4;else if(f.top)a+=x4,_-=x4}H(R7.current.map((E4)=>E4.id===D4?{...E4,x:E,y:a,width:j4,height:_}:E4)),T4({x:z4.clientX+12,y:z4.clientY+12,text:`${Math.round(j4)} × ${Math.round(_)}`})},G4=()=>{window.removeEventListener("mousemove",u),window.removeEventListener("mouseup",G4),T4(null),C4.current=null,A?.(!1),N7([])};window.addEventListener("mousemove",u),window.addEventListener("mouseup",G4)},[J,H,A]),eZ=t7.useCallback((U4)=>{C4.current=null,L4((D4)=>{let z7=new Set(D4);return z7.add(U4),z7}),t((D4)=>{let z7=new Set(D4);return z7.delete(U4),z7}),q7(()=>{H(R7.current.filter((D4)=>D4.id!==U4)),L4((D4)=>{let z7=new Set(D4);return z7.delete(U4),z7})},180)},[H]),Z5=new Set(["text","hero","button","badge","cta","toast","modal","card","navigation","tabs","input","search","breadcrumb","pricing","testimonial","alert","banner","tag","notification","stat","productCard"]),M4={hero:"Headline text",button:"Button label",badge:"Badge label",cta:"Call to action text",toast:"Notification message",modal:"Dialog title",card:"Card title",navigation:"Brand / nav items",tabs:"Tab labels",input:"Placeholder text",search:"Search placeholder",pricing:"Plan name or price",testimonial:"Quote text",alert:"Alert message",banner:"Banner text",tag:"Tag label",notification:"Notification message",stat:"Metric value",productCard:"Product name"},_2=t7.useCallback((U4)=>{let D4=J.find((z7)=>z7.id===U4);if(!D4)return;n4.current=!!D4.text,l4(U4),b4(!1)},[J]),uZ=t7.useCallback(()=>{if(!Y4)return;b4(!0),q7(()=>{l4(null),b4(!1)},150)},[Y4]);t7.useEffect(()=>{if(O&&Y4)uZ()},[O]);let Y2=t7.useCallback((U4)=>{if(!Y4)return;H(J.map((D4)=>D4.id===Y4?{...D4,text:U4.trim()||void 0}:D4)),uZ()},[Y4,J,H,uZ]),qZ=typeof window<"u"?window.scrollY:0,s7=["nw","ne","se","sw"],M2=q4?"#f97316":"#3c82f7",N4=[{dir:"n",cls:Z4.edgeN,arrow:RZ.jsx("svg",{width:"8",height:"6",viewBox:"0 0 8 6",fill:"none",children:RZ.jsx("path",{d:"M4 0.5L1 4.5h6z",fill:M2})})},{dir:"e",cls:Z4.edgeE,arrow:RZ.jsx("svg",{width:"6",height:"8",viewBox:"0 0 6 8",fill:"none",children:RZ.jsx("path",{d:"M5.5 4L1.5 1v6z",fill:M2})})},{dir:"s",cls:Z4.edgeS,arrow:RZ.jsx("svg",{width:"8",height:"6",viewBox:"0 0 8 6",fill:"none",children:RZ.jsx("path",{d:"M4 5.5L1 1.5h6z",fill:M2})})},{dir:"w",cls:Z4.edgeW,arrow:RZ.jsx("svg",{width:"6",height:"8",viewBox:"0 0 6 8",fill:"none",children:RZ.jsx("path",{d:"M0.5 4L4.5 1v6z",fill:M2})})}];return RZ.jsxs(RZ.Fragment,{children:[RZ.jsx("div",{ref:$4,className:`${Z4.overlay} ${!W?Z4.light:""} ${Y?Z4.placing:""} ${x?Z4.passthrough:""} ${O?Z4.overlayExiting:""} ${q4?Z4.wireframe:""}${C?` ${C}`:""}`,"data-feedback-toolbar":!0,onMouseDown:I2,children:J.map((U4)=>{let D4=h.has(U4.id),z7=j6[U4.type]?.label||U4.type,J7=U4.y-qZ;return RZ.jsxs("div",{"data-design-placement":U4.id,className:`${Z4.placement} ${D4?Z4.selected:""} ${B4.has(U4.id)?Z4.exiting:""}`,style:{left:U4.x,top:J7,width:U4.width,height:U4.height,position:"fixed"},onMouseDown:(t4)=>u7(t4,U4.id),onDoubleClick:()=>_2(U4.id),children:[RZ.jsx("span",{className:Z4.placementLabel,children:z7}),RZ.jsx("span",{className:`${Z4.placementAnnotation} ${U4.text?Z4.annotationVisible:""}`,children:(()=>{if(U4.text)O4.current.set(U4.id,U4.text);return U4.text||O4.current.get(U4.id)||""})()}),RZ.jsx("div",{className:Z4.placementContent,children:RZ.jsx(TF,{type:U4.type,width:U4.width,height:U4.height,text:U4.text})}),RZ.jsx("div",{className:Z4.deleteButton,onMouseDown:(t4)=>t4.stopPropagation(),onClick:()=>eZ(U4.id),children:"✕"}),s7.map((t4)=>RZ.jsx("div",{className:`${Z4.handle} ${Z4[`handle${t4.charAt(0).toUpperCase()}${t4.slice(1)}`]}`,onMouseDown:(b7)=>AZ(b7,U4.id,t4)},t4)),N4.map(({dir:t4,cls:b7,arrow:o7})=>RZ.jsx("div",{className:`${Z4.edgeHandle} ${b7}`,onMouseDown:(S7)=>AZ(S7,U4.id,t4),children:o7},t4))]},U4.id)})}),Y4&&(()=>{let U4=J.find((o4)=>o4.id===Y4);if(!U4)return null;let D4=U4.y-qZ,z7=U4.x+U4.width/2,J7=D4-8,t4=D4+U4.height+8,b7=J7>200,o7=t4<window.innerHeight-100,S7=Math.max(160,Math.min(window.innerWidth-160,z7)),A7;if(b7)A7={left:S7,bottom:window.innerHeight-J7};else if(o7)A7={left:S7,top:t4};else A7={left:S7,top:Math.max(80,window.innerHeight/2-80)};return RZ.jsx(iz,{element:j6[U4.type]?.label||U4.type,placeholder:M4[U4.type]||"Label or content text",initialValue:U4.text??"",submitLabel:n4.current?"Save":"Set",onSubmit:Y2,onCancel:uZ,onDelete:n4.current?()=>{Y2("")}:void 0,isExiting:d4,lightMode:!W,style:A7})})(),I4&&RZ.jsx("div",{className:Z4.drawBox,style:{left:I4.x,top:I4.y,width:I4.w,height:I4.h},"data-feedback-toolbar":!0}),i4&&RZ.jsx("div",{className:Z4.selectBox,style:{left:i4.x,top:i4.y,width:i4.w,height:i4.h},"data-feedback-toolbar":!0}),h7&&RZ.jsx("div",{className:Z4.sizeIndicator,style:{left:h7.x,top:h7.y},"data-feedback-toolbar":!0,children:h7.text}),p4.map((U4,D4)=>RZ.jsx("div",{className:Z4.guideLine,style:U4.axis==="x"?{position:"fixed",left:U4.pos,top:0,width:1,bottom:0}:{position:"fixed",left:0,top:U4.pos-qZ,right:0,height:1},"data-feedback-toolbar":!0},`${U4.axis}-${U4.pos}-${D4}`))]})}function xF(J){if(!J)return"";let H=J.scrollTop>2,Y=J.scrollTop+J.clientHeight<J.scrollHeight-2;return`${H?Z4.fadeTop:""} ${Y?Z4.fadeBottom:""}`}var M="currentColor",n="0.5";function SF({type:J}){switch(J){case"navigation":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"4",width:"18",height:"8",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"2.5",y:"7",width:"3",height:"1.5",rx:".5",fill:M,opacity:".4"}),L.jsx("rect",{x:"7",y:"7",width:"2.5",height:"1.5",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"11",y:"7",width:"2.5",height:"1.5",rx:".5",fill:M,opacity:".25"})]});case"header":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"2",width:"18",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3",y:"5.5",width:"8",height:"2",rx:".5",fill:M,opacity:".35"}),L.jsx("rect",{x:"3",y:"9",width:"12",height:"1",rx:".5",fill:M,opacity:".15"})]});case"hero":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"1",width:"18",height:"14",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5",y:"5",width:"10",height:"1.5",rx:".5",fill:M,opacity:".35"}),L.jsx("rect",{x:"7",y:"8",width:"6",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"7.5",y:"10.5",width:"5",height:"2.5",rx:"1",stroke:M,strokeWidth:n})]});case"section":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"1",width:"18",height:"14",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3",y:"4",width:"6",height:"1",rx:".5",fill:M,opacity:".3"}),L.jsx("rect",{x:"3",y:"6.5",width:"14",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"3",y:"9",width:"10",height:"1",rx:".5",fill:M,opacity:".15"})]});case"sidebar":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"1",width:"7",height:"14",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"2.5",y:"4",width:"4",height:"1",rx:".5",fill:M,opacity:".3"}),L.jsx("rect",{x:"2.5",y:"6.5",width:"3.5",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"2.5",y:"9",width:"4",height:"1",rx:".5",fill:M,opacity:".15"})]});case"footer":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"7",width:"18",height:"8",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3",y:"9.5",width:"4",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"9",y:"9.5",width:"4",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"15",y:"9.5",width:"3",height:"1",rx:".5",fill:M,opacity:".2"})]});case"modal":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"2",width:"14",height:"12",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5",y:"4.5",width:"7",height:"1",rx:".5",fill:M,opacity:".3"}),L.jsx("rect",{x:"5",y:"7",width:"10",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"11",y:"11",width:"5",height:"2",rx:".75",stroke:M,strokeWidth:n})]});case"divider":return L.jsx("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:L.jsx("line",{x1:"2",y1:"8",x2:"18",y2:"8",stroke:M,strokeWidth:"0.5",opacity:".3"})});case"card":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"1",width:"16",height:"14",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"2",y:"1",width:"16",height:"5.5",rx:"1",fill:M,opacity:".04"}),L.jsx("rect",{x:"4",y:"8.5",width:"8",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"4",y:"11",width:"11",height:"1",rx:".5",fill:M,opacity:".12"})]});case"text":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"4",width:"14",height:"1.5",rx:".5",fill:M,opacity:".3"}),L.jsx("rect",{x:"2",y:"7",width:"11",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"2",y:"9.5",width:"13",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"2",y:"12",width:"8",height:"1",rx:".5",fill:M,opacity:".12"})]});case"image":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"2",width:"16",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("line",{x1:"2",y1:"2",x2:"18",y2:"14",stroke:M,strokeWidth:".3",opacity:".25"}),L.jsx("line",{x1:"18",y1:"2",x2:"2",y2:"14",stroke:M,strokeWidth:".3",opacity:".25"})]});case"video":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"2",width:"16",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("path",{d:"M8.5 5.5v5l4.5-2.5z",stroke:M,strokeWidth:n,fill:M,opacity:".15"})]});case"table":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"2",width:"18",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("line",{x1:"1",y1:"5.5",x2:"19",y2:"5.5",stroke:M,strokeWidth:".3",opacity:".25"}),L.jsx("line",{x1:"1",y1:"9",x2:"19",y2:"9",stroke:M,strokeWidth:".3",opacity:".25"}),L.jsx("line",{x1:"7",y1:"2",x2:"7",y2:"14",stroke:M,strokeWidth:".3",opacity:".25"}),L.jsx("line",{x1:"13",y1:"2",x2:"13",y2:"14",stroke:M,strokeWidth:".3",opacity:".25"})]});case"grid":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1.5",y:"2",width:"7",height:"5.5",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"11.5",y:"2",width:"7",height:"5.5",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"1.5",y:"9.5",width:"7",height:"5.5",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"11.5",y:"9.5",width:"7",height:"5.5",rx:"1",stroke:M,strokeWidth:n})]});case"list":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("circle",{cx:"3.5",cy:"4.5",r:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6.5",y:"4",width:"10",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("circle",{cx:"3.5",cy:"8",r:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6.5",y:"7.5",width:"8",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("circle",{cx:"3.5",cy:"11.5",r:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6.5",y:"11",width:"11",height:"1",rx:".5",fill:M,opacity:".2"})]});case"chart":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"9",width:"2.5",height:"4",rx:".5",fill:M,opacity:".2"}),L.jsx("rect",{x:"7",y:"6",width:"2.5",height:"7",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"11",y:"3",width:"2.5",height:"10",rx:".5",fill:M,opacity:".3"}),L.jsx("rect",{x:"15",y:"5",width:"2.5",height:"8",rx:".5",fill:M,opacity:".2"})]});case"accordion":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1.5",y:"2",width:"17",height:"4",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3",y:"3.5",width:"6",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"1.5",y:"7.5",width:"17",height:"3",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"1.5",y:"12",width:"17",height:"3",rx:"1",stroke:M,strokeWidth:n})]});case"carousel":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"2",width:"14",height:"10",rx:"1",stroke:M,strokeWidth:n}),L.jsx("path",{d:"M1.5 7L3 8.5 1.5 10",stroke:M,strokeWidth:n,opacity:".35"}),L.jsx("path",{d:"M18.5 7L17 8.5 18.5 10",stroke:M,strokeWidth:n,opacity:".35"}),L.jsx("circle",{cx:"8.5",cy:"14",r:".6",fill:M,opacity:".35"}),L.jsx("circle",{cx:"10",cy:"14",r:".6",fill:M,opacity:".15"}),L.jsx("circle",{cx:"11.5",cy:"14",r:".6",fill:M,opacity:".15"})]});case"button":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"5",width:"14",height:"6",rx:"2",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6.5",y:"7.5",width:"7",height:"1",rx:".5",fill:M,opacity:".25"})]});case"input":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"4",width:"5.5",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"2",y:"6.5",width:"16",height:"5.5",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3.5",y:"8.5",width:"7",height:"1",rx:".5",fill:M,opacity:".12"})]});case"search":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"4.5",width:"16",height:"7",rx:"3.5",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"6",cy:"8",r:"2",stroke:M,strokeWidth:n,opacity:".3"}),L.jsx("line",{x1:"7.5",y1:"9.5",x2:"9",y2:"11",stroke:M,strokeWidth:n,opacity:".3"}),L.jsx("rect",{x:"9.5",y:"7.5",width:"6",height:"1",rx:".5",fill:M,opacity:".12"})]});case"form":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"1.5",width:"5.5",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"2",y:"3.5",width:"16",height:"3",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"2",y:"8",width:"7",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"2",y:"10",width:"16",height:"3",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"12",y:"14",width:"6",height:"2",rx:".75",stroke:M,strokeWidth:n})]});case"tabs":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"5",width:"18",height:"10",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"1",y:"2",width:"6",height:"3.5",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"2.5",y:"3.25",width:"3",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"7",y:"2",width:"6",height:"3.5",rx:".75",stroke:M,strokeWidth:n})]});case"dropdown":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"2",width:"16",height:"4",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3.5",y:"3.5",width:"7",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("path",{d:"M15 3.5l1.5 1.5L18 3.5",stroke:M,strokeWidth:n,opacity:".3"}),L.jsx("rect",{x:"2",y:"7",width:"16",height:"7",rx:"1",stroke:M,strokeWidth:n,strokeDasharray:"2 1",opacity:".3"})]});case"toggle":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"4",y:"5",width:"12",height:"6",rx:"3",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"13",cy:"8",r:"2",fill:M,opacity:".3"})]});case"avatar":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("circle",{cx:"10",cy:"8",r:"6",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"10",cy:"6.5",r:"2",stroke:M,strokeWidth:n}),L.jsx("path",{d:"M6.5 13c0-2 1.5-3.5 3.5-3.5s3.5 1.5 3.5 3.5",stroke:M,strokeWidth:n})]});case"badge":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"5",width:"14",height:"6",rx:"3",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6",y:"7.5",width:"8",height:"1",rx:".5",fill:M,opacity:".25"})]});case"breadcrumb":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1.5",y:"7",width:"3.5",height:"1",rx:".5",fill:M,opacity:".3"}),L.jsx("path",{d:"M6.5 7l1 1-1 1",stroke:M,strokeWidth:n,opacity:".2"}),L.jsx("rect",{x:"9",y:"7",width:"3.5",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("path",{d:"M14 7l1 1-1 1",stroke:M,strokeWidth:n,opacity:".2"}),L.jsx("rect",{x:"16.5",y:"7",width:"2",height:"1",rx:".5",fill:M,opacity:".15"})]});case"pagination":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"5.5",width:"3.5",height:"5",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6.5",y:"5.5",width:"3.5",height:"5",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"11",y:"5.5",width:"3.5",height:"5",rx:"1",fill:M,opacity:".15",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"15.5",y:"5.5",width:"3.5",height:"5",rx:"1",stroke:M,strokeWidth:n})]});case"progress":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"7",width:"16",height:"2",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"2",y:"7",width:"10",height:"2",rx:"1",fill:M,opacity:".2"})]});case"toast":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"4",width:"16",height:"8",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"5",cy:"8",r:"1.5",stroke:M,strokeWidth:n,opacity:".3"}),L.jsx("rect",{x:"8",y:"6.5",width:"7",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"8",y:"9",width:"5",height:"1",rx:".5",fill:M,opacity:".12"})]});case"tooltip":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"3",width:"14",height:"7",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5.5",y:"5.5",width:"9",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("path",{d:"M9 10l1 2.5 1-2.5",stroke:M,strokeWidth:n})]});case"pricing":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"1",width:"16",height:"14",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6",y:"3",width:"8",height:"1.5",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"7",y:"5.5",width:"6",height:"2",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"5",y:"9",width:"10",height:"1",rx:".5",fill:M,opacity:".1"}),L.jsx("rect",{x:"5",y:"11",width:"10",height:"1",rx:".5",fill:M,opacity:".1"}),L.jsx("rect",{x:"6",y:"13",width:"8",height:"1.5",rx:".5",fill:M,opacity:".2"})]});case"testimonial":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"1",width:"16",height:"14",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("text",{x:"4",y:"5.5",fontSize:"4",fill:M,opacity:".2",fontFamily:"serif",children:"“"}),L.jsx("rect",{x:"4",y:"7",width:"12",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"4",y:"9",width:"9",height:"1",rx:".5",fill:M,opacity:".12"}),L.jsx("circle",{cx:"5.5",cy:"12.5",r:"1.5",stroke:M,strokeWidth:n,opacity:".25"}),L.jsx("rect",{x:"8",y:"12",width:"5",height:"1",rx:".5",fill:M,opacity:".15"})]});case"cta":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"2",width:"18",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5",y:"4.5",width:"10",height:"1.5",rx:".5",fill:M,opacity:".3"}),L.jsx("rect",{x:"6",y:"7.5",width:"8",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"7",y:"10",width:"6",height:"2.5",rx:"1",stroke:M,strokeWidth:n})]});case"alert":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"4",width:"16",height:"8",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"6",cy:"8",r:"2",stroke:M,strokeWidth:n,opacity:".3"}),L.jsx("line",{x1:"6",y1:"7",x2:"6",y2:"8.5",stroke:M,strokeWidth:"0.6",opacity:".5"}),L.jsx("circle",{cx:"6",cy:"9.3",r:".3",fill:M,opacity:".5"}),L.jsx("rect",{x:"9.5",y:"7",width:"6",height:"1",rx:".5",fill:M,opacity:".2"})]});case"banner":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1",y:"5",width:"18",height:"6",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"4",y:"7.5",width:"8",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"14",y:"7",width:"3.5",height:"2",rx:".75",stroke:M,strokeWidth:n})]});case"stat":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"2",width:"14",height:"12",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6",y:"4.5",width:"8",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"5",y:"7",width:"10",height:"2.5",rx:".5",fill:M,opacity:".3"}),L.jsx("rect",{x:"7",y:"11",width:"6",height:"1",rx:".5",fill:M,opacity:".12"})]});case"stepper":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("circle",{cx:"4",cy:"8",r:"2",fill:M,opacity:".2",stroke:M,strokeWidth:n}),L.jsx("line",{x1:"6",y1:"8",x2:"8",y2:"8",stroke:M,strokeWidth:".4",opacity:".3"}),L.jsx("circle",{cx:"10",cy:"8",r:"2",stroke:M,strokeWidth:n}),L.jsx("line",{x1:"12",y1:"8",x2:"14",y2:"8",stroke:M,strokeWidth:".4",opacity:".3"}),L.jsx("circle",{cx:"16",cy:"8",r:"2",stroke:M,strokeWidth:n})]});case"tag":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"5",width:"14",height:"6",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5.5",y:"7.5",width:"6",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("line",{x1:"14",y1:"6.5",x2:"15.5",y2:"9.5",stroke:M,strokeWidth:n,opacity:".2"}),L.jsx("line",{x1:"15.5",y1:"6.5",x2:"14",y2:"9.5",stroke:M,strokeWidth:n,opacity:".2"})]});case"rating":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("path",{d:"M4 5.5l1 2 2.2.3-1.6 1.5.4 2.2L4 10.3l-2 1.2.4-2.2L.8 7.8 3 7.5z",fill:M,opacity:".25"}),L.jsx("path",{d:"M10 5.5l1 2 2.2.3-1.6 1.5.4 2.2L10 10.3l-2 1.2.4-2.2L6.8 7.8 9 7.5z",fill:M,opacity:".25"}),L.jsx("path",{d:"M16 5.5l1 2 2.2.3-1.6 1.5.4 2.2L16 10.3l-2 1.2.4-2.2-1.6-1.5 2.2-.3z",stroke:M,strokeWidth:n,opacity:".25"})]});case"map":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"2",width:"16",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("line",{x1:"2",y1:"6",x2:"18",y2:"10",stroke:M,strokeWidth:".3",opacity:".15"}),L.jsx("line",{x1:"7",y1:"2",x2:"11",y2:"14",stroke:M,strokeWidth:".3",opacity:".15"}),L.jsx("path",{d:"M10 5c-1.7 0-3 1.3-3 3 0 2.5 3 5 3 5s3-2.5 3-5c0-1.7-1.3-3-3-3z",fill:M,opacity:".15",stroke:M,strokeWidth:n})]});case"timeline":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("line",{x1:"5",y1:"2",x2:"5",y2:"14",stroke:M,strokeWidth:".4",opacity:".25"}),L.jsx("circle",{cx:"5",cy:"4",r:"1.5",fill:M,opacity:".2",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"8",y:"3",width:"8",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("circle",{cx:"5",cy:"8.5",r:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"8",y:"7.5",width:"6",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("circle",{cx:"5",cy:"13",r:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"8",y:"12",width:"7",height:"1",rx:".5",fill:M,opacity:".15"})]});case"fileUpload":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"2",width:"14",height:"12",rx:"1.5",stroke:M,strokeWidth:n,strokeDasharray:"2 1"}),L.jsx("path",{d:"M10 10V5.5m0 0L7.5 8m2.5-2.5L12.5 8",stroke:M,strokeWidth:n,opacity:".3"}),L.jsx("rect",{x:"7",y:"11.5",width:"6",height:"1",rx:".5",fill:M,opacity:".15"})]});case"codeBlock":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"2",width:"16",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"4",cy:"4",r:".6",fill:M,opacity:".3"}),L.jsx("circle",{cx:"5.5",cy:"4",r:".6",fill:M,opacity:".3"}),L.jsx("circle",{cx:"7",cy:"4",r:".6",fill:M,opacity:".3"}),L.jsx("rect",{x:"4",y:"7",width:"7",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("rect",{x:"6",y:"9",width:"5",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"4",y:"11",width:"8",height:"1",rx:".5",fill:M,opacity:".12"})]});case"calendar":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"3",width:"16",height:"12",rx:"1",stroke:M,strokeWidth:n}),L.jsx("line",{x1:"2",y1:"6.5",x2:"18",y2:"6.5",stroke:M,strokeWidth:".4",opacity:".25"}),L.jsx("rect",{x:"5",y:"4",width:"1",height:"1.5",rx:".3",fill:M,opacity:".2"}),L.jsx("rect",{x:"14",y:"4",width:"1",height:"1.5",rx:".3",fill:M,opacity:".2"}),L.jsx("circle",{cx:"7",cy:"9",r:".6",fill:M,opacity:".2"}),L.jsx("circle",{cx:"10",cy:"9",r:".6",fill:M,opacity:".2"}),L.jsx("circle",{cx:"13",cy:"9",r:".6",fill:M,opacity:".3"}),L.jsx("circle",{cx:"7",cy:"12",r:".6",fill:M,opacity:".2"}),L.jsx("circle",{cx:"10",cy:"12",r:".6",fill:M,opacity:".2"})]});case"notification":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"3",width:"16",height:"10",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"5.5",cy:"8",r:"2",stroke:M,strokeWidth:n,opacity:".25"}),L.jsx("rect",{x:"9",y:"6",width:"6",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"9",y:"8.5",width:"4.5",height:"1",rx:".5",fill:M,opacity:".12"}),L.jsx("circle",{cx:"16.5",cy:"4.5",r:"1.5",fill:M,opacity:".25"})]});case"productCard":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"1",width:"14",height:"14",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3",y:"1",width:"14",height:"6",rx:"1",fill:M,opacity:".04"}),L.jsx("rect",{x:"5",y:"8.5",width:"7",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"5",y:"10.5",width:"4",height:"1.5",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"12",y:"12",width:"4",height:"2",rx:".75",stroke:M,strokeWidth:n})]});case"profile":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("circle",{cx:"10",cy:"5",r:"3",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5",y:"10",width:"10",height:"1.5",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"7",y:"12.5",width:"6",height:"1",rx:".5",fill:M,opacity:".12"})]});case"drawer":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"9",y:"1",width:"10",height:"14",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"10.5",y:"4",width:"5",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"10.5",y:"6.5",width:"7",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"10.5",y:"9",width:"6",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"1",y:"1",width:"7",height:"14",rx:"1",stroke:M,strokeWidth:n,opacity:".15"})]});case"popover":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"2",width:"14",height:"9",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5",y:"4.5",width:"8",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"5",y:"7",width:"6",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("path",{d:"M9 11l1 2.5 1-2.5",stroke:M,strokeWidth:n})]});case"logo":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"3",width:"10",height:"10",rx:"2",stroke:M,strokeWidth:n}),L.jsx("path",{d:"M5 9.5l2-4 2 4",stroke:M,strokeWidth:n,opacity:".3"}),L.jsx("rect",{x:"14",y:"6",width:"4",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("rect",{x:"14",y:"8.5",width:"3",height:"1",rx:".5",fill:M,opacity:".12"})]});case"faq":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("text",{x:"2.5",y:"5.5",fontSize:"4",fill:M,opacity:".3",fontWeight:"bold",children:"?"}),L.jsx("rect",{x:"7",y:"3",width:"10",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"7",y:"5.5",width:"8",height:"1",rx:".5",fill:M,opacity:".12"}),L.jsx("text",{x:"2.5",y:"11.5",fontSize:"4",fill:M,opacity:".3",fontWeight:"bold",children:"?"}),L.jsx("rect",{x:"7",y:"9",width:"9",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"7",y:"11.5",width:"7",height:"1",rx:".5",fill:M,opacity:".12"})]});case"gallery":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1.5",y:"1.5",width:"5",height:"5",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"7.5",y:"1.5",width:"5",height:"5",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"13.5",y:"1.5",width:"5",height:"5",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"1.5",y:"9.5",width:"5",height:"5",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"7.5",y:"9.5",width:"5",height:"5",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"13.5",y:"9.5",width:"5",height:"5",rx:".75",stroke:M,strokeWidth:n})]});case"checkbox":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"5",y:"4",width:"8",height:"8",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("path",{d:"M7.5 8l1.5 1.5 3-3",stroke:M,strokeWidth:n,opacity:".35"})]});case"radio":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("circle",{cx:"10",cy:"8",r:"4",stroke:M,strokeWidth:n}),L.jsx("circle",{cx:"10",cy:"8",r:"2",fill:M,opacity:".3"})]});case"slider":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"7.5",width:"16",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"2",y:"7.5",width:"10",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("circle",{cx:"12",cy:"8",r:"2.5",stroke:M,strokeWidth:n})]});case"datePicker":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"1",width:"16",height:"5",rx:"1",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"3.5",y:"3",width:"5",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("rect",{x:"14",y:"2.5",width:"2.5",height:"2",rx:".5",fill:M,opacity:".12"}),L.jsx("rect",{x:"2",y:"7",width:"16",height:"8",rx:"1",stroke:M,strokeWidth:n,strokeDasharray:"2 1",opacity:".3"}),L.jsx("circle",{cx:"6",cy:"10",r:".6",fill:M,opacity:".2"}),L.jsx("circle",{cx:"10",cy:"10",r:".6",fill:M,opacity:".3"}),L.jsx("circle",{cx:"14",cy:"10",r:".6",fill:M,opacity:".2"}),L.jsx("circle",{cx:"6",cy:"13",r:".6",fill:M,opacity:".2"}),L.jsx("circle",{cx:"10",cy:"13",r:".6",fill:M,opacity:".2"})]});case"skeleton":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"2",width:"16",height:"3",rx:"1",fill:M,opacity:".08"}),L.jsx("rect",{x:"2",y:"7",width:"10",height:"2",rx:".75",fill:M,opacity:".08"}),L.jsx("rect",{x:"2",y:"11",width:"13",height:"2",rx:".75",fill:M,opacity:".08"})]});case"chip":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"1.5",y:"5",width:"10",height:"6",rx:"3",fill:M,opacity:".08",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"4",y:"7.5",width:"4",height:"1",rx:".5",fill:M,opacity:".25"}),L.jsx("line",{x1:"9.5",y1:"6.5",x2:"10.5",y2:"9.5",stroke:M,strokeWidth:n,opacity:".2"}),L.jsx("line",{x1:"10.5",y1:"6.5",x2:"9.5",y2:"9.5",stroke:M,strokeWidth:n,opacity:".2"}),L.jsx("rect",{x:"13",y:"5",width:"5.5",height:"6",rx:"3",stroke:M,strokeWidth:n,opacity:".25"})]});case"icon":return L.jsx("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:L.jsx("path",{d:"M10 3l1.5 3 3.5.5-2.5 2.5.5 3.5L10 11l-3 1.5.5-3.5L5 6.5l3.5-.5z",stroke:M,strokeWidth:n,opacity:".3"})});case"spinner":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("circle",{cx:"10",cy:"8",r:"5",stroke:M,strokeWidth:n,opacity:".12"}),L.jsx("path",{d:"M10 3a5 5 0 0 1 5 5",stroke:M,strokeWidth:n,opacity:".35",strokeLinecap:"round"})]});case"feature":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"2",width:"5",height:"5",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("path",{d:"M4.5 3.5v3m-1.5-1.5h3",stroke:M,strokeWidth:n,opacity:".25"}),L.jsx("rect",{x:"9",y:"2.5",width:"8",height:"1.5",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"9",y:"5.5",width:"6",height:"1",rx:".5",fill:M,opacity:".12"}),L.jsx("rect",{x:"2",y:"10",width:"5",height:"5",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"9",y:"10.5",width:"7",height:"1.5",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"9",y:"13.5",width:"5",height:"1",rx:".5",fill:M,opacity:".12"})]});case"team":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("circle",{cx:"5",cy:"5",r:"2.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"2.5",y:"9",width:"5",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("circle",{cx:"15",cy:"5",r:"2.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"12.5",y:"9",width:"5",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("circle",{cx:"10",cy:"5",r:"2.5",stroke:M,strokeWidth:n,opacity:".5"}),L.jsx("rect",{x:"7.5",y:"9",width:"5",height:"1",rx:".5",fill:M,opacity:".15"}),L.jsx("rect",{x:"4",y:"12",width:"12",height:"1",rx:".5",fill:M,opacity:".1"})]});case"login":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"3",y:"1",width:"14",height:"14",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6",y:"3",width:"8",height:"1.5",rx:".5",fill:M,opacity:".25"}),L.jsx("rect",{x:"5",y:"5.5",width:"10",height:"3",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"5",y:"9.5",width:"10",height:"3",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"6.5",y:"13.5",width:"7",height:"2",rx:".75",fill:M,opacity:".2"})]});case"contact":return L.jsxs("svg",{viewBox:"0 0 20 16",width:"20",height:"16",fill:"none",children:[L.jsx("rect",{x:"2",y:"1",width:"16",height:"14",rx:"1.5",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"4",y:"3",width:"5",height:"1",rx:".5",fill:M,opacity:".2"}),L.jsx("rect",{x:"4",y:"5",width:"12",height:"2.5",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"4",y:"8.5",width:"12",height:"4",rx:".75",stroke:M,strokeWidth:n}),L.jsx("rect",{x:"11",y:"13.5",width:"5",height:"1.5",rx:".5",fill:M,opacity:".2"})]});default:return null}}function vF({activeType:J,onSelect:H,onDragStart:Y,scrollRef:K,fadeClass:W,blankCanvas:O}){return L.jsx("div",{ref:K,className:`${Z4.placeScroll} ${W||""}`,children:q3.map((A)=>L.jsxs("div",{className:Z4.paletteSection,children:[L.jsx("div",{className:Z4.paletteSectionTitle,children:A.section}),A.items.map((C)=>L.jsxs("div",{className:`${Z4.paletteItem} ${J===C.type?Z4.active:""} ${O?Z4.wireframe:""}`,onClick:()=>H(C.type),onMouseDown:(x)=>{if(x.button===0)Y(C.type,x)},children:[L.jsx("div",{className:Z4.paletteItemIcon,children:L.jsx(SF,{type:C.type})}),L.jsx("span",{className:Z4.paletteItemLabel,children:C.label})]},C.type))]},A.section))})}function kF({value:J,suffix:H}){let[Y,K]=hZ.useState(null),[W,O]=hZ.useState(H),[A,C]=hZ.useState("up"),x=hZ.useRef(J),J4=hZ.useRef(H),b=hZ.useRef(),g=Y!==null&&W!==H;if(hZ.useEffect(()=>{if(J!==x.current){if(J===0){x.current=J,J4.current=H,K(null);return}C(J>x.current?"up":"down"),K(x.current),O(J4.current),x.current=J,J4.current=H,clearTimeout(b.current),b.current=q7(()=>K(null),250)}else J4.current=H},[J,H]),Y===null)return L.jsxs(L.Fragment,{children:[J,H?` ${H}`:""]});if(g)return L.jsxs("span",{className:Z4.rollingWrap,children:[L.jsxs("span",{style:{visibility:"hidden"},children:[J," ",H]}),L.jsxs("span",{className:`${Z4.rollingNum} ${A==="up"?Z4.exitUp:Z4.exitDown}`,children:[Y," ",W]},`o${Y}-${J}`),L.jsxs("span",{className:`${Z4.rollingNum} ${A==="up"?Z4.enterUp:Z4.enterDown}`,children:[J," ",H]},`n${J}`)]});return L.jsxs(L.Fragment,{children:[L.jsxs("span",{className:Z4.rollingWrap,children:[L.jsx("span",{style:{visibility:"hidden"},children:J}),L.jsx("span",{className:`${Z4.rollingNum} ${A==="up"?Z4.exitUp:Z4.exitDown}`,children:Y},`o${Y}-${J}`),L.jsx("span",{className:`${Z4.rollingNum} ${A==="up"?Z4.enterUp:Z4.enterDown}`,children:J},`n${J}`)]}),H?` ${H}`:""]})}function yF({activeType:J,onSelect:H,isDarkMode:Y,sectionCount:K,onDetectSections:W,visible:O,onExited:A,placementCount:C,onClearPlacements:x,onDragStart:J4,blankCanvas:b,onBlankCanvasChange:g,wireframePurpose:R,onWireframePurposeChange:o,Tooltip:p}){let[q4,h]=hZ.useState(!1),[t,I4]=hZ.useState("exit"),[u4,i4]=hZ.useState(!1),[g7,h7]=hZ.useState(!0),T4=hZ.useRef(0),p4=hZ.useRef(""),N7=hZ.useRef(0),Y4=hZ.useRef(),l4=hZ.useRef(null),[d4,b4]=hZ.useState("");hZ.useEffect(()=>{if(O)h(!0),clearTimeout(Y4.current),cancelAnimationFrame(N7.current),N7.current=C0(()=>{N7.current=C0(()=>{I4("enter")})});else cancelAnimationFrame(N7.current),I4("exit"),clearTimeout(Y4.current),Y4.current=q7(()=>{h(!1),A?.()},200);return()=>cancelAnimationFrame(N7.current)},[O]);let n4=C>0||K>0,B4=C+K;if(B4>0)T4.current=B4,p4.current=b?B4===1?"Component":"Components":B4===1?"Change":"Changes";if(hZ.useEffect(()=>{if(n4)if(!u4)h7(!0),i4(!0),C0(()=>{C0(()=>{h7(!1)})});else h7(!1);else{h7(!0);let O4=q7(()=>i4(!1),300);return()=>clearTimeout(O4)}},[n4]),hZ.useEffect(()=>{if(!q4)return;let O4=l4.current;if(!O4)return;let $4=()=>b4(xF(O4));$4(),O4.addEventListener("scroll",$4,{passive:!0});let C4=new ResizeObserver($4);return C4.observe(O4),()=>{O4.removeEventListener("scroll",$4),C4.disconnect()}},[q4]),!q4)return null;let L4=[];if(C>0)L4.push("placed");if(K>0)L4.push("captured");return L.jsxs("div",{className:`${Z4.palette} ${Z4[t]} ${!Y?Z4.light:""}`,"data-feedback-toolbar":!0,"data-agentation-palette":!0,onClick:(O4)=>O4.stopPropagation(),onMouseDown:(O4)=>O4.stopPropagation(),onTransitionEnd:(O4)=>{if(O4.target!==O4.currentTarget)return;if(!O)clearTimeout(Y4.current),h(!1),I4("exit"),A?.()},children:[L.jsxs("div",{className:Z4.paletteHeader,children:[L.jsx("div",{className:Z4.paletteHeaderTitle,children:"Layout Mode"}),L.jsxs("div",{className:Z4.paletteHeaderDesc,children:["Rearrange and resize existing elements, add new components, and explore layout ideas. Agent results may vary."," ",L.jsx("a",{href:"https://agentation.dev/features#layout-mode",target:"_blank",rel:"noopener noreferrer",children:"Learn more."})]})]}),L.jsxs("div",{className:`${Z4.canvasToggle} ${b?Z4.active:""}`,onClick:()=>g(!b),children:[L.jsx("span",{className:Z4.canvasToggleIcon,children:L.jsxs("svg",{viewBox:"0 0 14 14",width:"14",height:"14",fill:"none",children:[L.jsx("rect",{x:"1",y:"1",width:"12",height:"12",rx:"2",stroke:"currentColor",strokeWidth:"1"}),L.jsx("circle",{cx:"4.5",cy:"4.5",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"7",cy:"4.5",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"9.5",cy:"4.5",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"4.5",cy:"7",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"7",cy:"7",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"9.5",cy:"7",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"4.5",cy:"9.5",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"7",cy:"9.5",r:"0.8",fill:"currentColor",opacity:".6"}),L.jsx("circle",{cx:"9.5",cy:"9.5",r:"0.8",fill:"currentColor",opacity:".6"})]})}),L.jsx("span",{className:Z4.canvasToggleLabel,children:"Wireframe New Page"})]}),L.jsx("div",{className:`${Z4.wireframePurposeWrap} ${!b?Z4.collapsed:""}`,children:L.jsx("div",{className:Z4.wireframePurposeInner,children:L.jsx("textarea",{className:Z4.wireframePurposeInput,placeholder:"Describe this page to provide additional context for your agent.",value:R,onChange:(O4)=>o(O4.target.value),rows:2})})}),L.jsx(vF,{activeType:J,onSelect:H,onDragStart:J4,scrollRef:l4,fadeClass:d4,blankCanvas:b}),u4&&L.jsx("div",{className:`${Z4.paletteFooterWrap} ${g7?Z4.footerHidden:""}`,children:L.jsx("div",{className:Z4.paletteFooterInner,children:L.jsx("div",{className:Z4.paletteFooterInnerContent,children:L.jsxs("div",{className:Z4.paletteFooter,children:[L.jsx("span",{className:Z4.paletteFooterCount,children:L.jsx(kF,{value:T4.current,suffix:p4.current})}),L.jsx("button",{className:Z4.paletteFooterClear,onClick:x,children:"Clear"})]})})})})]})}function I0(J){if(J.parentElement)return J.parentElement;let H=J.getRootNode();if(H instanceof ShadowRoot)return H.host;return null}function t2(J,H){let Y=J;while(Y){if(Y.matches(H))return Y;Y=I0(Y)}return null}function gF(J,H=4){let Y=[],K=J,W=0;while(K&&W<H){let O=K.tagName.toLowerCase();if(O==="html"||O==="body")break;let A=O;if(K.id)A=`#${K.id}`;else if(K.className&&typeof K.className==="string"){let x=K.className.split(/\s+/).find((J4)=>J4.length>2&&!J4.match(/^[a-z]{1,2}$/)&&!J4.match(/[A-Z0-9]{5,}/));if(x)A=`.${x.split("_")[0]}`}let C=I0(K);if(!K.parentElement&&C)A=`⟨shadow⟩ ${A}`;Y.unshift(A),K=C,W++}return Y.join(" > ")}function T0(J){let H=gF(J);if(J.dataset.element)return{name:J.dataset.element,path:H};let Y=J.tagName.toLowerCase();if(["path","circle","rect","line","g"].includes(Y)){let K=t2(J,"svg");if(K){let W=I0(K);if(W instanceof HTMLElement)return{name:`graphic in ${T0(W).name}`,path:H}}return{name:"graphic element",path:H}}if(Y==="svg"){let K=I0(J);if(K?.tagName.toLowerCase()==="button"){let W=K.textContent?.trim();return{name:W?`icon in "${W}" button`:"button icon",path:H}}return{name:"icon",path:H}}if(Y==="button"){let K=J.textContent?.trim(),W=J.getAttribute("aria-label");if(W)return{name:`button [${W}]`,path:H};return{name:K?`button "${K.slice(0,25)}"`:"button",path:H}}if(Y==="a"){let K=J.textContent?.trim(),W=J.getAttribute("href");if(K)return{name:`link "${K.slice(0,25)}"`,path:H};if(W)return{name:`link to ${W.slice(0,30)}`,path:H};return{name:"link",path:H}}if(Y==="input"){let K=J.getAttribute("type")||"text",W=J.getAttribute("placeholder"),O=J.getAttribute("name");if(W)return{name:`input "${W}"`,path:H};if(O)return{name:`input [${O}]`,path:H};return{name:`${K} input`,path:H}}if(["h1","h2","h3","h4","h5","h6"].includes(Y)){let K=J.textContent?.trim();return{name:K?`${Y} "${K.slice(0,35)}"`:Y,path:H}}if(Y==="p"){let K=J.textContent?.trim();if(K)return{name:`paragraph: "${K.slice(0,40)}${K.length>40?"...":""}"`,path:H};return{name:"paragraph",path:H}}if(Y==="span"||Y==="label"){let K=J.textContent?.trim();if(K&&K.length<40)return{name:`"${K}"`,path:H};return{name:Y,path:H}}if(Y==="li"){let K=J.textContent?.trim();if(K&&K.length<40)return{name:`list item: "${K.slice(0,35)}"`,path:H};return{name:"list item",path:H}}if(Y==="blockquote")return{name:"blockquote",path:H};if(Y==="code"){let K=J.textContent?.trim();if(K&&K.length<30)return{name:`code: \`${K}\``,path:H};return{name:"code",path:H}}if(Y==="pre")return{name:"code block",path:H};if(Y==="img"){let K=J.getAttribute("alt");return{name:K?`image "${K.slice(0,30)}"`:"image",path:H}}if(Y==="video")return{name:"video",path:H};if(["div","section","article","nav","header","footer","aside","main"].includes(Y)){let K=J.className,W=J.getAttribute("role"),O=J.getAttribute("aria-label");if(O)return{name:`${Y} [${O}]`,path:H};if(W)return{name:`${W}`,path:H};if(typeof K==="string"&&K){let A=K.split(/[\s_-]+/).map((C)=>C.replace(/[A-Z0-9]{5,}.*$/,"")).filter((C)=>C.length>2&&!/^[a-z]{1,2}$/.test(C)).slice(0,2);if(A.length>0)return{name:A.join(" "),path:H}}return{name:Y==="div"?"container":Y,path:H}}return{name:Y,path:H}}function UB(J){let H=[],Y=J.textContent?.trim();if(Y&&Y.length<100)H.push(Y);let K=J.previousElementSibling;if(K){let O=K.textContent?.trim();if(O&&O.length<50)H.unshift(`[before: "${O.slice(0,40)}"]`)}let W=J.nextElementSibling;if(W){let O=W.textContent?.trim();if(O&&O.length<50)H.push(`[after: "${O.slice(0,40)}"]`)}return H.join(" ")}function bz(J){let H=I0(J);if(!H)return"";let W=(J.getRootNode()instanceof ShadowRoot&&J.parentElement?Array.from(J.parentElement.children):Array.from(H.children)).filter((b)=>b!==J&&b instanceof HTMLElement);if(W.length===0)return"";let O=W.slice(0,4).map((b)=>{let g=b.tagName.toLowerCase(),R=b.className,o="";if(typeof R==="string"&&R){let p=R.split(/\s+/).map((q4)=>q4.replace(/[_][a-zA-Z0-9]{5,}.*$/,"")).find((q4)=>q4.length>2&&!/^[a-z]{1,2}$/.test(q4));if(p)o=`.${p}`}if(g==="button"||g==="a"){let p=b.textContent?.trim().slice(0,15);if(p)return`${g}${o} "${p}"`}return`${g}${o}`}),C=H.tagName.toLowerCase();if(typeof H.className==="string"&&H.className){let b=H.className.split(/\s+/).map((g)=>g.replace(/[_][a-zA-Z0-9]{5,}.*$/,"")).find((g)=>g.length>2&&!/^[a-z]{1,2}$/.test(g));if(b)C=`.${b}`}let x=H.children.length,J4=x>O.length+1?` (${x} total in ${C})`:"";return O.join(", ")+J4}function VB(J){let H=J.className;if(typeof H!=="string"||!H)return"";return H.split(/\s+/).filter((K)=>K.length>0).map((K)=>{let W=K.match(/^([a-zA-Z][a-zA-Z0-9_-]*?)(?:_[a-zA-Z0-9]{5,})?$/);return W?W[1]:K}).filter((K,W,O)=>O.indexOf(K)===W).join(", ")}var H3=new Set(["none","normal","auto","0px","rgba(0, 0, 0, 0)","transparent","static","visible"]),bF=new Set(["p","span","h1","h2","h3","h4","h5","h6","label","li","td","th","blockquote","figcaption","caption","legend","dt","dd","pre","code","em","strong","b","i","a","time","cite","q"]),fF=new Set(["input","textarea","select"]),mF=new Set(["img","video","canvas","svg"]),hF=new Set(["div","section","article","nav","header","footer","aside","main","ul","ol","form","fieldset"]);function fz(J){if(typeof window>"u")return{};let H=window.getComputedStyle(J),Y={},K=J.tagName.toLowerCase(),W;if(bF.has(K))W=["color","fontSize","fontWeight","fontFamily","lineHeight"];else if(K==="button"||K==="a"&&J.getAttribute("role")==="button")W=["backgroundColor","color","padding","borderRadius","fontSize"];else if(fF.has(K))W=["backgroundColor","color","padding","borderRadius","fontSize"];else if(mF.has(K))W=["width","height","objectFit","borderRadius"];else if(hF.has(K))W=["display","padding","margin","gap","backgroundColor"];else W=["color","fontSize","margin","padding","backgroundColor"];for(let O of W){let A=O.replace(/([A-Z])/g,"-$1").toLowerCase(),C=H.getPropertyValue(A);if(C&&!H3.has(C))Y[O]=C}return Y}var uF=["color","backgroundColor","borderColor","fontSize","fontWeight","fontFamily","lineHeight","letterSpacing","textAlign","width","height","padding","margin","border","borderRadius","display","position","top","right","bottom","left","zIndex","flexDirection","justifyContent","alignItems","gap","opacity","visibility","overflow","boxShadow","transform"];function mz(J){if(typeof window>"u")return"";let H=window.getComputedStyle(J),Y=[];for(let K of uF){let W=K.replace(/([A-Z])/g,"-$1").toLowerCase(),O=H.getPropertyValue(W);if(O&&!H3.has(O))Y.push(`${W}: ${O}`)}return Y.join("; ")}function dF(J){if(!J)return;let H={},Y=J.split(";").map((K)=>K.trim()).filter(Boolean);for(let K of Y){let W=K.indexOf(":");if(W>0){let O=K.slice(0,W).trim(),A=K.slice(W+1).trim();if(O&&A)H[O]=A}}return Object.keys(H).length>0?H:void 0}function hz(J){let H=[],Y=J.getAttribute("role"),K=J.getAttribute("aria-label"),W=J.getAttribute("aria-describedby"),O=J.getAttribute("tabindex"),A=J.getAttribute("aria-hidden");if(Y)H.push(`role="${Y}"`);if(K)H.push(`aria-label="${K}"`);if(W)H.push(`aria-describedby="${W}"`);if(O)H.push(`tabindex=${O}`);if(A==="true")H.push("aria-hidden");if(J.matches("a, button, input, select, textarea, [tabindex]"))H.push("focusable");return H.join(", ")}function uz(J){let H=[],Y=J;while(Y&&Y.tagName.toLowerCase()!=="html"){let K=Y.tagName.toLowerCase(),W=K;if(Y.id)W=`${K}#${Y.id}`;else if(Y.className&&typeof Y.className==="string"){let A=Y.className.split(/\s+/).map((C)=>C.replace(/[_][a-zA-Z0-9]{5,}.*$/,"")).find((C)=>C.length>2);if(A)W=`${K}.${A}`}let O=I0(Y);if(!Y.parentElement&&O)W=`⟨shadow⟩ ${W}`;H.unshift(W),Y=O}return H.join(" > ")}var pF=new Set(["nav","header","main","section","article","footer","aside"]),DH={banner:"Header",navigation:"Navigation",main:"Main Content",contentinfo:"Footer",complementary:"Sidebar",region:"Section"},g_={nav:"Navigation",header:"Header",main:"Main Content",section:"Section",article:"Article",footer:"Footer",aside:"Sidebar"},cF=new Set(["script","style","noscript","link","meta"]),lF=40;function X3(J){let H=J;while(H&&H!==document.body&&H!==document.documentElement){let Y=window.getComputedStyle(H).position;if(Y==="fixed"||Y==="sticky")return!0;H=H.parentElement}return!1}function HG(J){let H=J.tagName.toLowerCase();if(["nav","header","footer","main"].includes(H)){if(document.querySelectorAll(H).length===1)return H}if(J.id)return`#${CSS.escape(J.id)}`;if(J.className&&typeof J.className==="string"){let W=J.className.split(/\s+/).filter((O)=>O.length>0).find((O)=>O.length>2&&!/^[a-zA-Z0-9]{6,}$/.test(O)&&!/^[a-z]{1,2}$/.test(O));if(W){let O=`${H}.${CSS.escape(W)}`;if(document.querySelectorAll(O).length===1)return O}}let Y=J.parentElement;if(Y){let W=Array.from(Y.children).indexOf(J)+1;return`${Y===document.body?"body":HG(Y)} > ${H}:nth-child(${W})`}return H}function oz(J){let H=J.tagName.toLowerCase(),Y=J.getAttribute("aria-label");if(Y)return Y;let K=J.getAttribute("role");if(K&&DH[K])return DH[K];if(g_[H])return g_[H];let W=J.querySelector("h1, h2, h3, h4, h5, h6");if(W){let A=W.textContent?.trim();if(A&&A.length<=50)return A;if(A)return A.slice(0,47)+"..."}let{name:O}=T0(J);return O.charAt(0).toUpperCase()+O.slice(1)}function Y3(J){let H=J.className;if(typeof H!=="string"||!H)return null;return H.split(/\s+/).map((K)=>K.replace(/[_][a-zA-Z0-9]{5,}.*$/,"")).find((K)=>K.length>2&&!/^[a-z]{1,2}$/.test(K))||null}function j3(J){let H=J.textContent?.trim();if(!H)return null;let Y=H.replace(/\s+/g," ");if(Y.length<=30)return Y;return Y.slice(0,30)+"…"}function sF(){let J=document.querySelector("main")||document.body,H=Array.from(J.children),Y=H;if(J!==document.body&&H.length<3)Y=Array.from(document.body.children);let K=[];return Y.forEach((W,O)=>{if(!(W instanceof HTMLElement))return;let A=W.tagName.toLowerCase();if(cF.has(A))return;if(W.hasAttribute("data-feedback-toolbar"))return;if(W.closest("[data-feedback-toolbar]"))return;let C=window.getComputedStyle(W);if(C.display==="none"||C.visibility==="hidden")return;let x=W.getBoundingClientRect();if(x.height<lF)return;let J4=pF.has(A),b=W.getAttribute("role")&&DH[W.getAttribute("role")],g=A==="div"&&x.height>=60;if(!J4&&!b&&!g)return;let R=window.scrollY,o=X3(W),p={x:x.x,y:o?x.y:x.y+R,width:x.width,height:x.height};K.push({id:`rs-${Date.now()}-${Math.random().toString(36).slice(2,7)}`,label:oz(W),tagName:A,selector:HG(W),role:W.getAttribute("role"),className:Y3(W),textSnippet:j3(W),originalRect:p,currentRect:{...p},originalIndex:O,isFixed:o})}),K}function aF(J){let H=window.scrollY,Y=J.getBoundingClientRect(),K=X3(J),W={x:Y.x,y:K?Y.y:Y.y+H,width:Y.width,height:Y.height},O=J.parentElement,A=0;if(O)A=Array.from(O.children).indexOf(J);return{id:`rs-${Date.now()}-${Math.random().toString(36).slice(2,7)}`,label:oz(J),tagName:J.tagName.toLowerCase(),selector:HG(J),role:J.getAttribute("role"),className:Y3(J),textSnippet:j3(J),originalRect:W,currentRect:{...W},originalIndex:A,isFixed:K}}var b_={bg:"rgba(59, 130, 246, 0.08)",border:"rgba(59, 130, 246, 0.5)",pill:"#3b82f6"},f_=["nw","n","ne","e","se","s","sw","w"],dz=24,m_=16,pz=5;function h_(J,H,Y,K){let W=1/0,O=1/0,A=J.x,C=J.x+J.width,x=J.x+J.width/2,J4=J.y,b=J.y+J.height,g=J.y+J.height/2,R=[];for(let T4 of H)if(!Y.has(T4.id))R.push(T4.currentRect);if(K)R.push(...K);for(let T4 of R){let p4=T4.x,N7=T4.x+T4.width,Y4=T4.x+T4.width/2,l4=T4.y,d4=T4.y+T4.height,b4=T4.y+T4.height/2;for(let n4 of[A,C,x])for(let B4 of[p4,N7,Y4]){let L4=B4-n4;if(Math.abs(L4)<pz&&Math.abs(L4)<Math.abs(W))W=L4}for(let n4 of[J4,b,g])for(let B4 of[l4,d4,b4]){let L4=B4-n4;if(Math.abs(L4)<pz&&Math.abs(L4)<Math.abs(O))O=L4}}let o=Math.abs(W)<pz?W:0,p=Math.abs(O)<pz?O:0,q4=[],h=new Set,t=A+o,I4=C+o,u4=x+o,i4=J4+p,g7=b+p,h7=g+p;for(let T4 of R){let p4=T4.x,N7=T4.x+T4.width,Y4=T4.x+T4.width/2,l4=T4.y,d4=T4.y+T4.height,b4=T4.y+T4.height/2;for(let n4 of[p4,Y4,N7])for(let B4 of[t,u4,I4])if(Math.abs(B4-n4)<0.5){let L4=`x:${Math.round(n4)}`;if(!h.has(L4))h.add(L4),q4.push({axis:"x",pos:n4})}for(let n4 of[l4,b4,d4])for(let B4 of[i4,h7,g7])if(Math.abs(B4-n4)<0.5){let L4=`y:${Math.round(n4)}`;if(!h.has(L4))h.add(L4),q4.push({axis:"y",pos:n4})}}return{dx:o,dy:p,guides:q4}}var iF=new Set(["script","style","noscript","link","meta","br","hr"]);function u_(J){let H=J;while(H&&H!==document.body&&H!==document.documentElement){if(H.closest("[data-feedback-toolbar]"))return null;if(iF.has(H.tagName.toLowerCase())){H=H.parentElement;continue}let Y=H.getBoundingClientRect();if(Y.width>=m_&&Y.height>=m_)return H;H=H.parentElement}return null}function oF({rearrangeState:J,onChange:H,isDarkMode:Y,exiting:K,className:W,blankCanvas:O,extraSnapRects:A,onSelectionChange:C,deselectSignal:x,onDragMove:J4,onDragEnd:b,clearSignal:g}){let{sections:R}=J,o=F7.useRef(J);o.current=J;let[p,q4]=F7.useState(new Set),[h,t]=F7.useState(!1),I4=F7.useRef(g);F7.useEffect(()=>{if(g!==void 0&&g!==I4.current){if(I4.current=g,R.length>0)t(!0)}},[g,R.length]);let u4=F7.useRef(x);F7.useEffect(()=>{if(x!==u4.current)u4.current=x,q4(new Set)},[x]);let[i4,g7]=F7.useState(null),[h7,T4]=F7.useState(!1),p4=F7.useRef(!1),N7=F7.useCallback((f)=>{let u=R.find((G4)=>G4.id===f);if(!u)return;p4.current=!!u.note,g7(f),T4(!1)},[R]),Y4=F7.useCallback(()=>{if(!i4)return;T4(!0),q7(()=>{g7(null),T4(!1)},150)},[i4]),l4=F7.useCallback((f)=>{if(!i4)return;H({...J,sections:R.map((u)=>u.id===i4?{...u,note:f.trim()||void 0}:u)}),Y4()},[i4,R,J,H,Y4]);F7.useEffect(()=>{if(K&&i4)Y4()},[K]);let[d4,b4]=F7.useState(new Set),n4=F7.useRef(new Map),[B4,L4]=F7.useState(null),[O4,$4]=F7.useState(null),[C4,R7]=F7.useState([]),[s,c4]=F7.useState(0),Q7=F7.useRef(null),W7=F7.useRef(new Set),EZ=F7.useRef(new Map),[I2,u7]=F7.useState(new Map),[AZ,eZ]=F7.useState(new Map),Z5=F7.useRef(new Set),M4=F7.useRef(new Map),_2=F7.useRef(C);_2.current=C;let uZ=F7.useRef(J4);uZ.current=J4;let Y2=F7.useRef(b);Y2.current=b,F7.useEffect(()=>{if(O)q4(new Set)},[O]);let[qZ,s7]=F7.useState(()=>!J.sections.some((f)=>{let{originalRect:u,currentRect:G4}=f;return Math.abs(u.x-G4.x)>1||Math.abs(u.y-G4.y)>1||Math.abs(u.width-G4.width)>1||Math.abs(u.height-G4.height)>1}));F7.useEffect(()=>{if(!qZ){let f=q7(()=>s7(!0),380);return()=>clearTimeout(f)}},[]);let M2=F7.useRef(new Set);F7.useEffect(()=>{M2.current=new Set(R.map((f)=>f.selector))},[R]),F7.useEffect(()=>{let f=()=>c4(window.scrollY);return f(),window.addEventListener("scroll",f,{passive:!0}),window.addEventListener("resize",f,{passive:!0}),()=>{window.removeEventListener("scroll",f),window.removeEventListener("resize",f)}},[]),F7.useEffect(()=>{let f=(u)=>{if(Q7.current){L4(null);return}let G4=document.elementFromPoint(u.clientX,u.clientY);if(!G4){L4(null);return}if(G4.closest("[data-feedback-toolbar]")){L4(null);return}if(G4.closest("[data-design-placement]")){L4(null);return}if(G4.closest("[data-annotation-popup]")){L4(null);return}let z4=u_(G4);if(!z4){L4(null);return}for(let m4 of M2.current)try{let j4=document.querySelector(m4);if(j4&&(j4===z4||z4.contains(j4))){L4(null);return}}catch{}let S4=z4.getBoundingClientRect();L4({x:S4.x,y:S4.y,w:S4.width,h:S4.height})};return document.addEventListener("mousemove",f,{passive:!0}),()=>document.removeEventListener("mousemove",f)},[R]),F7.useEffect(()=>{let f=document.body.style.userSelect;return document.body.style.userSelect="none",()=>{document.body.style.userSelect=f}},[]),F7.useEffect(()=>{let f=(u)=>{if(Q7.current)return;if(u.button!==0)return;let G4=u.target;if(!G4||G4.closest("[data-feedback-toolbar]"))return;if(G4.closest("[data-design-placement]"))return;if(G4.closest("[data-annotation-popup]"))return;let z4=u_(G4),S4=!1;if(z4)for(let j4 of M2.current)try{let _=document.querySelector(j4);if(_&&(_===z4||z4.contains(_))){S4=!0;break}}catch{}let m4=!!(u.shiftKey||u.metaKey||u.ctrlKey);if(z4&&!S4){u.preventDefault(),u.stopPropagation();let j4=aF(z4),_=[...R,j4],E=[...J.originalOrder,j4.id];H({...J,sections:_,originalOrder:E});let a=new Set([j4.id]);q4(a),_2.current?.(a,m4),L4(null);let{clientX:H4,clientY:e}=u,x4={x:j4.currentRect.x,y:j4.currentRect.y},F4=j4.originalRect,E4=!1,Q4=0,M7=0;Q7.current="move";let U7=(f7)=>{let X7=f7.clientX-H4,e7=f7.clientY-e;if(!E4&&(Math.abs(X7)>2||Math.abs(e7)>2))E4=!0;if(!E4)return;let kZ={x:x4.x+X7,y:x4.y+e7,width:j4.currentRect.width,height:j4.currentRect.height},dZ=h_(kZ,_,new Set([j4.id]),A);R7(dZ.guides);let yZ=X7+dZ.dx,N2=e7+dZ.dy;Q4=yZ,M7=N2;let t5=document.querySelector(`[data-rearrange-section="${j4.id}"]`);if(t5)t5.style.transform=`translate(${yZ}px, ${N2}px)`;u7(new Map([[j4.id,{x:x4.x+yZ,y:x4.y+N2,width:j4.currentRect.width,height:j4.currentRect.height}]])),uZ.current?.(yZ,N2)},H7=()=>{window.removeEventListener("mousemove",U7),window.removeEventListener("mouseup",H7),Q7.current=null,R7([]),u7(new Map);let f7=document.querySelector(`[data-rearrange-section="${j4.id}"]`);if(f7)f7.style.transform="";if(E4)H({...J,sections:_.map((X7)=>X7.id===j4.id?{...X7,currentRect:{...X7.currentRect,x:Math.max(0,x4.x+Q4),y:Math.max(0,x4.y+M7)}}:X7),originalOrder:E});Y2.current?.(Q4,M7,E4)};window.addEventListener("mousemove",U7),window.addEventListener("mouseup",H7)}else if(S4&&z4){u.preventDefault();for(let j4 of R)try{let _=document.querySelector(j4.selector);if(_&&_===z4){let E=new Set([j4.id]);q4(E),_2.current?.(E,m4);return}}catch{}if(!m4)q4(new Set),_2.current?.(new Set,!1)}else if(!m4)q4(new Set),_2.current?.(new Set,!1)};return document.addEventListener("mousedown",f,!0),()=>document.removeEventListener("mousedown",f,!0)},[R,J,H]),F7.useEffect(()=>{let f=(u)=>{let G4=u.target;if(G4.tagName==="INPUT"||G4.tagName==="TEXTAREA"||G4.isContentEditable)return;if((u.key==="Backspace"||u.key==="Delete")&&p.size>0){u.preventDefault();let z4=new Set(p);b4((S4)=>{let m4=new Set(S4);for(let j4 of z4)m4.add(j4);return m4}),q4(new Set),q7(()=>{let S4=o.current;H({...S4,sections:S4.sections.filter((m4)=>!z4.has(m4.id)),originalOrder:S4.originalOrder.filter((m4)=>!z4.has(m4))}),b4((m4)=>{let j4=new Set(m4);for(let _ of z4)j4.delete(_);return j4})},180);return}if(["ArrowUp","ArrowDown","ArrowLeft","ArrowRight"].includes(u.key)&&p.size>0){u.preventDefault();let z4=u.shiftKey?20:1,S4=u.key==="ArrowLeft"?-z4:u.key==="ArrowRight"?z4:0,m4=u.key==="ArrowUp"?-z4:u.key==="ArrowDown"?z4:0;H({...J,sections:R.map((j4)=>p.has(j4.id)?{...j4,currentRect:{...j4.currentRect,x:Math.max(0,j4.currentRect.x+S4),y:Math.max(0,j4.currentRect.y+m4)}}:j4)});return}if(u.key==="Escape"&&p.size>0)q4(new Set)};return document.addEventListener("keydown",f),()=>document.removeEventListener("keydown",f)},[p,R,J,H]);let N4=F7.useCallback((f,u)=>{if(f.button!==0)return;let G4=f.target;if(G4.closest(`.${Z4.handle}`)||G4.closest(`.${Z4.deleteButton}`))return;f.preventDefault(),f.stopPropagation();let z4;if(f.shiftKey||f.metaKey||f.ctrlKey)if(z4=new Set(p),z4.has(u))z4.delete(u);else z4.add(u);else if(!p.has(u))z4=new Set([u]);else z4=new Set(p);if(q4(z4),z4.size!==p.size||[...z4].some((E4)=>!p.has(E4)))_2.current?.(z4,!!(f.shiftKey||f.metaKey||f.ctrlKey));let{clientX:m4,clientY:j4}=f,_=new Map;for(let E4 of R)if(z4.has(E4.id))_.set(E4.id,{x:E4.currentRect.x,y:E4.currentRect.y});Q7.current="move";let E=!1,a=0,H4=0,e=new Map;for(let E4 of R)if(z4.has(E4.id)){let Q4=document.querySelector(`[data-rearrange-section="${E4.id}"]`);e.set(E4.id,{outlineEl:Q4,curW:E4.currentRect.width,curH:E4.currentRect.height})}let x4=(E4)=>{let Q4=E4.clientX-m4,M7=E4.clientY-j4;if(Q4===0&&M7===0)return;E=!0;let U7=1/0,H7=1/0,f7=-1/0,X7=-1/0;for(let[N2,{curW:t5,curH:P8}]of e){let wZ=_.get(N2);if(!wZ)continue;let G5=wZ.x+Q4,D2=wZ.y+M7;U7=Math.min(U7,G5),H7=Math.min(H7,D2),f7=Math.max(f7,G5+t5),X7=Math.max(X7,D2+P8)}let e7=h_({x:U7,y:H7,width:f7-U7,height:X7-H7},R,z4,A),kZ=Q4+e7.dx,dZ=M7+e7.dy;a=kZ,H4=dZ,R7(e7.guides);for(let[,{outlineEl:N2}]of e)if(N2)N2.style.transform=`translate(${kZ}px, ${dZ}px)`;let yZ=new Map;for(let[N2,{curW:t5,curH:P8}]of e){let wZ=_.get(N2);if(wZ){let G5={x:Math.max(0,wZ.x+kZ),y:Math.max(0,wZ.y+dZ),width:t5,height:P8};yZ.set(N2,G5)}}u7(yZ),uZ.current?.(kZ,dZ)},F4=(E4)=>{window.removeEventListener("mousemove",x4),window.removeEventListener("mouseup",F4),Q7.current=null,R7([]),u7(new Map);for(let[,{outlineEl:Q4}]of e)if(Q4)Q4.style.transform="";if(E){let Q4=E4.clientX-m4,M7=E4.clientY-j4;if(Math.abs(Q4)<5&&Math.abs(M7)<5)H({...J,sections:R.map((U7)=>{let H7=_.get(U7.id);if(!H7)return U7;return{...U7,currentRect:{...U7.currentRect,x:H7.x,y:H7.y}}})});else{H({...J,sections:R.map((U7)=>{let H7=_.get(U7.id);if(!H7)return U7;return{...U7,currentRect:{...U7.currentRect,x:Math.max(0,H7.x+a),y:Math.max(0,H7.y+H4)}}})}),Y2.current?.(a,H4,!0);return}}Y2.current?.(0,0,!1)};window.addEventListener("mousemove",x4),window.addEventListener("mouseup",F4)},[p,R,J,H]),U4=F7.useCallback((f,u,G4)=>{f.preventDefault(),f.stopPropagation();let z4=R.find((F4)=>F4.id===u);if(!z4)return;q4(new Set([u])),Q7.current="resize";let{clientX:S4,clientY:m4}=f,j4={...z4.currentRect},_=z4.originalRect,E=j4.width/j4.height,a={...j4},H4=document.querySelector(`[data-rearrange-section="${u}"]`),e=(F4)=>{let E4=F4.clientX-S4,Q4=F4.clientY-m4,M7=j4.x,U7=j4.y,H7=j4.width,f7=j4.height;if(G4.includes("e"))H7=Math.max(dz,j4.width+E4);if(G4.includes("w"))H7=Math.max(dz,j4.width-E4),M7=j4.x+j4.width-H7;if(G4.includes("s"))f7=Math.max(dz,j4.height+Q4);if(G4.includes("n"))f7=Math.max(dz,j4.height-Q4),U7=j4.y+j4.height-f7;if(F4.shiftKey)if(G4.length===2){let e7=Math.abs(H7-j4.width),kZ=Math.abs(f7-j4.height);if(e7>kZ)f7=H7/E;else H7=f7*E;if(G4.includes("w"))M7=j4.x+j4.width-H7;if(G4.includes("n"))U7=j4.y+j4.height-f7}else{if(G4==="e"||G4==="w")f7=H7/E;else H7=f7*E;if(G4==="w")M7=j4.x+j4.width-H7;if(G4==="n")U7=j4.y+j4.height-f7}if(a={x:M7,y:U7,width:H7,height:f7},H4)H4.style.left=`${M7}px`,H4.style.top=`${U7-s}px`,H4.style.width=`${H7}px`,H4.style.height=`${f7}px`;$4({x:F4.clientX+12,y:F4.clientY+12,text:`${Math.round(H7)} × ${Math.round(f7)}`}),u7(new Map([[u,a]]))},x4=()=>{window.removeEventListener("mousemove",e),window.removeEventListener("mouseup",x4),$4(null),Q7.current=null,u7(new Map),H({...J,sections:R.map((F4)=>F4.id===u?{...F4,currentRect:a}:F4)})};window.addEventListener("mousemove",e),window.addEventListener("mouseup",x4)},[R,J,H,s]),D4=F7.useCallback((f)=>{b4((u)=>{let G4=new Set(u);return G4.add(f),G4}),q4((u)=>{let G4=new Set(u);return G4.delete(f),G4}),q7(()=>{let u=o.current;H({...u,sections:u.sections.filter((G4)=>G4.id!==f),originalOrder:u.originalOrder.filter((G4)=>G4!==f)}),b4((G4)=>{let z4=new Set(G4);return z4.delete(f),z4})},180)},[H]),z7=(f)=>{let{originalRect:u,currentRect:G4}=f;return Math.abs(u.x-G4.x)>1||Math.abs(u.y-G4.y)>1||Math.abs(u.width-G4.width)>1||Math.abs(u.height-G4.height)>1},J7=(f)=>{let{originalRect:u,currentRect:G4}=f;return Math.abs(u.x-G4.x)>1||Math.abs(u.y-G4.y)>1},t4=(f)=>{let{originalRect:u,currentRect:G4}=f;return Math.abs(u.width-G4.width)>1||Math.abs(u.height-G4.height)>1};for(let f of R)if(!EZ.current.has(f.id)){if(J7(f))EZ.current.set(f.id,"move");else if(t4(f))EZ.current.set(f.id,"resize")}for(let f of EZ.current.keys())if(!R.some((u)=>u.id===f))EZ.current.delete(f);let b7=R.filter((f)=>{try{if(d4.has(f.id))return!0;if(p.has(f.id))return!0;let u=document.querySelector(f.selector);if(!u)return!1;let G4=u.getBoundingClientRect(),z4=f.originalRect;return Math.abs(G4.width-z4.width)+Math.abs(G4.height-z4.height)<200}catch{return!1}}),o7=b7.filter((f)=>z7(f)),S7=b7.filter((f)=>!z7(f)),A7=new Set(o7.map((f)=>f.id));for(let f of W7.current)if(!A7.has(f))W7.current.delete(f);let o4=[...A7].sort().join(",");for(let f of o7)M4.current.set(f.id,{currentRect:f.currentRect,originalRect:f.originalRect,isFixed:f.isFixed});return F7.useEffect(()=>{let f=Z5.current;Z5.current=A7;let u=new Map;for(let G4 of f)if(!A7.has(G4)){if(!R.some((S4)=>S4.id===G4))continue;let z4=M4.current.get(G4);if(z4)u.set(G4,{orig:z4.originalRect,target:z4.currentRect,isFixed:z4.isFixed}),M4.current.delete(G4)}if(u.size>0){eZ((z4)=>{let S4=new Map(z4);for(let[m4,j4]of u)S4.set(m4,j4);return S4});let G4=q7(()=>{eZ((z4)=>{let S4=new Map(z4);for(let m4 of u.keys())S4.delete(m4);return S4})},250);return()=>clearTimeout(G4)}},[o4,R]),n7.jsxs(n7.Fragment,{children:[n7.jsxs("div",{className:`${Z4.rearrangeOverlay} ${!Y?Z4.light:""} ${K?Z4.overlayExiting:""}${W?` ${W}`:""}`,"data-feedback-toolbar":!0,children:[B4&&n7.jsx("div",{className:Z4.hoverHighlight,style:{left:B4.x,top:B4.y,width:B4.w,height:B4.h}}),S7.map((f)=>{let u=f.currentRect,G4=f.isFixed?u.y:u.y-s,z4=b_,S4=p.has(f.id);return n7.jsxs("div",{"data-rearrange-section":f.id,className:`${Z4.sectionOutline} ${S4?Z4.selected:""} ${h||K||d4.has(f.id)?Z4.exiting:""}`,style:{left:u.x,top:G4,width:u.width,height:u.height,borderColor:z4.border,backgroundColor:z4.bg,...qZ?{}:{opacity:0,animation:"none",transition:"none"}},onMouseDown:(m4)=>N4(m4,f.id),onDoubleClick:()=>N7(f.id),children:[n7.jsx("span",{className:Z4.sectionLabel,style:{backgroundColor:z4.pill},children:f.label}),n7.jsx("span",{className:`${Z4.sectionAnnotation} ${f.note?Z4.annotationVisible:""}`,children:(()=>{if(f.note)n4.current.set(f.id,f.note);return f.note||n4.current.get(f.id)||""})()}),n7.jsxs("span",{className:Z4.sectionDimensions,children:[Math.round(u.width)," × ",Math.round(u.height)]}),n7.jsx("div",{className:Z4.deleteButton,onMouseDown:(m4)=>m4.stopPropagation(),onClick:()=>D4(f.id),children:"✕"}),f_.map((m4)=>n7.jsx("div",{className:`${Z4.handle} ${Z4[`handle${m4.charAt(0).toUpperCase()}${m4.slice(1)}`]}`,onMouseDown:(j4)=>U4(j4,f.id,m4)},m4))]},f.id)}),o7.map((f)=>{let u=f.currentRect,G4=f.isFixed?u.y:u.y-s,z4=p.has(f.id),S4=J7(f),m4=t4(f);if(O&&!z4)return null;let _=!W7.current.has(f.id);if(_)W7.current.add(f.id);return n7.jsxs("div",{"data-rearrange-section":f.id,className:`${Z4.ghostOutline} ${z4?Z4.selected:""} ${h||K||d4.has(f.id)?Z4.exiting:""}`,style:{left:u.x,top:G4,width:u.width,height:u.height,...qZ?{}:{opacity:0,animation:"none",transition:"none"},...!_?{animation:"none"}:{}},onMouseDown:(E)=>N4(E,f.id),onDoubleClick:()=>N7(f.id),children:[n7.jsx("span",{className:Z4.sectionLabel,style:{backgroundColor:b_.pill},children:f.label}),n7.jsx("span",{className:`${Z4.sectionAnnotation} ${f.note?Z4.annotationVisible:""}`,children:(()=>{if(f.note)n4.current.set(f.id,f.note);return f.note||n4.current.get(f.id)||""})()}),n7.jsxs("span",{className:Z4.sectionDimensions,children:[Math.round(u.width)," × ",Math.round(u.height)]}),n7.jsx("div",{className:Z4.deleteButton,onMouseDown:(E)=>E.stopPropagation(),onClick:()=>D4(f.id),children:"✕"}),f_.map((E)=>n7.jsx("div",{className:`${Z4.handle} ${Z4[`handle${E.charAt(0).toUpperCase()}${E.slice(1)}`]}`,onMouseDown:(a)=>U4(a,f.id,E)},E)),n7.jsx("span",{className:Z4.ghostBadge,children:(()=>{let E=EZ.current.get(f.id);if(S4&&m4){let[a,H4]=E==="resize"?["Resize","Move"]:["Move","Resize"];return n7.jsxs(n7.Fragment,{children:["Suggested ",a," ",n7.jsxs("span",{className:Z4.ghostBadgeExtra,children:["& ",H4]})]})}return`Suggested ${m4?"Resize":"Move"}`})()})]},f.id)})]}),!O&&(()=>{let f=[];for(let u of o7){let G4=I2.get(u.id);f.push({id:u.id,orig:u.originalRect,target:G4||u.currentRect,isFixed:u.isFixed,isSelected:p.has(u.id),isExiting:d4.has(u.id)})}for(let[u,G4]of I2)if(!f.some((z4)=>z4.id===u)){let z4=R.find((S4)=>S4.id===u);if(z4)f.push({id:u,orig:z4.originalRect,target:G4,isFixed:z4.isFixed,isSelected:p.has(u)})}for(let[u,G4]of AZ)if(!f.some((z4)=>z4.id===u))f.push({id:u,orig:G4.orig,target:G4.target,isFixed:G4.isFixed,isSelected:!1,isExiting:!0});if(f.length===0)return null;return n7.jsxs("svg",{className:`${Z4.connectorSvg} ${h||K?Z4.connectorExiting:""}`,children:[f.map(({id:u,orig:G4,target:z4,isFixed:S4,isSelected:m4,isExiting:j4})=>{let _=G4.x+G4.width/2,E=(S4?G4.y:G4.y-s)+G4.height/2,a=z4.x+z4.width/2,H4=(S4?z4.y:z4.y-s)+z4.height/2,e=a-_,x4=H4-E,F4=Math.sqrt(e*e+x4*x4);if(F4<2)return null;let E4=Math.min(1,F4/40),Q4=Math.min(F4*0.3,60),M7=F4>0?-x4/F4:0,U7=F4>0?e/F4:0,H7=(_+a)/2+M7*Q4,f7=(E+H4)/2+U7*Q4,X7=I2.has(u),e7=X7||m4?1:0.4,kZ=X7||m4?1:0.5;return n7.jsxs("g",{className:j4?Z4.connectorExiting:"",children:[n7.jsx("path",{className:Z4.connectorLine,d:`M ${_} ${E} Q ${H7} ${f7} ${a} ${H4}`,fill:"none",stroke:"rgba(59, 130, 246, 0.45)",strokeWidth:"1.5",opacity:e7*E4}),n7.jsx("circle",{className:Z4.connectorDot,cx:_,cy:E,r:4*E4,fill:"rgba(59, 130, 246, 0.8)",stroke:"#fff",strokeWidth:"1.5",opacity:kZ*E4,filter:"url(#connDotShadow)"}),n7.jsx("circle",{className:Z4.connectorDot,cx:a,cy:H4,r:4*E4,fill:"rgba(59, 130, 246, 0.8)",stroke:"#fff",strokeWidth:"1.5",opacity:kZ*E4,filter:"url(#connDotShadow)"})]},`conn-${u}`)}),n7.jsx("defs",{children:n7.jsx("filter",{id:"connDotShadow",x:"-50%",y:"-50%",width:"200%",height:"200%",children:n7.jsx("feDropShadow",{dx:"0",dy:"0.5",stdDeviation:"1",floodOpacity:"0.15"})})})]})})(),i4&&(()=>{let f=R.find((H4)=>H4.id===i4);if(!f)return null;let u=f.currentRect,G4=f.isFixed?u.y:u.y-s,z4=u.x+u.width/2,S4=G4-8,m4=G4+u.height+8,j4=S4>200,_=m4<window.innerHeight-100,E=Math.max(160,Math.min(window.innerWidth-160,z4)),a;if(j4)a={left:E,bottom:window.innerHeight-S4};else if(_)a={left:E,top:m4};else a={left:E,top:Math.max(80,window.innerHeight/2-80)};return n7.jsx(iz,{element:f.label,placeholder:"Add a note about this section",initialValue:f.note??"",submitLabel:p4.current?"Save":"Set",onSubmit:l4,onCancel:Y4,onDelete:p4.current?()=>{l4("")}:void 0,isExiting:h7,lightMode:!Y,style:a})})(),O4&&n7.jsx("div",{className:Z4.sizeIndicator,style:{left:O4.x,top:O4.y},"data-feedback-toolbar":!0,children:O4.text}),C4.map((f,u)=>n7.jsx("div",{className:Z4.guideLine,style:f.axis==="x"?{position:"fixed",left:f.pos,top:0,width:1,height:"100vh"}:{position:"fixed",left:0,top:f.pos-s,width:"100vw",height:1}},`${f.axis}-${f.pos}-${u}`))]})}var PH=new Set(["script","style","noscript","link","meta","br","hr"]);function rF(){let J=document.querySelector("main")||document.body,H=[],Y=Array.from(J.children),K=J!==document.body&&Y.length<3?Array.from(document.body.children):Y;for(let W of K){if(!(W instanceof HTMLElement))continue;if(PH.has(W.tagName.toLowerCase()))continue;if(W.hasAttribute("data-feedback-toolbar"))continue;let O=window.getComputedStyle(W);if(O.display==="none"||O.visibility==="hidden")continue;let A=W.getBoundingClientRect();if(A.height<10||A.width<10)continue;H.push({label:oz(W),selector:HG(W),top:A.top,bottom:A.bottom,left:A.left,right:A.right,area:A.width*A.height});for(let C of Array.from(W.children)){if(!(C instanceof HTMLElement))continue;if(PH.has(C.tagName.toLowerCase()))continue;if(C.hasAttribute("data-feedback-toolbar"))continue;let x=window.getComputedStyle(C);if(x.display==="none"||x.visibility==="hidden")continue;let J4=C.getBoundingClientRect();if(J4.height<10||J4.width<10)continue;H.push({label:oz(C),selector:HG(C),top:J4.top,bottom:J4.bottom,left:J4.left,right:J4.right,area:J4.width*J4.height})}}return H}function nF(J){let H=window.scrollY;return J.map(({label:Y,selector:K,rect:W})=>{let O=W.y-H;return{label:Y,selector:K,top:O,bottom:O+W.height,left:W.x,right:W.x+W.width,area:W.width*W.height}})}function tF(J){let H=window.scrollY,Y=J.y-H,K=J.x;return{top:Y,bottom:Y+J.height,left:K,right:K+J.width,area:J.width*J.height}}function AH(J,H){let Y=H?nF(H):rF(),K=tF(J),W=null,O=null,A=null,C=null,x=null;for(let p of Y){if(Math.abs(p.left-K.left)<2&&Math.abs(p.top-K.top)<2&&Math.abs(p.right-p.left-J.width)<2&&Math.abs(p.bottom-p.top-J.height)<2)continue;if(p.left<=K.left+2&&p.right>=K.right-2&&p.top<=K.top+2&&p.bottom>=K.bottom-2&&p.area>K.area*1.5){if(!x||p.area<x._area)x={label:p.label,selector:p.selector,_area:p.area}}let q4=K.right>p.left+5&&K.left<p.right-5,h=K.bottom>p.top+5&&K.top<p.bottom-5;if(q4&&p.bottom<=K.top+5){let t=Math.round(K.top-p.bottom);if(!W||t<W._dist)W={label:p.label,selector:p.selector,gap:Math.max(0,t),_dist:t}}if(q4&&p.top>=K.bottom-5){let t=Math.round(p.top-K.bottom);if(!O||t<O._dist)O={label:p.label,selector:p.selector,gap:Math.max(0,t),_dist:t}}if(h&&p.right<=K.left+5){let t=Math.round(K.left-p.right);if(!A||t<A._dist)A={label:p.label,selector:p.selector,gap:Math.max(0,t),_dist:t}}if(h&&p.left>=K.right-5){let t=Math.round(p.left-K.right);if(!C||t<C._dist)C={label:p.label,selector:p.selector,gap:Math.max(0,t),_dist:t}}}let{innerWidth:J4,innerHeight:b}=window,g=ZR(J,J4),R=(p)=>{if(!p)return null;return{label:p.label,selector:p.selector,gap:p.gap}},o=eF(K,J,J4,b,x?{label:x.label,selector:x.selector,_area:x._area}:null,Y);return{above:R(W),below:R(O),left:R(A),right:R(C),alignment:g,containedIn:x?{label:x.label,selector:x.selector}:null,outOfBounds:o}}function eF(J,H,Y,K,W,O){let A={},C=!1,x=[];if(J.left<-2)x.push("left");if(J.right>Y+2)x.push("right");if(J.top<-2)x.push("top");if(J.bottom>K+2)x.push("bottom");if(x.length>0)A.viewport=x,C=!0;if(W){let J4=O.find((b)=>b.label===W.label&&b.selector===W.selector&&Math.abs(b.area-W._area)<10);if(J4){let b=[];if(J.left<J4.left-2)b.push("left");if(J.right>J4.right+2)b.push("right");if(J.top<J4.top-2)b.push("top");if(J.bottom>J4.bottom+2)b.push("bottom");if(b.length>0)A.container={label:W.label,edges:b},C=!0}}return C?A:null}function ZR(J,H){if(J.width/H>0.85)return"full-width";let K=J.x+J.width/2,W=H/2,O=K-W,A=H*0.08;if(Math.abs(O)<A)return"center";if(O<0)return"left";return"right"}function K3(J){switch(J){case"full-width":return"full-width";case"center":return"centered";case"left":return"left-aligned";case"right":return"right-aligned"}}function W3(J,H={}){let Y=[];if(J.above)Y.push(`Below \`${J.above.label}\`${J.above.gap>0?` (${J.above.gap}px gap)`:""}`);if(J.below)Y.push(`Above \`${J.below.label}\`${J.below.gap>0?` (${J.below.gap}px gap)`:""}`);if(H.includeLeftRight){if(J.left)Y.push(`Right of \`${J.left.label}\`${J.left.gap>0?` (${J.left.gap}px gap)`:""}`);if(J.right)Y.push(`Left of \`${J.right.label}\`${J.right.gap>0?` (${J.right.gap}px gap)`:""}`)}let K=K3(J.alignment);if(J.containedIn)Y.push(`${K.charAt(0).toUpperCase()+K.slice(1)} in \`${J.containedIn.label}\``);else Y.push(`${K.charAt(0).toUpperCase()+K.slice(1)} in page`);if(H.includePixelRef&&H.pixelRef)Y.push(`Pixel ref: \`${H.pixelRef}\``);if(J.outOfBounds){if(J.outOfBounds.viewport)Y.push(`**Outside viewport** (${J.outOfBounds.viewport.join(", ")} edge${J.outOfBounds.viewport.length>1?"s":""})`);if(J.outOfBounds.container)Y.push(`**Outside \`${J.outOfBounds.container.label}\`** (${J.outOfBounds.container.edges.join(", ")} edge${J.outOfBounds.container.edges.length>1?"s":""})`)}return Y}function GR(J,H,Y){let K=[];if(J.above)K.push(`below \`${J.above.label}\``);if(J.below)K.push(`above \`${J.below.label}\``);if(J.left)K.push(`right of \`${J.left.label}\``);if(J.right)K.push(`left of \`${J.right.label}\``);if(J.containedIn)K.push(`inside \`${J.containedIn.label}\``);if(K.push(K3(J.alignment)),J.outOfBounds?.viewport)K.push(`**outside viewport** (${J.outOfBounds.viewport.join(", ")})`);if(J.outOfBounds?.container)K.push(`**outside \`${J.outOfBounds.container.label}\`** (${J.outOfBounds.container.edges.join(", ")})`);let W=Y?`, ${Math.round(Y.width)}×${Math.round(Y.height)}px`:"";return`at (${Math.round(H.x)}, ${Math.round(H.y)})${W}: ${K.join(", ")}`}var d_=15;function p_(J){if(J.length<2)return[];let H=[],Y=new Set;for(let K=0;K<J.length;K++){if(Y.has(K))continue;let W=[K];for(let O=K+1;O<J.length;O++){if(Y.has(O))continue;if(Math.abs(J[K].rect.y-J[O].rect.y)<d_)W.push(O)}if(W.length>=2){let O=W.map((x)=>J[x]);O.sort((x,J4)=>x.rect.x-J4.rect.x);let A=[];for(let x=0;x<O.length-1;x++)A.push(Math.round(O[x+1].rect.x-(O[x].rect.x+O[x].rect.width)));let C=Math.round(O.reduce((x,J4)=>x+J4.rect.y,0)/O.length);H.push({labels:O.map((x)=>x.label),type:"row",sharedEdge:C,gaps:A,avgGap:A.length?Math.round(A.reduce((x,J4)=>x+J4,0)/A.length):0}),W.forEach((x)=>Y.add(x))}}for(let K=0;K<J.length;K++){if(Y.has(K))continue;let W=[K];for(let O=K+1;O<J.length;O++){if(Y.has(O))continue;if(Math.abs(J[K].rect.x-J[O].rect.x)<d_)W.push(O)}if(W.length>=2){let O=W.map((x)=>J[x]);O.sort((x,J4)=>x.rect.y-J4.rect.y);let A=[];for(let x=0;x<O.length-1;x++)A.push(Math.round(O[x+1].rect.y-(O[x].rect.y+O[x].rect.height)));let C=Math.round(O.reduce((x,J4)=>x+J4.rect.x,0)/O.length);H.push({labels:O.map((x)=>x.label),type:"column",sharedEdge:C,gaps:A,avgGap:A.length?Math.round(A.reduce((x,J4)=>x+J4,0)/A.length):0}),W.forEach((x)=>Y.add(x))}}return H}function BR(J){if(J.length<2)return[];let H=p_(J.map((A)=>({label:A.label,rect:A.originalRect}))),Y=p_(J.map((A)=>({label:A.label,rect:A.currentRect}))),K=[],W=new Set;for(let A of H){let C=new Set(A.labels),x=null,J4=0;for(let b of Y){let g=b.labels.filter((R)=>C.has(R)).length;if(g>=2&&g>J4)x=b,J4=g}if(x){let b=x.labels.filter((R)=>C.has(R)),g=b.join(", ");if(x.type!==A.type){let R=A.type==="row"?"y":"x",o=x.type==="row"?"y":"x";K.push(`**${g}**: ${A.type} (${R}≈${A.sharedEdge}, ${A.avgGap}px gaps) → ${x.type} (${o}≈${x.sharedEdge}, ${x.avgGap}px gaps)`)}else if(Math.abs(A.sharedEdge-x.sharedEdge)>20||Math.abs(A.avgGap-x.avgGap)>5){let R=A.type==="row"?"y":"x",o=Math.abs(A.sharedEdge-x.sharedEdge)>20?` ${R}: ${A.sharedEdge} → ${x.sharedEdge}`:"",p=Math.abs(A.avgGap-x.avgGap)>5?` gaps: ${A.avgGap}px → ${x.avgGap}px`:"";K.push(`**${g}**: ${A.type} shifted —${o}${p}`)}b.forEach((R)=>W.add(R))}else{let b=A.labels.join(", "),g=A.type==="row"?"y":"x";K.push(`**${b}**: ${A.type} (${g}≈${A.sharedEdge}) dissolved`),A.labels.forEach((R)=>W.add(R))}}for(let A of Y){if(A.labels.every((J4)=>W.has(J4)))continue;if(A.labels.filter((J4)=>!W.has(J4)).length<2)continue;if(!H.some((J4)=>{return J4.labels.filter((g)=>A.labels.includes(g)).length>=2})){let J4=A.type==="row"?"y":"x";K.push(`**${A.labels.join(", ")}**: new ${A.type} (${J4}≈${A.sharedEdge}, ${A.avgGap}px gaps)`),A.labels.forEach((b)=>W.add(b))}}let O=J.filter((A)=>!W.has(A.label));if(O.length>=2){let A={};for(let C of O){let x=Math.round(C.currentRect.x/5)*5;(A[x]??(A[x]=[])).push(C.label)}for(let[C,x]of Object.entries(A))if(x.length>=2)K.push(`**${x.join(", ")}**: shared left edge at x≈${C}`)}return K}function _3(J){if(typeof document>"u")return{viewport:J,contentArea:null};let H=[],Y=new Set,K=(C)=>{if(Y.has(C))return;if(!(C instanceof HTMLElement))return;if(C.hasAttribute("data-feedback-toolbar"))return;if(PH.has(C.tagName.toLowerCase()))return;Y.add(C),H.push(C)},W=document.querySelector("main");if(W)K(W);let O=document.querySelector("[role='main']");if(O)K(O);for(let C of Array.from(document.body.children))if(K(C),C.children){for(let x of Array.from(C.children))if(K(x),x.children)for(let J4 of Array.from(x.children))K(J4)}let A=null;for(let C of H){let x=C.getBoundingClientRect();if(x.height<50)continue;let J4=getComputedStyle(C);if(J4.maxWidth&&J4.maxWidth!=="none"&&J4.maxWidth!=="0px"){if(!A||x.width<A.rect.width)A={el:C,rect:x};continue}if(!A&&x.width<J.width-20&&x.width>100)A={el:C,rect:x}}if(A){let{el:C,rect:x}=A;return{viewport:J,contentArea:{width:Math.round(x.width),left:Math.round(x.left),right:Math.round(x.right),centerX:Math.round(x.left+x.width/2),selector:HG(C)}}}return{viewport:J,contentArea:null}}function $R(J){if(typeof document>"u")return null;let H=document.querySelector(J);if(!H?.parentElement)return null;let Y=getComputedStyle(H.parentElement),K={parentDisplay:Y.display,parentSelector:HG(H.parentElement)};if(Y.display.includes("flex"))K.flexDirection=Y.flexDirection;if(Y.display.includes("grid")&&Y.gridTemplateColumns!=="none")K.gridCols=Y.gridTemplateColumns;if(Y.gap&&Y.gap!=="normal"&&Y.gap!=="0px")K.gap=Y.gap;return K}function L3(J,H){let Y=H.contentArea,K=Y?Y.width:H.viewport.width,W=Y?Y.left:0,O=Y?Y.centerX:Math.round(H.viewport.width/2),A=Math.round(J.x-W),C=Math.round(W+K-(J.x+J.width)),x=(J.width/K*100).toFixed(1),J4=J.x+J.width/2,b=Math.abs(J4-O)<20,g=J.width/K>0.95,R=[];if(g)R.push("`width: 100%` of container");else R.push(`left \`${A}px\` in container, right \`${C}px\`, width \`${x}%\` (\`${Math.round(J.width)}px\`)`);if(b&&!g)R.push("centered — `margin-inline: auto`");return R.join(" — ")}function U3(J){let{viewport:H,contentArea:Y}=J,K=`### Reference Frame
`;if(K+=`- Viewport: \`${H.width}×${H.height}px\`
`,Y){let W=Y;K+=`- Content area: \`${W.width}px\` wide, left edge at \`x=${W.left}\`, right at \`x=${W.right}\` (\`${W.selector}\`)
`,K+=`- Pixel → CSS translation:
`,K+=`  - **Horizontal position in container**: \`element.x - ${W.left}\` → use as \`margin-left\` or \`left\`
`,K+=`  - **Width as % of container**: \`element.width / ${W.width} × 100\` → use as \`width: X%\`
`,K+="  - **Vertical gap between elements**: `nextElement.y - (prevElement.y + prevElement.height)` → use as `margin-top` or `gap`\n",K+=`  - **Centered**: if \`|element.centerX - ${W.centerX}| < 20px\` → use \`margin-inline: auto\`
`}else K+=`- No distinct content container — elements positioned relative to full viewport
`,K+=`- Pixel → CSS translation:
`,K+=`  - **Width as % of viewport**: \`element.width / ${H.width} × 100\` → use as \`width: X%\`
`,K+=`  - **Centered**: if \`|(element.x + element.width/2) - ${Math.round(H.width/2)}| < 20px\` → use \`margin-inline: auto\`
`;return K+=`
`,K}function zR(J){let H=$R(J);if(!H)return null;let Y=`\`${H.parentDisplay}\``;if(H.flexDirection)Y+=`, flex-direction: \`${H.flexDirection}\``;if(H.gridCols)Y+=`, grid-template-columns: \`${H.gridCols}\``;if(H.gap)Y+=`, gap: \`${H.gap}\``;return`Parent: ${Y} (\`${H.parentSelector}\`)`}function c_(J,H,Y,K="standard"){if(J.length===0)return"";let W=[...J].sort((h,t)=>{if(Math.abs(h.y-t.y)<20)return h.x-t.x;return h.y-t.y}),O="";if(Y?.blankCanvas){if(O+=`## Wireframe: New Page

`,Y.wireframePurpose)O+=`> **Purpose:** ${Y.wireframePurpose}
>
`;O+=`> ${J.length} component${J.length!==1?"s":""} placed — this is a standalone wireframe, not related to the current page.
>
> This wireframe is a rough sketch for exploring ideas.

`}else O+=`## Design Layout

> ${J.length} component${J.length!==1?"s":""} placed

`;if(K==="compact")return O+=`### Components
`,W.forEach((h,t)=>{let I4=j6[h.type]?.label||h.type;O+=`${t+1}. **${I4}** — \`${Math.round(h.width)}×${Math.round(h.height)}px\` at \`(${Math.round(h.x)}, ${Math.round(h.y)})\`
`}),O;let A=_3(H);O+=U3(A),O+=`### Components
`,W.forEach((h,t)=>{let I4=j6[h.type]?.label||h.type,u4={x:h.x,y:h.y,width:h.width,height:h.height};O+=`${t+1}. **${I4}** — \`${Math.round(h.width)}×${Math.round(h.height)}px\` at \`(${Math.round(h.x)}, ${Math.round(h.y)})\`
`;let i4=AH(u4),h7=W3(i4,{includeLeftRight:K==="detailed"||K==="forensic"});for(let p4 of h7)O+=`   - ${p4}
`;let T4=L3(u4,A);if(T4)O+=`   - CSS: ${T4}
`}),O+=`
### Layout Analysis
`;let C=[];for(let h of W){let t=C.find((I4)=>Math.abs(I4.y-h.y)<30);if(t)t.items.push(h);else C.push({y:h.y,items:[h]})}if(C.sort((h,t)=>h.y-t.y),C.forEach((h,t)=>{h.items.sort((u4,i4)=>u4.x-i4.x);let I4=h.items.map((u4)=>j6[u4.type]?.label||u4.type);if(h.items.length===1){let i4=h.items[0].width>H.width*0.8;O+=`- Row ${t+1} (y≈${Math.round(h.y)}): ${I4[0]}${i4?" — full width":""}
`}else O+=`- Row ${t+1} (y≈${Math.round(h.y)}): ${I4.join(" | ")} — ${h.items.length} items side by side
`}),K==="detailed"||K==="forensic"){O+=`
### Spacing & Gaps
`;for(let h=0;h<W.length-1;h++){let t=W[h],I4=W[h+1],u4=j6[t.type]?.label||t.type,i4=j6[I4.type]?.label||I4.type,g7=Math.round(I4.y-(t.y+t.height)),h7=Math.round(I4.x-(t.x+t.width));if(Math.abs(t.y-I4.y)<30)O+=`- ${u4} → ${i4}: \`${h7}px\` horizontal gap
`;else O+=`- ${u4} → ${i4}: \`${g7}px\` vertical gap
`}if(K==="forensic"&&W.length>2){O+=`
### All Pairwise Gaps
`;for(let h=0;h<W.length;h++)for(let t=h+1;t<W.length;t++){let I4=W[h],u4=W[t],i4=j6[I4.type]?.label||I4.type,g7=j6[u4.type]?.label||u4.type,h7=Math.round(u4.y-(I4.y+I4.height)),T4=Math.round(u4.x-(I4.x+I4.width));O+=`- ${i4} ↔ ${g7}: h=\`${T4}px\` v=\`${h7}px\`
`}}if(K==="forensic")O+=`
### Z-Order (placement order)
`,J.forEach((h,t)=>{let I4=j6[h.type]?.label||h.type;O+=`${t}. ${I4} at \`(${Math.round(h.x)}, ${Math.round(h.y)})\`
`})}O+=`
### Suggested Implementation
`;let x=W.some((h)=>h.type==="navigation"),J4=W.some((h)=>h.type==="hero"),b=W.some((h)=>h.type==="sidebar"),g=W.some((h)=>h.type==="footer"),R=W.filter((h)=>h.type==="card"),o=W.filter((h)=>h.type==="form"),p=W.filter((h)=>h.type==="table"),q4=W.filter((h)=>h.type==="modal");if(x)O+=`- Top navigation bar with logo + nav links + CTA
`;if(J4)O+=`- Hero section with heading, subtext, and call-to-action
`;if(b)O+=`- Sidebar layout — use CSS Grid with sidebar + main content area
`;if(R.length>1)O+=`- ${R.length}-column card grid — use CSS Grid or Flexbox
`;else if(R.length===1)O+=`- Card component with image + content area
`;if(o.length>0)O+=`- ${o.length} form${o.length>1?"s":""} — add proper labels, validation, and submit handling
`;if(p.length>0)O+=`- Data table — consider sortable columns and pagination
`;if(q4.length>0)O+=`- Modal dialog — add overlay backdrop and focus trapping
`;if(g)O+=`- Multi-column footer with links
`;if(K==="detailed"||K==="forensic"){if(O+=`
### CSS Suggestions
`,b){let h=W.find((t)=>t.type==="sidebar");O+=`- \`display: grid; grid-template-columns: ${Math.round(h.width)}px 1fr;\`
`}if(R.length>1){let h=Math.round(R[0].width);O+=`- \`display: grid; grid-template-columns: repeat(${R.length}, ${h}px); gap: 16px;\`
`}if(x)O+="- Navigation: `position: sticky; top: 0; z-index: 50;`\n"}return O}function l_(J,H="standard",Y){let{sections:K}=J,W=[];for(let b of K){let{originalRect:g,currentRect:R}=b,o=Math.abs(g.x-R.x)>1||Math.abs(g.y-R.y)>1,p=Math.abs(g.width-R.width)>1||Math.abs(g.height-R.height)>1;if(!o&&!p){if(H==="forensic")W.push({section:b,posMoved:!1,sizeChanged:!1});continue}W.push({section:b,posMoved:o,sizeChanged:p})}if(W.length===0)return"";if(H!=="forensic"&&W.every((b)=>!b.posMoved&&!b.sizeChanged))return"";let O=`## Suggested Layout Changes

`,A=Y?Y.width:typeof window<"u"?window.innerWidth:0,C=Y?Y.height:typeof window<"u"?window.innerHeight:0,x=_3({width:A,height:C});if(H!=="compact")O+=U3(x);if(H==="forensic")O+=`> Detected at: \`${new Date(J.detectedAt).toISOString()}\`
`,O+=`> Total sections: ${K.length}

`;let J4=(b)=>K.map((g)=>({label:g.label,selector:g.selector,rect:b==="original"?g.originalRect:g.currentRect}));O+=`**Changes:**
`;for(let{section:b,posMoved:g,sizeChanged:R}of W){let{originalRect:o,currentRect:p}=b;if(!g&&!R){O+=`- ${b.label} — unchanged at (${Math.round(p.x)}, ${Math.round(p.y)}) ${Math.round(p.width)}×${Math.round(p.height)}px
`;continue}if(H==="compact"){if(g&&R)O+=`- Suggested: move **${b.label}** to (${Math.round(p.x)}, ${Math.round(p.y)}) ${Math.round(p.width)}×${Math.round(p.height)}px
`;else if(g)O+=`- Suggested: move **${b.label}** to (${Math.round(p.x)}, ${Math.round(p.y)})
`;else O+=`- Suggested: resize **${b.label}** to ${Math.round(p.width)}×${Math.round(p.height)}px
`;continue}if(g&&R)O+=`- Suggested: move and resize **${b.label}**
`;else if(g)O+=`- Suggested: move **${b.label}**
`;else O+=`- Suggested: resize **${b.label}** from ${Math.round(o.width)}×${Math.round(o.height)}px to ${Math.round(p.width)}×${Math.round(p.height)}px
`;if(g){let h=AH(o,J4("original")),t=AH(p,J4("current")),I4=R?{width:o.width,height:o.height}:void 0;O+=`  - Currently ${GR(h,{x:o.x,y:o.y},I4)}
`;let u4=R?{width:p.width,height:p.height}:void 0,i4=`at (${Math.round(p.x)}, ${Math.round(p.y)})`,g7=u4?`, ${Math.round(u4.width)}×${Math.round(u4.height)}px`:"",T4=W3(t,{includeLeftRight:H==="detailed"||H==="forensic"});if(T4.length>0){O+=`  - Suggested position ${i4}${g7}: ${T4[0]}
`;for(let N7=1;N7<T4.length;N7++)O+=`    ${T4[N7]}
`}else O+=`  - Suggested position ${i4}${g7}
`;let p4=L3(p,x);if(p4)O+=`  - CSS: ${p4}
`}let q4=zR(b.selector);if(q4)O+=`  - ${q4}
`;if(O+=`  - Selector: \`${b.selector}\`
`,H==="detailed"||H==="forensic"){let h=b.className?`${b.tagName}.${b.className.split(" ")[0]}`:b.tagName;if(h!==b.selector)O+=`  - Element: \`${h}\`
`;if(b.role)O+=`  - Role: \`${b.role}\`
`;if(H==="forensic"&&b.textSnippet)O+=`  - Text: "${b.textSnippet}"
`}if(H==="forensic")O+=`  - Original rect: \`{ x: ${Math.round(o.x)}, y: ${Math.round(o.y)}, w: ${Math.round(o.width)}, h: ${Math.round(o.height)} }\`
`,O+=`  - Current rect: \`{ x: ${Math.round(p.x)}, y: ${Math.round(p.y)}, w: ${Math.round(p.width)}, h: ${Math.round(p.height)} }\`
`}if(H!=="compact"){let b=W.filter((R)=>R.posMoved).map((R)=>({label:R.section.label,originalRect:R.section.originalRect,currentRect:R.section.currentRect})),g=BR(b);if(g.length>0){O+=`
### Layout Summary
`;for(let R of g)O+=`- ${R}
`}}if(H!=="compact"&&K.length>1){O+=`
### All Sections (current positions)
`;let b=[...K].sort((g,R)=>{if(Math.abs(g.currentRect.y-R.currentRect.y)<20)return g.currentRect.x-R.currentRect.x;return g.currentRect.y-R.currentRect.y});for(let g of b){let R=g.currentRect,o=Math.abs(R.x-g.originalRect.x)>1||Math.abs(R.y-g.originalRect.y)>1||Math.abs(R.width-g.originalRect.width)>1||Math.abs(R.height-g.originalRect.height)>1;O+=`- ${g.label}: \`${Math.round(R.width)}×${Math.round(R.height)}px\` at \`(${Math.round(R.x)}, ${Math.round(R.y)})\`${o?" ← suggested":""}
`}}return O}var CH="feedback-annotations-",V3=7;function rz(J){return`${CH}${J}`}function KH(J){if(typeof window>"u")return[];try{let H=localStorage.getItem(rz(J));if(!H)return[];let Y=JSON.parse(H),K=Date.now()-V3*24*60*60*1000;return Y.filter((W)=>!W.timestamp||W.timestamp>K)}catch{return[]}}function O3(J,H){if(typeof window>"u")return;try{localStorage.setItem(rz(J),JSON.stringify(H))}catch{}}function QR(){let J=new Map;if(typeof window>"u")return J;try{let H=Date.now()-V3*24*60*60*1000;for(let Y=0;Y<localStorage.length;Y++){let K=localStorage.key(Y);if(K?.startsWith(CH)){let W=K.slice(CH.length),O=localStorage.getItem(K);if(O){let C=JSON.parse(O).filter((x)=>!x.timestamp||x.timestamp>H);if(C.length>0)J.set(W,C)}}}}catch{}return J}function OB(J,H,Y){let K=H.map((W)=>({...W,_syncedTo:Y}));O3(J,K)}var wH="agentation-design-";function JR(J){if(typeof window>"u")return[];try{let H=localStorage.getItem(`${wH}${J}`);if(!H)return[];return JSON.parse(H)}catch{return[]}}function qR(J,H){if(typeof window>"u")return;try{localStorage.setItem(`${wH}${J}`,JSON.stringify(H))}catch{}}function HR(J){if(typeof window>"u")return;try{localStorage.removeItem(`${wH}${J}`)}catch{}}var IH="agentation-rearrange-";function XR(J){if(typeof window>"u")return null;try{let H=localStorage.getItem(`${IH}${J}`);if(!H)return null;return JSON.parse(H)}catch{return null}}function YR(J,H){if(typeof window>"u")return;try{localStorage.setItem(`${IH}${J}`,JSON.stringify(H))}catch{}}function jR(J){if(typeof window>"u")return;try{localStorage.removeItem(`${IH}${J}`)}catch{}}var xH="agentation-wireframe-";function KR(J){if(typeof window>"u")return null;try{let H=localStorage.getItem(`${xH}${J}`);if(!H)return null;return JSON.parse(H)}catch{return null}}function s_(J,H){if(typeof window>"u")return;try{localStorage.setItem(`${xH}${J}`,JSON.stringify(H))}catch{}}function cz(J){if(typeof window>"u")return;try{localStorage.removeItem(`${xH}${J}`)}catch{}}var F3="agentation-session-";function SH(J){return`${F3}${J}`}function WR(J){if(typeof window>"u")return null;try{return localStorage.getItem(SH(J))}catch{return null}}function WH(J,H){if(typeof window>"u")return;try{localStorage.setItem(SH(J),H)}catch{}}function _R(J){if(typeof window>"u")return;try{localStorage.removeItem(SH(J))}catch{}}var TH=`${F3}toolbar-hidden`;function LR(){if(typeof window>"u")return!1;try{return sessionStorage.getItem(TH)==="1"}catch{return!1}}function UR(J){if(typeof window>"u")return;try{if(J)sessionStorage.setItem(TH,"1");else sessionStorage.removeItem(TH)}catch{}}async function _H(J,H){let Y=await fetch(`${J}/sessions`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:H})});if(!Y.ok)throw Error(`Failed to create session: ${Y.status}`);return Y.json()}async function a_(J,H){let Y=await fetch(`${J}/sessions/${H}`);if(!Y.ok)throw Error(`Failed to get session: ${Y.status}`);return Y.json()}async function P0(J,H,Y){let K=await fetch(`${J}/sessions/${H}/annotations`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(Y)});if(!K.ok)throw Error(`Failed to sync annotation: ${K.status}`);return K.json()}async function i_(J,H,Y){let K=await fetch(`${J}/annotations/${H}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify(Y)});if(!K.ok)throw Error(`Failed to update annotation: ${K.status}`);return K.json()}async function U9(J,H){let Y=await fetch(`${J}/annotations/${H}`,{method:"DELETE"});if(!Y.ok)throw Error(`Failed to delete annotation: ${Y.status}`)}var $Z={FunctionComponent:0,ClassComponent:1,IndeterminateComponent:2,HostRoot:3,HostPortal:4,HostComponent:5,HostText:6,Fragment:7,Mode:8,ContextConsumer:9,ContextProvider:10,ForwardRef:11,Profiler:12,SuspenseComponent:13,MemoComponent:14,SimpleMemoComponent:15,LazyComponent:16,IncompleteClassComponent:17,DehydratedFragment:18,SuspenseListComponent:19,ScopeComponent:21,OffscreenComponent:22,LegacyHiddenComponent:23,CacheComponent:24,TracingMarkerComponent:25,HostHoistable:26,HostSingleton:27,IncompleteFunctionComponent:28,Throw:29,ViewTransitionComponent:30,ActivityComponent:31},o_=new Set(["Component","PureComponent","Fragment","Suspense","Profiler","StrictMode","Routes","Route","Outlet","Root","ErrorBoundaryHandler","HotReload","Hot"]),r_=[/Boundary$/,/BoundaryHandler$/,/Provider$/,/Consumer$/,/^(Inner|Outer)/,/Router$/,/^Client(Page|Segment|Root)/,/^Segment(ViewNode|Node)$/,/^LayoutSegment/,/^Server(Root|Component|Render)/,/^RSC/,/Context$/,/^Hot(Reload)?$/,/^(Dev|React)(Overlay|Tools|Root)/,/Overlay$/,/Handler$/,/^With[A-Z]/,/Wrapper$/,/^Root$/],VR=[/Page$/,/View$/,/Screen$/,/Section$/,/Card$/,/List$/,/Item$/,/Form$/,/Modal$/,/Dialog$/,/Button$/,/Nav$/,/Header$/,/Footer$/,/Layout$/,/Panel$/,/Tab$/,/Menu$/];function OR(J){let H=J?.mode??"filtered",Y=o_;if(J?.skipExact){let K=J.skipExact instanceof Set?J.skipExact:new Set(J.skipExact);Y=new Set([...o_,...K])}return{maxComponents:J?.maxComponents??6,maxDepth:J?.maxDepth??30,mode:H,skipExact:Y,skipPatterns:J?.skipPatterns?[...r_,...J.skipPatterns]:r_,userPatterns:J?.userPatterns??VR,filter:J?.filter}}function FR(J){return J.replace(/([a-z])([A-Z])/g,"$1-$2").replace(/([A-Z])([A-Z][a-z])/g,"$1-$2").toLowerCase()}function RR(J,H=10){let Y=new Set,K=J,W=0;while(K&&W<H){if(K.className&&typeof K.className==="string")K.className.split(/\s+/).forEach((O)=>{if(O.length>1){let A=O.replace(/[_][a-zA-Z0-9]{5,}.*$/,"").toLowerCase();if(A.length>1)Y.add(A)}});K=K.parentElement,W++}return Y}function MR(J,H){let Y=FR(J);for(let K of H){if(K===Y)return!0;let W=Y.split("-").filter((A)=>A.length>2),O=K.split("-").filter((A)=>A.length>2);for(let A of W)for(let C of O)if(A===C||A.includes(C)||C.includes(A))return!0}return!1}function NR(J,H,Y,K){if(Y.filter)return Y.filter(J,H);switch(Y.mode){case"all":return!0;case"filtered":if(Y.skipExact.has(J))return!1;if(Y.skipPatterns.some((W)=>W.test(J)))return!1;return!0;case"smart":if(Y.skipExact.has(J))return!1;if(Y.skipPatterns.some((W)=>W.test(J)))return!1;if(K&&MR(J,K))return!0;if(Y.userPatterns.some((W)=>W.test(J)))return!0;return!1;default:return!0}}var A0=null,DR=new WeakMap;function LH(J){return Object.keys(J).some((H)=>H.startsWith("__reactFiber$")||H.startsWith("__reactInternalInstance$")||H.startsWith("__reactProps$"))}function PR(){if(A0!==null)return A0;if(typeof document>"u")return!1;if(document.body&&LH(document.body))return A0=!0,!0;let J=["#root","#app","#__next","[data-reactroot]"];for(let H of J){let Y=document.querySelector(H);if(Y&&LH(Y))return A0=!0,!0}if(document.body){for(let H of document.body.children)if(LH(H))return A0=!0,!0}return A0=!1,!1}var FB={map:DR};function AR(J){return Object.keys(J).find((Y)=>Y.startsWith("__reactFiber$")||Y.startsWith("__reactInternalInstance$"))||null}function CR(J){let H=AR(J);if(!H)return null;return J[H]}function $G(J){if(!J)return null;if(J.displayName)return J.displayName;if(J.name)return J.name;return null}function TR(J){let{tag:H,type:Y,elementType:K}=J;if(H===$Z.HostComponent||H===$Z.HostText||H===$Z.HostHoistable||H===$Z.HostSingleton)return null;if(H===$Z.Fragment||H===$Z.Mode||H===$Z.Profiler||H===$Z.DehydratedFragment)return null;if(H===$Z.HostRoot||H===$Z.HostPortal||H===$Z.ScopeComponent||H===$Z.OffscreenComponent||H===$Z.LegacyHiddenComponent||H===$Z.CacheComponent||H===$Z.TracingMarkerComponent||H===$Z.Throw||H===$Z.ViewTransitionComponent||H===$Z.ActivityComponent)return null;if(H===$Z.ForwardRef){let W=K;if(W?.render){let O=$G(W.render);if(O)return O}if(W?.displayName)return W.displayName;return $G(Y)}if(H===$Z.MemoComponent||H===$Z.SimpleMemoComponent){let W=K;if(W?.type){let O=$G(W.type);if(O)return O}if(W?.displayName)return W.displayName;return $G(Y)}if(H===$Z.ContextProvider){let W=Y;if(W?._context?.displayName)return`${W._context.displayName}.Provider`;return null}if(H===$Z.ContextConsumer){let W=Y;if(W?.displayName)return`${W.displayName}.Consumer`;return null}if(H===$Z.LazyComponent){let W=K;if(W?._status===1&&W._result)return $G(W._result);return null}if(H===$Z.SuspenseComponent||H===$Z.SuspenseListComponent)return null;if(H===$Z.IncompleteClassComponent||H===$Z.IncompleteFunctionComponent)return $G(Y);if(H===$Z.FunctionComponent||H===$Z.ClassComponent||H===$Z.IndeterminateComponent)return $G(Y);return null}function ER(J){if(J.length<=2)return!0;if(J.length<=3&&J===J.toLowerCase())return!0;return!1}function wR(J,H){let Y=OR(H),K=Y.mode==="all";if(K){let x=FB.map.get(J);if(x!==void 0)return x}if(!PR()){let x={path:null,components:[]};if(K)FB.map.set(J,x);return x}let W=Y.mode==="smart"?RR(J):void 0,O=[];try{let x=CR(J),J4=0;while(x&&J4<Y.maxDepth&&O.length<Y.maxComponents){let b=TR(x);if(b&&!ER(b)&&NR(b,J4,Y,W))O.push(b);x=x.return,J4++}}catch{let x={path:null,components:[]};if(K)FB.map.set(J,x);return x}if(O.length===0){let x={path:null,components:[]};if(K)FB.map.set(J,x);return x}let C={path:O.slice().reverse().map((x)=>`<${x}>`).join(" "),components:O};if(K)FB.map.set(J,C);return C}var RB={FunctionComponent:0,ClassComponent:1,IndeterminateComponent:2,HostRoot:3,HostPortal:4,HostComponent:5,HostText:6,Fragment:7,Mode:8,ContextConsumer:9,ContextProvider:10,ForwardRef:11,Profiler:12,SuspenseComponent:13,MemoComponent:14,SimpleMemoComponent:15,LazyComponent:16};function IR(J){if(!J||typeof J!=="object")return null;let H=Object.keys(J),Y=H.find((O)=>O.startsWith("__reactFiber$"));if(Y)return J[Y]||null;let K=H.find((O)=>O.startsWith("__reactInternalInstance$"));if(K)return J[K]||null;let W=H.find((O)=>{if(!O.startsWith("__react"))return!1;let A=J[O];return A&&typeof A==="object"&&"_debugSource"in A});if(W)return J[W]||null;return null}function DB(J){if(!J.type)return null;if(typeof J.type==="string")return null;if(typeof J.type==="object"||typeof J.type==="function"){let H=J.type;if(H.displayName)return H.displayName;if(H.name)return H.name}return null}function xR(J,H=50){let Y=J,K=0;while(Y&&K<H){if(Y._debugSource)return{source:Y._debugSource,componentName:DB(Y)};if(Y._debugOwner?._debugSource)return{source:Y._debugOwner._debugSource,componentName:DB(Y._debugOwner)};Y=Y.return,K++}return null}function SR(J){let H=J,Y=0,K=50;while(H&&Y<K){let W=H,O=["_debugSource","__source","_source","debugSource"];for(let A of O){let C=W[A];if(C&&typeof C==="object"&&"fileName"in C)return{source:C,componentName:DB(H)}}if(H.memoizedProps){let A=H.memoizedProps;if(A.__source&&typeof A.__source==="object"){let C=A.__source;if(C.fileName&&C.lineNumber)return{source:{fileName:C.fileName,lineNumber:C.lineNumber,columnNumber:C.columnNumber},componentName:DB(H)}}}H=H.return,Y++}return null}var lz=new Map;function vR(J){let{tag:H,type:Y,elementType:K}=J;if(typeof Y==="string"||Y==null)return null;if(typeof Y==="function"&&Y.prototype?.isReactComponent)return null;if((H===RB.FunctionComponent||H===RB.IndeterminateComponent)&&typeof Y==="function")return Y;if(H===RB.ForwardRef&&K){let W=K.render;if(typeof W==="function")return W}if((H===RB.MemoComponent||H===RB.SimpleMemoComponent)&&K){let W=K.type;if(typeof W==="function")return W}if(typeof Y==="function")return Y;return null}function kR(){let J=R3.default,H=J.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;if(H&&"H"in H)return{get:()=>H.H,set:(K)=>{H.H=K}};let Y=J.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;if(Y){let K=Y.ReactCurrentDispatcher;if(K&&"current"in K)return{get:()=>K.current,set:(W)=>{K.current=W}}}return null}function yR(J){let H=J.split(`
`),Y=[/source-location/,/\/dist\/index\./,/node_modules\//,/react-dom/,/react\.development/,/react\.production/,/chunk-[A-Z0-9]+/i,/react-stack-bottom-frame/,/react-reconciler/,/scheduler/,/<anonymous>/],K=/^\s*at\s+(?:.*?\s+\()?(.+?):(\d+):(\d+)\)?$/,W=/^[^@]*@(.+?):(\d+):(\d+)$/;for(let O of H){let A=O.trim();if(!A)continue;if(Y.some((x)=>x.test(A)))continue;let C=K.exec(A)||W.exec(A);if(C)return{fileName:C[1],line:parseInt(C[2],10),column:parseInt(C[3],10)}}return null}function gR(J){let H=J;return H=H.replace(/[?#].*$/,""),H=H.replace(/^turbopack:\/\/\/\[project\]\//,""),H=H.replace(/^webpack-internal:\/\/\/\.\//,""),H=H.replace(/^webpack-internal:\/\/\//,""),H=H.replace(/^webpack:\/\/\/\.\//,""),H=H.replace(/^webpack:\/\/\//,""),H=H.replace(/^turbopack:\/\/\//,""),H=H.replace(/^https?:\/\/[^/]+\//,""),H=H.replace(/^file:\/\/\//,"/"),H=H.replace(/^\([^)]+\)\/\.\//,""),H=H.replace(/^\.\//,""),H}function bR(J){let H=vR(J);if(!H)return null;if(lz.has(H))return lz.get(H);let Y=kR();if(!Y)return lz.set(H,null),null;let K=Y.get(),W=null;try{let O=new Proxy({},{get(){throw Error("probe")}});Y.set(O);try{H({})}catch(A){if(A instanceof Error&&A.message==="probe"&&A.stack){let C=yR(A.stack);if(C)W={fileName:gR(C.fileName),lineNumber:C.line,columnNumber:C.column,componentName:DB(J)||void 0}}}}finally{Y.set(K)}return lz.set(H,W),W}function fR(J,H=15){let Y=J,K=0;while(Y&&K<H){let W=bR(Y);if(W)return W;Y=Y.return,K++}return null}function EH(J){let H=IR(J);if(!H)return{found:!1,reason:"no-fiber",isReactApp:!1,isProduction:!1};let Y=xR(H);if(!Y)Y=SR(H);if(Y?.source)return{found:!0,source:{fileName:Y.source.fileName,lineNumber:Y.source.lineNumber,columnNumber:Y.source.columnNumber,componentName:Y.componentName||void 0},isReactApp:!0,isProduction:!1};let K=fR(H);if(K)return{found:!0,source:K,isReactApp:!0,isProduction:!1};return{found:!1,reason:"no-debug-source",isReactApp:!0,isProduction:!1}}function mR(J,H="path"){let{fileName:Y,lineNumber:K,columnNumber:W}=J,O=`${Y}:${K}`;if(W!==void 0)O+=`:${W}`;if(H==="vscode")return`vscode://file${Y.startsWith("/")?"":"/"}${O}`;return O}function hR(J,H=10){let Y=J,K=0;while(Y&&K<H){let W=EH(Y);if(W.found)return W;Y=Y.parentElement,K++}return EH(J)}var uR=`.styles-module__toolbar___wNsdK svg[fill=none],
.styles-module__markersLayer___-25j1 svg[fill=none],
.styles-module__fixedMarkersLayer___ffyX6 svg[fill=none] {
  fill: none !important;
}
.styles-module__toolbar___wNsdK svg[fill=none] :not([fill]),
.styles-module__markersLayer___-25j1 svg[fill=none] :not([fill]),
.styles-module__fixedMarkersLayer___ffyX6 svg[fill=none] :not([fill]) {
  fill: none !important;
}

.styles-module__controlsContent___9GJWU :where(button, input, select, textarea, label) {
  background: unset;
  border: unset;
  border-radius: unset;
  padding: unset;
  margin: unset;
  color: unset;
  font-family: unset;
  font-weight: unset;
  font-style: unset;
  line-height: unset;
  letter-spacing: unset;
  text-transform: unset;
  text-decoration: unset;
  box-shadow: unset;
  outline: unset;
}

@keyframes styles-module__toolbarEnter___u8RRu {
  from {
    opacity: 0;
    transform: scale(0.5) rotate(90deg);
  }
  to {
    opacity: 1;
    transform: scale(1) rotate(0deg);
  }
}
@keyframes styles-module__toolbarHide___y8kaT {
  from {
    opacity: 1;
    transform: scale(1);
  }
  to {
    opacity: 0;
    transform: scale(0.8);
  }
}
@keyframes styles-module__badgeEnter___mVQLj {
  from {
    opacity: 0;
    transform: scale(0);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}
@keyframes styles-module__scaleIn___c-r1K {
  from {
    opacity: 0;
    transform: scale(0.85);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}
@keyframes styles-module__scaleOut___Wctwz {
  from {
    opacity: 1;
    transform: scale(1);
  }
  to {
    opacity: 0;
    transform: scale(0.85);
  }
}
@keyframes styles-module__slideUp___kgD36 {
  from {
    opacity: 0;
    transform: scale(0.85) translateY(8px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}
@keyframes styles-module__slideDown___zcdje {
  from {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
  to {
    opacity: 0;
    transform: scale(0.85) translateY(8px);
  }
}
@keyframes styles-module__fadeIn___b9qmf {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
@keyframes styles-module__fadeOut___6Ut6- {
  from {
    opacity: 1;
  }
  to {
    opacity: 0;
  }
}
@keyframes styles-module__hoverHighlightIn___6WYHY {
  from {
    opacity: 0;
    transform: scale(0.98);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}
@keyframes styles-module__hoverTooltipIn___FYGQx {
  from {
    opacity: 0;
    transform: scale(0.95) translateY(4px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}
.styles-module__disableTransitions___EopxO :is(*, *::before, *::after) {
  transition: none !important;
}

.styles-module__toolbar___wNsdK {
  position: fixed;
  bottom: 1.25rem;
  right: 1.25rem;
  width: 337px;
  z-index: 100000;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  pointer-events: none;
  transition: left 0s, top 0s, right 0s, bottom 0s;
}

:where(.styles-module__toolbar___wNsdK) {
  bottom: 1.25rem;
  right: 1.25rem;
}

.styles-module__toolbarContainer___dIhma {
  position: relative;
  user-select: none;
  margin-left: auto;
  align-self: flex-end;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #1a1a1a;
  color: #fff;
  border: none;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2), 0 4px 16px rgba(0, 0, 0, 0.1);
  pointer-events: auto;
  transition: width 0.4s cubic-bezier(0.19, 1, 0.22, 1), transform 0.4s cubic-bezier(0.19, 1, 0.22, 1);
}
.styles-module__toolbarContainer___dIhma.styles-module__entrance___sgHd8 {
  animation: styles-module__toolbarEnter___u8RRu 0.5s cubic-bezier(0.34, 1.2, 0.64, 1) forwards;
}
.styles-module__toolbarContainer___dIhma.styles-module__hiding___1td44 {
  animation: styles-module__toolbarHide___y8kaT 0.4s cubic-bezier(0.4, 0, 1, 1) forwards;
  pointer-events: none;
}
.styles-module__toolbarContainer___dIhma.styles-module__collapsed___Rydsn {
  width: 44px;
  height: 44px;
  border-radius: 22px;
  padding: 0;
  cursor: pointer;
}
.styles-module__toolbarContainer___dIhma.styles-module__collapsed___Rydsn svg {
  margin-top: -1px;
}
.styles-module__toolbarContainer___dIhma.styles-module__collapsed___Rydsn:hover {
  background: #2a2a2a;
}
.styles-module__toolbarContainer___dIhma.styles-module__collapsed___Rydsn:active {
  transform: scale(0.95);
}
.styles-module__toolbarContainer___dIhma.styles-module__expanded___ofKPx {
  height: 44px;
  border-radius: 1.5rem;
  padding: 0.375rem;
  width: 297px;
}
.styles-module__toolbarContainer___dIhma.styles-module__expanded___ofKPx.styles-module__serverConnected___Gfbou {
  width: 337px;
}

.styles-module__toggleContent___0yfyP {
  position: absolute;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: opacity 0.1s cubic-bezier(0.19, 1, 0.22, 1);
}
.styles-module__toggleContent___0yfyP.styles-module__visible___KHwEW {
  opacity: 1;
  visibility: visible;
  pointer-events: auto;
}
.styles-module__toggleContent___0yfyP.styles-module__hidden___Ae8H4 {
  opacity: 0;
  pointer-events: none;
}

.styles-module__controlsContent___9GJWU {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  transition: filter 0.8s cubic-bezier(0.19, 1, 0.22, 1), opacity 0.8s cubic-bezier(0.19, 1, 0.22, 1), transform 0.6s cubic-bezier(0.19, 1, 0.22, 1);
}
.styles-module__controlsContent___9GJWU.styles-module__visible___KHwEW {
  opacity: 1;
  filter: blur(0px);
  transform: scale(1);
  visibility: visible;
  pointer-events: auto;
}
.styles-module__controlsContent___9GJWU.styles-module__hidden___Ae8H4 {
  pointer-events: none;
  opacity: 0;
  filter: blur(10px);
  transform: scale(0.4);
}

.styles-module__badge___2XsgF {
  position: absolute;
  top: -13px;
  right: -13px;
  user-select: none;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 9px;
  background-color: var(--agentation-color-accent);
  color: white;
  font-size: 0.625rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15), inset 0 0 0 1px rgba(255, 255, 255, 0.04);
  opacity: 1;
  transition: transform 0.3s ease, opacity 0.2s ease;
  transform: scale(1);
}
.styles-module__badge___2XsgF.styles-module__fadeOut___6Ut6- {
  opacity: 0;
  transform: scale(0);
  pointer-events: none;
}
.styles-module__badge___2XsgF.styles-module__entrance___sgHd8 {
  animation: styles-module__badgeEnter___mVQLj 0.3s cubic-bezier(0.34, 1.2, 0.64, 1) 0.4s both;
}

.styles-module__controlButton___8Q0jc {
  position: relative;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  border-radius: 50%;
  border: none;
  background: transparent;
  color: rgba(255, 255, 255, 0.85);
  transition: background-color 0.15s ease, color 0.15s ease, transform 0.1s ease, opacity 0.2s ease;
}
.styles-module__controlButton___8Q0jc:hover:not(:disabled):not([data-active=true]):not([data-failed=true]):not([data-auto-sync=true]):not([data-error=true]):not([data-no-hover=true]) {
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
}
.styles-module__controlButton___8Q0jc:active:not(:disabled) {
  transform: scale(0.92);
}
.styles-module__controlButton___8Q0jc:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}
.styles-module__controlButton___8Q0jc[data-active=true] {
  color: var(--agentation-color-blue);
  background-color: color-mix(in srgb, var(--agentation-color-blue) 25%, transparent);
}
.styles-module__controlButton___8Q0jc[data-error=true] {
  color: var(--agentation-color-red);
  background-color: color-mix(in srgb, var(--agentation-color-red) 25%, transparent);
}
.styles-module__controlButton___8Q0jc[data-danger]:hover:not(:disabled):not([data-active=true]):not([data-failed=true]) {
  background-color: color-mix(in srgb, var(--agentation-color-red) 25%, transparent);
  color: var(--agentation-color-red);
}
.styles-module__controlButton___8Q0jc[data-no-hover=true], .styles-module__controlButton___8Q0jc.styles-module__statusShowing___te6iu {
  cursor: default;
  pointer-events: none;
  background: transparent !important;
}
.styles-module__controlButton___8Q0jc[data-auto-sync=true] {
  color: var(--agentation-color-green);
  background: transparent;
  cursor: default;
}
.styles-module__controlButton___8Q0jc[data-failed=true] {
  color: var(--agentation-color-red);
  background-color: color-mix(in srgb, var(--agentation-color-red) 25%, transparent);
}

.styles-module__buttonBadge___NeFWb {
  position: absolute;
  top: 0px;
  right: 0px;
  min-width: 16px;
  height: 16px;
  padding: 0 4px;
  border-radius: 8px;
  background-color: var(--agentation-color-accent);
  color: white;
  font-size: 0.625rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 0 2px #1a1a1a, 0 1px 3px rgba(0, 0, 0, 0.2);
  pointer-events: none;
}
[data-agentation-theme=light] .styles-module__buttonBadge___NeFWb {
  box-shadow: 0 0 0 2px #fff, 0 1px 3px rgba(0, 0, 0, 0.2);
}

@keyframes styles-module__mcpIndicatorPulseConnected___EDodZ {
  0%, 100% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-green) 50%, transparent);
  }
  50% {
    box-shadow: 0 0 0 5px color-mix(in srgb, var(--agentation-color-green) 0%, transparent);
  }
}
@keyframes styles-module__mcpIndicatorPulseConnecting___cCYte {
  0%, 100% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-yellow) 50%, transparent);
  }
  50% {
    box-shadow: 0 0 0 5px color-mix(in srgb, var(--agentation-color-yellow) 0%, transparent);
  }
}
.styles-module__mcpIndicator___zGJeL {
  position: absolute;
  top: 3px;
  right: 3px;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  pointer-events: none;
  transition: background-color 0.3s ease, opacity 0.15s ease, transform 0.15s ease;
  opacity: 1;
  transform: scale(1);
}
.styles-module__mcpIndicator___zGJeL.styles-module__connected___7c28g {
  background-color: var(--agentation-color-green);
  animation: styles-module__mcpIndicatorPulseConnected___EDodZ 2.5s ease-in-out infinite;
}
.styles-module__mcpIndicator___zGJeL.styles-module__connecting___uo-CW {
  background-color: var(--agentation-color-yellow);
  animation: styles-module__mcpIndicatorPulseConnecting___cCYte 1.5s ease-in-out infinite;
}
.styles-module__mcpIndicator___zGJeL.styles-module__hidden___Ae8H4 {
  opacity: 0;
  transform: scale(0);
  animation: none;
}

@keyframes styles-module__connectionPulse___-Zycw {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.6;
    transform: scale(0.9);
  }
}
.styles-module__connectionIndicatorWrapper___L-e-3 {
  width: 8px;
  height: 34px;
  margin-left: 6px;
  margin-right: 6px;
}

.styles-module__connectionIndicator___afk9p {
  position: relative;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  opacity: 0;
  transition: opacity 0.3s ease, background-color 0.3s ease;
  cursor: default;
}

.styles-module__connectionIndicatorVisible___C-i5B {
  opacity: 1;
}

.styles-module__connectionIndicatorConnected___IY8pR {
  background-color: var(--agentation-color-green);
  animation: styles-module__connectionPulse___-Zycw 2.5s ease-in-out infinite;
}

.styles-module__connectionIndicatorDisconnected___kmpaZ {
  background-color: var(--agentation-color-red);
  animation: none;
}

.styles-module__connectionIndicatorConnecting___QmSLH {
  background-color: var(--agentation-color-yellow);
  animation: styles-module__connectionPulse___-Zycw 1s ease-in-out infinite;
}

.styles-module__buttonWrapper___rBcdv {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}
.styles-module__buttonWrapper___rBcdv:hover .styles-module__buttonTooltip___Burd9 {
  opacity: 1;
  visibility: visible;
  transform: translateX(-50%) scale(1);
  transition-delay: 0.85s;
}
.styles-module__buttonWrapper___rBcdv:has(.styles-module__controlButton___8Q0jc:disabled):hover .styles-module__buttonTooltip___Burd9 {
  opacity: 0;
  visibility: hidden;
}

.styles-module__tooltipsInSession___-0lHH .styles-module__buttonWrapper___rBcdv:hover .styles-module__buttonTooltip___Burd9 {
  transition-delay: 0s;
}

.styles-module__sendButtonWrapper___UUxG6 {
  width: 0;
  opacity: 0;
  overflow: hidden;
  pointer-events: none;
  margin-left: -0.375rem;
  transition: width 0.4s cubic-bezier(0.19, 1, 0.22, 1), opacity 0.3s cubic-bezier(0.19, 1, 0.22, 1), margin 0.4s cubic-bezier(0.19, 1, 0.22, 1);
}
.styles-module__sendButtonWrapper___UUxG6 .styles-module__controlButton___8Q0jc {
  transform: scale(0.8);
  transition: transform 0.4s cubic-bezier(0.19, 1, 0.22, 1);
}
.styles-module__sendButtonWrapper___UUxG6.styles-module__sendButtonVisible___WPSQU {
  width: 34px;
  opacity: 1;
  overflow: visible;
  pointer-events: auto;
  margin-left: 0;
}
.styles-module__sendButtonWrapper___UUxG6.styles-module__sendButtonVisible___WPSQU .styles-module__controlButton___8Q0jc {
  transform: scale(1);
}

.styles-module__buttonTooltip___Burd9 {
  position: absolute;
  bottom: calc(100% + 14px);
  left: 50%;
  transform: translateX(-50%) scale(0.95);
  padding: 6px 10px;
  background: #1a1a1a;
  color: rgba(255, 255, 255, 0.9);
  font-size: 12px;
  font-weight: 500;
  border-radius: 8px;
  white-space: nowrap;
  opacity: 0;
  visibility: hidden;
  pointer-events: none;
  z-index: 100001;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
  transition: opacity 0.135s ease, transform 0.135s ease, visibility 0.135s ease;
}
.styles-module__buttonTooltip___Burd9::after {
  content: "";
  position: absolute;
  top: calc(100% - 4px);
  left: 50%;
  transform: translateX(-50%) rotate(45deg);
  width: 8px;
  height: 8px;
  background: #1a1a1a;
  border-radius: 0 0 2px 0;
}

.styles-module__shortcut___lEAQk {
  margin-left: 4px;
  opacity: 0.5;
}

.styles-module__tooltipBelow___m6ats .styles-module__buttonTooltip___Burd9 {
  bottom: auto;
  top: calc(100% + 14px);
  transform: translateX(-50%) scale(0.95);
}
.styles-module__tooltipBelow___m6ats .styles-module__buttonTooltip___Burd9::after {
  top: -4px;
  bottom: auto;
  border-radius: 2px 0 0 0;
}

.styles-module__tooltipBelow___m6ats .styles-module__buttonWrapper___rBcdv:hover .styles-module__buttonTooltip___Burd9 {
  transform: translateX(-50%) scale(1);
}

.styles-module__tooltipsHidden___VtLJG .styles-module__buttonTooltip___Burd9 {
  opacity: 0 !important;
  visibility: hidden !important;
  transition: none !important;
}

.styles-module__tooltipVisible___0jcCv,
.styles-module__tooltipsHidden___VtLJG .styles-module__tooltipVisible___0jcCv {
  opacity: 1 !important;
  visibility: visible !important;
  transform: translateX(-50%) scale(1) !important;
  transition-delay: 0s !important;
}

.styles-module__buttonWrapperAlignLeft___myzIp .styles-module__buttonTooltip___Burd9 {
  left: 50%;
  transform: translateX(-12px) scale(0.95);
}
.styles-module__buttonWrapperAlignLeft___myzIp .styles-module__buttonTooltip___Burd9::after {
  left: 16px;
}
.styles-module__buttonWrapperAlignLeft___myzIp:hover .styles-module__buttonTooltip___Burd9 {
  transform: translateX(-12px) scale(1);
}

.styles-module__tooltipBelow___m6ats .styles-module__buttonWrapperAlignLeft___myzIp .styles-module__buttonTooltip___Burd9 {
  transform: translateX(-12px) scale(0.95);
}
.styles-module__tooltipBelow___m6ats .styles-module__buttonWrapperAlignLeft___myzIp:hover .styles-module__buttonTooltip___Burd9 {
  transform: translateX(-12px) scale(1);
}

.styles-module__buttonWrapperAlignRight___HCQFR .styles-module__buttonTooltip___Burd9 {
  left: 50%;
  transform: translateX(calc(-100% + 12px)) scale(0.95);
}
.styles-module__buttonWrapperAlignRight___HCQFR .styles-module__buttonTooltip___Burd9::after {
  left: auto;
  right: 8px;
}
.styles-module__buttonWrapperAlignRight___HCQFR:hover .styles-module__buttonTooltip___Burd9 {
  transform: translateX(calc(-100% + 12px)) scale(1);
}

.styles-module__tooltipBelow___m6ats .styles-module__buttonWrapperAlignRight___HCQFR .styles-module__buttonTooltip___Burd9 {
  transform: translateX(calc(-100% + 12px)) scale(0.95);
}
.styles-module__tooltipBelow___m6ats .styles-module__buttonWrapperAlignRight___HCQFR:hover .styles-module__buttonTooltip___Burd9 {
  transform: translateX(calc(-100% + 12px)) scale(1);
}

.styles-module__divider___c--s1 {
  width: 1px;
  height: 12px;
  background: rgba(255, 255, 255, 0.15);
  margin: 0 0.125rem;
}

.styles-module__overlay___Q1O9y {
  position: fixed;
  inset: 0;
  z-index: 99997;
  pointer-events: none;
}
.styles-module__overlay___Q1O9y > * {
  pointer-events: auto;
}

.styles-module__hoverHighlight___ogakW {
  position: fixed;
  border: 2px solid color-mix(in srgb, var(--agentation-color-accent) 50%, transparent);
  border-radius: 4px;
  background-color: color-mix(in srgb, var(--agentation-color-accent) 4%, transparent);
  pointer-events: none !important;
  box-sizing: border-box;
  will-change: opacity;
  contain: layout style;
}
.styles-module__hoverHighlight___ogakW.styles-module__enter___WFIki {
  animation: styles-module__hoverHighlightIn___6WYHY 0.12s ease-out forwards;
}

.styles-module__multiSelectOutline___cSJ-m {
  position: fixed;
  border: 2px dashed color-mix(in srgb, var(--agentation-color-green) 60%, transparent);
  border-radius: 4px;
  pointer-events: none !important;
  background-color: color-mix(in srgb, var(--agentation-color-green) 5%, transparent);
  box-sizing: border-box;
  will-change: opacity;
}
.styles-module__multiSelectOutline___cSJ-m.styles-module__enter___WFIki {
  animation: styles-module__fadeIn___b9qmf 0.15s ease-out forwards;
}
.styles-module__multiSelectOutline___cSJ-m.styles-module__exit___fyOJ0 {
  animation: styles-module__fadeOut___6Ut6- 0.15s ease-out forwards;
}

.styles-module__singleSelectOutline___QhX-O {
  position: fixed;
  border: 2px solid color-mix(in srgb, var(--agentation-color-blue) 60%, transparent);
  border-radius: 4px;
  pointer-events: none !important;
  background-color: color-mix(in srgb, var(--agentation-color-blue) 5%, transparent);
  box-sizing: border-box;
  will-change: opacity;
}
.styles-module__singleSelectOutline___QhX-O.styles-module__enter___WFIki {
  animation: styles-module__fadeIn___b9qmf 0.15s ease-out forwards;
}
.styles-module__singleSelectOutline___QhX-O.styles-module__exit___fyOJ0 {
  animation: styles-module__fadeOut___6Ut6- 0.15s ease-out forwards;
}

.styles-module__hoverTooltip___bvLk7 {
  position: fixed;
  font-size: 0.6875rem;
  font-weight: 500;
  color: #fff;
  background: rgba(0, 0, 0, 0.85);
  padding: 0.35rem 0.6rem;
  border-radius: 0.375rem;
  pointer-events: none !important;
  white-space: nowrap;
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
}
.styles-module__hoverTooltip___bvLk7.styles-module__enter___WFIki {
  animation: styles-module__hoverTooltipIn___FYGQx 0.1s ease-out forwards;
}

.styles-module__hoverReactPath___gx1IJ {
  font-size: 0.625rem;
  color: rgba(255, 255, 255, 0.6);
  margin-bottom: 0.15rem;
  overflow: hidden;
  text-overflow: ellipsis;
}

.styles-module__hoverElementName___QMLMl {
  overflow: hidden;
  text-overflow: ellipsis;
}

.styles-module__markersLayer___-25j1 {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 0;
  z-index: 99998;
  pointer-events: none;
}
.styles-module__markersLayer___-25j1 > * {
  pointer-events: auto;
}

.styles-module__fixedMarkersLayer___ffyX6 {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 99998;
  pointer-events: none;
}
.styles-module__fixedMarkersLayer___ffyX6 > * {
  pointer-events: auto;
}

.styles-module__marker___6sQrs {
  position: absolute;
  width: 22px;
  height: 22px;
  background: var(--agentation-color-blue);
  color: white;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.6875rem;
  font-weight: 600;
  transform: translate(-50%, -50%) scale(1);
  opacity: 1;
  cursor: pointer;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2), inset 0 0 0 1px rgba(0, 0, 0, 0.04);
  user-select: none;
  will-change: transform, opacity;
  contain: layout style;
  z-index: 1;
}
.styles-module__marker___6sQrs:hover {
  z-index: 2;
}
.styles-module__marker___6sQrs:not(.styles-module__enter___WFIki):not(.styles-module__exit___fyOJ0):not(.styles-module__clearing___FQ--7) {
  transition: background-color 0.15s ease, transform 0.1s ease;
}
.styles-module__marker___6sQrs.styles-module__enter___WFIki {
  animation: styles-module__markerIn___5FaAP 0.25s cubic-bezier(0.22, 1, 0.36, 1) both;
}
.styles-module__marker___6sQrs.styles-module__exit___fyOJ0 {
  animation: styles-module__markerOut___GU5jX 0.2s ease-out both;
  pointer-events: none;
}
.styles-module__marker___6sQrs.styles-module__clearing___FQ--7 {
  animation: styles-module__markerOut___GU5jX 0.15s ease-out both;
  pointer-events: none;
}
.styles-module__marker___6sQrs:not(.styles-module__enter___WFIki):not(.styles-module__exit___fyOJ0):not(.styles-module__clearing___FQ--7):hover {
  transform: translate(-50%, -50%) scale(1.1);
}
.styles-module__marker___6sQrs.styles-module__pending___2IHLC {
  position: fixed;
  background-color: var(--agentation-color-blue);
  cursor: default;
}
.styles-module__marker___6sQrs.styles-module__fixed___dBMHC {
  position: fixed;
}
.styles-module__marker___6sQrs.styles-module__multiSelect___YWiuz {
  background-color: var(--agentation-color-green);
  width: 26px;
  height: 26px;
  border-radius: 6px;
  font-size: 0.75rem;
}
.styles-module__marker___6sQrs.styles-module__multiSelect___YWiuz.styles-module__pending___2IHLC {
  background-color: var(--agentation-color-green);
}
.styles-module__marker___6sQrs.styles-module__hovered___ZgXIy {
  background-color: var(--agentation-color-red);
}

.styles-module__renumber___nCTxD {
  display: block;
  animation: styles-module__renumberRoll___Wgbq3 0.2s ease-out;
}

@keyframes styles-module__renumberRoll___Wgbq3 {
  0% {
    transform: translateX(-40%);
    opacity: 0;
  }
  100% {
    transform: translateX(0);
    opacity: 1;
  }
}
.styles-module__markerTooltip___aLJID {
  position: absolute;
  top: calc(100% + 10px);
  left: 50%;
  transform: translateX(-50%) scale(0.909);
  z-index: 100002;
  background: #1a1a1a;
  padding: 8px 0.75rem;
  border-radius: 0.75rem;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-weight: 400;
  color: #fff;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.08);
  min-width: 120px;
  max-width: 200px;
  pointer-events: none;
  cursor: default;
}
.styles-module__markerTooltip___aLJID.styles-module__enter___WFIki {
  animation: styles-module__tooltipIn___0N31w 0.1s ease-out forwards;
}

.styles-module__markerQuote___FHmrz {
  display: block;
  font-size: 12px;
  font-style: italic;
  color: rgba(255, 255, 255, 0.6);
  margin-bottom: 0.3125rem;
  line-height: 1.4;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.styles-module__markerNote___QkrrS {
  display: block;
  font-size: 13px;
  font-weight: 400;
  line-height: 1.4;
  color: #fff;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  padding-bottom: 2px;
}

.styles-module__markerHint___2iF-6 {
  display: block;
  font-size: 0.625rem;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.6);
  margin-top: 0.375rem;
  white-space: nowrap;
}

.styles-module__settingsPanel___OxX3Y {
  position: absolute;
  right: 5px;
  bottom: calc(100% + 0.5rem);
  z-index: 1;
  overflow: hidden;
  background: #1c1c1c;
  border-radius: 1rem;
  padding: 13px 0 16px;
  min-width: 205px;
  cursor: default;
  opacity: 1;
  box-shadow: 0 1px 8px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.04);
  transition: background-color 0.25s ease, box-shadow 0.25s ease;
}
.styles-module__settingsPanel___OxX3Y::before, .styles-module__settingsPanel___OxX3Y::after {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  width: 16px;
  z-index: 2;
  pointer-events: none;
}
.styles-module__settingsPanel___OxX3Y::before {
  left: 0;
  background: linear-gradient(to right, #1c1c1c 0%, transparent 100%);
}
.styles-module__settingsPanel___OxX3Y::after {
  right: 0;
  background: linear-gradient(to left, #1c1c1c 0%, transparent 100%);
}
.styles-module__settingsPanel___OxX3Y .styles-module__settingsHeader___pwDY9,
.styles-module__settingsPanel___OxX3Y .styles-module__settingsBrand___0gJeM,
.styles-module__settingsPanel___OxX3Y .styles-module__settingsBrandSlash___uTG18,
.styles-module__settingsPanel___OxX3Y .styles-module__settingsVersion___TUcFq,
.styles-module__settingsPanel___OxX3Y .styles-module__settingsSection___m-YM2,
.styles-module__settingsPanel___OxX3Y .styles-module__settingsLabel___8UjfX,
.styles-module__settingsPanel___OxX3Y .styles-module__cycleButton___FMKfw,
.styles-module__settingsPanel___OxX3Y .styles-module__cycleDot___nPgLY,
.styles-module__settingsPanel___OxX3Y .styles-module__dropdownButton___16NPz,
.styles-module__settingsPanel___OxX3Y .styles-module__toggleLabel___Xm8Aa,
.styles-module__settingsPanel___OxX3Y .styles-module__customCheckbox___U39ax,
.styles-module__settingsPanel___OxX3Y .styles-module__sliderLabel___U8sPr,
.styles-module__settingsPanel___OxX3Y .styles-module__slider___GLdxp,
.styles-module__settingsPanel___OxX3Y .styles-module__themeToggle___2rUjA {
  transition: background-color 0.25s ease, color 0.25s ease, border-color 0.25s ease;
}
.styles-module__settingsPanel___OxX3Y.styles-module__enter___WFIki {
  opacity: 1;
  transform: translateY(0) scale(1);
  filter: blur(0px);
  transition: opacity 0.2s ease, transform 0.2s ease, filter 0.2s ease;
}
.styles-module__settingsPanel___OxX3Y.styles-module__exit___fyOJ0 {
  opacity: 0;
  transform: translateY(8px) scale(0.95);
  filter: blur(5px);
  pointer-events: none;
  transition: opacity 0.1s ease, transform 0.1s ease, filter 0.1s ease;
}
[data-agentation-theme=dark] .styles-module__settingsPanel___OxX3Y {
  background: #1a1a1a;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.08);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___OxX3Y .styles-module__settingsLabel___8UjfX {
  color: rgba(255, 255, 255, 0.6);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___OxX3Y .styles-module__settingsOption___UNa12 {
  color: rgba(255, 255, 255, 0.85);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___OxX3Y .styles-module__settingsOption___UNa12:hover {
  background: rgba(255, 255, 255, 0.1);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___OxX3Y .styles-module__settingsOption___UNa12.styles-module__selected___OwRqP {
  background: rgba(255, 255, 255, 0.15);
  color: #fff;
}
[data-agentation-theme=dark] .styles-module__settingsPanel___OxX3Y .styles-module__toggleLabel___Xm8Aa {
  color: rgba(255, 255, 255, 0.85);
}

.styles-module__settingsPanelContainer___Xksv8 {
  overflow: visible;
  position: relative;
  display: flex;
  padding: 0 1rem;
}

.styles-module__settingsPage___6YfHH {
  min-width: 100%;
  flex-shrink: 0;
  transition: transform 0.2s ease, opacity 0.2s ease;
  transition-delay: 0s;
  opacity: 1;
}

.styles-module__settingsPage___6YfHH.styles-module__slideLeft___Ps01J {
  transform: translateX(-24px);
  opacity: 0;
  pointer-events: none;
}

.styles-module__automationsPage___uvCq6 {
  position: absolute;
  top: 0;
  left: 24px;
  width: 100%;
  height: 100%;
  padding: 3px 1rem 0;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  transition: transform 0.2s ease, opacity 0.2s ease;
  opacity: 0;
  pointer-events: none;
}

.styles-module__automationsPage___uvCq6.styles-module__slideIn___4-qXe {
  transform: translateX(-24px);
  opacity: 1;
  pointer-events: auto;
}

.styles-module__settingsNavLink___wCzJt {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 0;
  border: none;
  background: transparent;
  font-family: inherit;
  font-size: 0.8125rem;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.5);
  cursor: pointer;
  transition: color 0.15s ease;
}
.styles-module__settingsNavLink___wCzJt:hover {
  color: rgba(255, 255, 255, 0.9);
}
[data-agentation-theme=light] .styles-module__settingsNavLink___wCzJt {
  color: rgba(0, 0, 0, 0.5);
}
[data-agentation-theme=light] .styles-module__settingsNavLink___wCzJt:hover {
  color: rgba(0, 0, 0, 0.8);
}
.styles-module__settingsNavLink___wCzJt svg {
  color: rgba(255, 255, 255, 0.4);
  transition: color 0.15s ease;
}
.styles-module__settingsNavLink___wCzJt:hover svg {
  color: #fff;
}
[data-agentation-theme=light] .styles-module__settingsNavLink___wCzJt svg {
  color: rgba(0, 0, 0, 0.25);
}
[data-agentation-theme=light] .styles-module__settingsNavLink___wCzJt:hover svg {
  color: rgba(0, 0, 0, 0.8);
}

.styles-module__settingsNavLinkRight___ZWwhj {
  display: flex;
  align-items: center;
  gap: 6px;
}

.styles-module__mcpNavIndicator___cl9pO {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.styles-module__mcpNavIndicator___cl9pO.styles-module__connected___7c28g {
  background-color: var(--agentation-color-green);
  animation: styles-module__mcpPulse___uNggr 2.5s ease-in-out infinite;
}
.styles-module__mcpNavIndicator___cl9pO.styles-module__connecting___uo-CW {
  background-color: var(--agentation-color-yellow);
  animation: styles-module__mcpPulse___uNggr 1.5s ease-in-out infinite;
}

.styles-module__settingsBackButton___bIe2j {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 6px 0 12px 0;
  margin: -6px 0 0.5rem 0;
  border: none;
  border-bottom: 1px solid rgba(255, 255, 255, 0.07);
  border-radius: 0;
  background: transparent;
  font-family: inherit;
  font-size: 0.8125rem;
  font-weight: 500;
  letter-spacing: -0.15px;
  color: #fff;
  cursor: pointer;
  transition: transform 0.12s cubic-bezier(0.32, 0.72, 0, 1);
}
.styles-module__settingsBackButton___bIe2j svg {
  opacity: 0.4;
  flex-shrink: 0;
  transition: opacity 0.15s ease, transform 0.18s cubic-bezier(0.32, 0.72, 0, 1);
}
.styles-module__settingsBackButton___bIe2j:hover {
  border-bottom-color: rgba(255, 255, 255, 0.07);
}
.styles-module__settingsBackButton___bIe2j:hover svg {
  opacity: 1;
}
[data-agentation-theme=light] .styles-module__settingsBackButton___bIe2j {
  color: rgba(0, 0, 0, 0.85);
  border-bottom-color: rgba(0, 0, 0, 0.08);
}
[data-agentation-theme=light] .styles-module__settingsBackButton___bIe2j:hover {
  border-bottom-color: rgba(0, 0, 0, 0.08);
}

.styles-module__automationHeader___InP0r {
  display: flex;
  align-items: center;
  gap: 0.125rem;
  font-size: 0.8125rem;
  font-weight: 400;
  color: #fff;
}
[data-agentation-theme=light] .styles-module__automationHeader___InP0r {
  color: rgba(0, 0, 0, 0.85);
}

.styles-module__automationDescription___NKlmo {
  font-size: 0.6875rem;
  font-weight: 300;
  color: rgba(255, 255, 255, 0.5);
  margin-top: 2px;
  line-height: 14px;
}
[data-agentation-theme=light] .styles-module__automationDescription___NKlmo {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__learnMoreLink___8xv-x {
  color: rgba(255, 255, 255, 0.8);
  text-decoration: underline dotted;
  text-decoration-color: rgba(255, 255, 255, 0.2);
  text-underline-offset: 2px;
  transition: color 0.15s ease;
}
.styles-module__learnMoreLink___8xv-x:hover {
  color: #fff;
}
[data-agentation-theme=light] .styles-module__learnMoreLink___8xv-x {
  color: rgba(0, 0, 0, 0.6);
  text-decoration-color: rgba(0, 0, 0, 0.2);
}
[data-agentation-theme=light] .styles-module__learnMoreLink___8xv-x:hover {
  color: rgba(0, 0, 0, 0.85);
}

.styles-module__autoSendRow___UblX5 {
  display: flex;
  align-items: center;
  gap: 8px;
}

.styles-module__autoSendLabel___icDc2 {
  font-size: 0.6875rem;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.4);
  transition: color 0.15s ease;
}
.styles-module__autoSendLabel___icDc2.styles-module__active___-zoN6 {
  color: #66b8ff;
  color: color(display-p3 0.4 0.72 1);
}
[data-agentation-theme=light] .styles-module__autoSendLabel___icDc2 {
  color: rgba(0, 0, 0, 0.4);
}
[data-agentation-theme=light] .styles-module__autoSendLabel___icDc2.styles-module__active___-zoN6 {
  color: var(--agentation-color-blue);
}

.styles-module__webhookUrlInput___2375C {
  display: block;
  width: 100%;
  flex: 1;
  min-height: 60px;
  box-sizing: border-box;
  margin-top: 11px;
  padding: 8px 10px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.03);
  font-family: inherit;
  font-size: 0.75rem;
  font-weight: 400;
  color: #fff;
  outline: none;
  resize: none;
  user-select: text;
  transition: border-color 0.15s ease, background-color 0.15s ease, box-shadow 0.15s ease;
}
.styles-module__webhookUrlInput___2375C::placeholder {
  color: rgba(255, 255, 255, 0.3);
}
.styles-module__webhookUrlInput___2375C:focus {
  border-color: rgba(255, 255, 255, 0.3);
  background: rgba(255, 255, 255, 0.08);
}
[data-agentation-theme=light] .styles-module__webhookUrlInput___2375C {
  border-color: rgba(0, 0, 0, 0.1);
  background: rgba(0, 0, 0, 0.03);
  color: rgba(0, 0, 0, 0.85);
}
[data-agentation-theme=light] .styles-module__webhookUrlInput___2375C::placeholder {
  color: rgba(0, 0, 0, 0.3);
}
[data-agentation-theme=light] .styles-module__webhookUrlInput___2375C:focus {
  border-color: rgba(0, 0, 0, 0.25);
  background: rgba(0, 0, 0, 0.05);
}

.styles-module__settingsHeader___pwDY9 {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 24px;
  margin-bottom: 0.5rem;
  padding-bottom: 9px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.07);
}

.styles-module__settingsBrand___0gJeM {
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: -0.0094em;
  color: #fff;
  text-decoration: none;
}

.styles-module__settingsBrandSlash___uTG18 {
  color: var(--agentation-color-accent);
  transition: color 0.2s ease;
}

.styles-module__settingsVersion___TUcFq {
  font-size: 11px;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.4);
  margin-left: auto;
  letter-spacing: -0.0094em;
}

.styles-module__settingsSection___m-YM2 + .styles-module__settingsSection___m-YM2 {
  margin-top: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid rgba(255, 255, 255, 0.07);
}
.styles-module__settingsSection___m-YM2.styles-module__settingsSectionExtraPadding___jdhFV {
  padding-top: calc(0.5rem + 4px);
}

.styles-module__settingsSectionGrow___h-5HZ {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.styles-module__settingsRow___3sdhc {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 24px;
}
.styles-module__settingsRow___3sdhc.styles-module__settingsRowMarginTop___zA0Sp {
  margin-top: 8px;
}

.styles-module__dropdownContainer___BVnxe {
  position: relative;
}

.styles-module__dropdownButton___16NPz {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.25rem 0.5rem;
  border: none;
  border-radius: 0.375rem;
  background: transparent;
  font-size: 0.8125rem;
  font-weight: 600;
  color: #fff;
  cursor: pointer;
  transition: background-color 0.15s ease, color 0.15s ease;
  letter-spacing: -0.0094em;
}
.styles-module__dropdownButton___16NPz:hover {
  background: rgba(255, 255, 255, 0.08);
}
.styles-module__dropdownButton___16NPz svg {
  opacity: 0.6;
}

.styles-module__cycleButton___FMKfw {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0;
  border: none;
  background: transparent;
  font-size: 0.8125rem;
  font-weight: 500;
  color: #fff;
  cursor: pointer;
  letter-spacing: -0.0094em;
}
[data-agentation-theme=light] .styles-module__cycleButton___FMKfw {
  color: rgba(0, 0, 0, 0.85);
}
.styles-module__cycleButton___FMKfw:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.styles-module__settingsRowDisabled___EgS0V .styles-module__settingsLabel___8UjfX {
  color: rgba(255, 255, 255, 0.2);
}
[data-agentation-theme=light] .styles-module__settingsRowDisabled___EgS0V .styles-module__settingsLabel___8UjfX {
  color: rgba(0, 0, 0, 0.2);
}
.styles-module__settingsRowDisabled___EgS0V .styles-module__toggleSwitch___l4Ygm {
  opacity: 0.4;
  cursor: not-allowed;
}

@keyframes styles-module__cycleTextIn___Q6zJf {
  0% {
    opacity: 0;
    transform: translateY(-6px);
  }
  100% {
    opacity: 1;
    transform: translateY(0);
  }
}
.styles-module__cycleButtonText___fD1LR {
  display: inline-block;
  animation: styles-module__cycleTextIn___Q6zJf 0.2s ease-out;
}

.styles-module__cycleDots___LWuoQ {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.styles-module__cycleDot___nPgLY {
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.3);
  transform: scale(0.667);
  transition: background-color 0.25s ease-out, transform 0.25s ease-out;
}
.styles-module__cycleDot___nPgLY.styles-module__active___-zoN6 {
  background: #fff;
  transform: scale(1);
}
[data-agentation-theme=light] .styles-module__cycleDot___nPgLY {
  background: rgba(0, 0, 0, 0.2);
}
[data-agentation-theme=light] .styles-module__cycleDot___nPgLY.styles-module__active___-zoN6 {
  background: rgba(0, 0, 0, 0.7);
}

.styles-module__dropdownMenu___k73ER {
  position: absolute;
  right: 0;
  top: calc(100% + 0.25rem);
  background: #1a1a1a;
  border-radius: 0.5rem;
  padding: 0.25rem;
  min-width: 120px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.1);
  z-index: 10;
  animation: styles-module__scaleIn___c-r1K 0.15s ease-out;
}

.styles-module__dropdownItem___ylsLj {
  width: 100%;
  display: flex;
  align-items: center;
  padding: 0.5rem 0.625rem;
  border: none;
  border-radius: 0.375rem;
  background: transparent;
  font-size: 0.8125rem;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.85);
  cursor: pointer;
  text-align: left;
  transition: background-color 0.15s ease, color 0.15s ease;
  letter-spacing: -0.0094em;
}
.styles-module__dropdownItem___ylsLj:hover {
  background: rgba(255, 255, 255, 0.08);
}
.styles-module__dropdownItem___ylsLj.styles-module__selected___OwRqP {
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
  font-weight: 600;
}

.styles-module__settingsLabel___8UjfX {
  font-size: 0.8125rem;
  font-weight: 400;
  letter-spacing: -0.0094em;
  color: rgba(255, 255, 255, 0.5);
  display: flex;
  align-items: center;
  gap: 0.125rem;
}
[data-agentation-theme=light] .styles-module__settingsLabel___8UjfX {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__settingsLabelMarker___ewdtV {
  padding-top: 3px;
  margin-bottom: 10px;
}

.styles-module__settingsOptions___LyrBA {
  display: flex;
  gap: 0.25rem;
}

.styles-module__settingsOption___UNa12 {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.25rem;
  padding: 0.375rem 0.5rem;
  border: none;
  border-radius: 0.375rem;
  background: transparent;
  font-size: 0.6875rem;
  font-weight: 500;
  color: rgba(0, 0, 0, 0.7);
  cursor: pointer;
  transition: background-color 0.15s ease, color 0.15s ease;
}
.styles-module__settingsOption___UNa12:hover {
  background: rgba(0, 0, 0, 0.05);
}
.styles-module__settingsOption___UNa12.styles-module__selected___OwRqP {
  background: color-mix(in srgb, var(--agentation-color-blue) 15%, transparent);
  color: var(--agentation-color-blue);
}

.styles-module__sliderContainer___ducXj {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.styles-module__slider___GLdxp {
  -webkit-appearance: none;
  appearance: none;
  width: 100%;
  height: 4px;
  background: rgba(255, 255, 255, 0.15);
  border-radius: 2px;
  outline: none;
  cursor: pointer;
}
.styles-module__slider___GLdxp::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 14px;
  height: 14px;
  background: white;
  border-radius: 50%;
  cursor: pointer;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
}
.styles-module__slider___GLdxp::-moz-range-thumb {
  width: 14px;
  height: 14px;
  background: white;
  border: none;
  border-radius: 50%;
  cursor: pointer;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
}
.styles-module__slider___GLdxp:hover::-webkit-slider-thumb {
  transform: scale(1.15);
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.4);
}
.styles-module__slider___GLdxp:hover::-moz-range-thumb {
  transform: scale(1.15);
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.4);
}

.styles-module__sliderLabels___FhLDB {
  display: flex;
  justify-content: space-between;
}

.styles-module__sliderLabel___U8sPr {
  font-size: 0.625rem;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.4);
  cursor: pointer;
  transition: color 0.15s ease;
}
.styles-module__sliderLabel___U8sPr:hover {
  color: rgba(255, 255, 255, 0.7);
}
.styles-module__sliderLabel___U8sPr.styles-module__active___-zoN6 {
  color: rgba(255, 255, 255, 0.9);
}

.styles-module__colorOptions___iHCNX {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.375rem;
  margin-bottom: 1px;
}

.styles-module__colorOption___IodiY {
  display: block;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  border: 2px solid transparent;
  background-color: var(--swatch);
  cursor: pointer;
  transition: transform 0.2s cubic-bezier(0.25, 1, 0.5, 1);
}
@supports (color: color(display-p3 0 0 0)) {
  .styles-module__colorOption___IodiY {
    background-color: var(--swatch-p3);
  }
}
.styles-module__colorOption___IodiY:hover {
  transform: scale(1.15);
}
.styles-module__colorOption___IodiY.styles-module__selected___OwRqP {
  transform: scale(0.83);
}

.styles-module__colorOptionRing___U2xpo {
  display: flex;
  width: 24px;
  height: 24px;
  border: 2px solid transparent;
  border-radius: 50%;
  transition: border-color 0.3s ease;
}
.styles-module__colorOptionRing___U2xpo.styles-module__selected___OwRqP {
  border-color: var(--swatch);
}
@supports (color: color(display-p3 0 0 0)) {
  .styles-module__colorOptionRing___U2xpo.styles-module__selected___OwRqP {
    border-color: var(--swatch-p3);
  }
}

.styles-module__settingsToggle___fBrFn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}
.styles-module__settingsToggle___fBrFn + .styles-module__settingsToggle___fBrFn {
  margin-top: calc(0.5rem + 6px);
}
.styles-module__settingsToggle___fBrFn input[type=checkbox] {
  position: absolute;
  opacity: 0;
  width: 0;
  height: 0;
}
.styles-module__settingsToggle___fBrFn.styles-module__settingsToggleMarginBottom___MZUyF {
  margin-bottom: calc(0.5rem + 6px);
}

.styles-module__customCheckbox___U39ax {
  position: relative;
  width: 14px;
  height: 14px;
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.05);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: background-color 0.25s ease, border-color 0.25s ease;
}
.styles-module__customCheckbox___U39ax svg {
  color: #1a1a1a;
  opacity: 1;
  transition: opacity 0.15s ease;
}
input[type=checkbox]:checked + .styles-module__customCheckbox___U39ax {
  border-color: rgba(255, 255, 255, 0.3);
  background: rgb(255, 255, 255);
}
[data-agentation-theme=light] .styles-module__customCheckbox___U39ax {
  border: 1px solid rgba(0, 0, 0, 0.15);
  background: #fff;
}
[data-agentation-theme=light] .styles-module__customCheckbox___U39ax.styles-module__checked___mnZLo {
  border-color: #1a1a1a;
  background: #1a1a1a;
}
[data-agentation-theme=light] .styles-module__customCheckbox___U39ax.styles-module__checked___mnZLo svg {
  color: #fff;
}

.styles-module__toggleLabel___Xm8Aa {
  font-size: 0.8125rem;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.5);
  letter-spacing: -0.0094em;
  display: flex;
  align-items: center;
  gap: 0.25rem;
}
[data-agentation-theme=light] .styles-module__toggleLabel___Xm8Aa {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__toggleSwitch___l4Ygm {
  position: relative;
  display: inline-block;
  width: 24px;
  height: 16px;
  flex-shrink: 0;
  cursor: pointer;
  transition: background-color 0.2s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}
.styles-module__toggleSwitch___l4Ygm input {
  opacity: 0;
  width: 0;
  height: 0;
}
.styles-module__toggleSwitch___l4Ygm input:checked + .styles-module__toggleSlider___wprIn {
  background-color: var(--agentation-color-blue);
}
.styles-module__toggleSwitch___l4Ygm input:checked + .styles-module__toggleSlider___wprIn::before {
  transform: translateX(8px);
}
.styles-module__toggleSwitch___l4Ygm.styles-module__disabled___332Jw {
  opacity: 0.4;
}
.styles-module__toggleSwitch___l4Ygm.styles-module__disabled___332Jw .styles-module__toggleSlider___wprIn {
  cursor: not-allowed;
}

.styles-module__toggleSlider___wprIn {
  position: absolute;
  cursor: pointer;
  inset: 0;
  border-radius: 16px;
  background: #484848;
}
[data-agentation-theme=light] .styles-module__toggleSlider___wprIn {
  background: #dddddd;
}
.styles-module__toggleSlider___wprIn::before {
  content: "";
  position: absolute;
  height: 12px;
  width: 12px;
  left: 2px;
  bottom: 2px;
  background: white;
  border-radius: 50%;
  transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

@keyframes styles-module__mcpPulse___uNggr {
  0% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-green) 50%, transparent);
  }
  70% {
    box-shadow: 0 0 0 6px color-mix(in srgb, var(--agentation-color-green) 0%, transparent);
  }
  100% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-green) 0%, transparent);
  }
}
@keyframes styles-module__mcpPulseError___fov9B {
  0% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-red) 50%, transparent);
  }
  70% {
    box-shadow: 0 0 0 6px color-mix(in srgb, var(--agentation-color-red) 0%, transparent);
  }
  100% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-red) 0%, transparent);
  }
}
.styles-module__mcpStatusDot___ibgkc {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.styles-module__mcpStatusDot___ibgkc.styles-module__connecting___uo-CW {
  background-color: var(--agentation-color-yellow);
  animation: styles-module__mcpPulse___uNggr 1.5s infinite;
}
.styles-module__mcpStatusDot___ibgkc.styles-module__connected___7c28g {
  background-color: var(--agentation-color-green);
  animation: styles-module__mcpPulse___uNggr 2.5s ease-in-out infinite;
}
.styles-module__mcpStatusDot___ibgkc.styles-module__disconnected___cHPxR {
  background-color: var(--agentation-color-red);
  animation: styles-module__mcpPulseError___fov9B 2s infinite;
}

.styles-module__drawCanvas___7cG9U {
  position: fixed;
  inset: 0;
  z-index: 99996;
  pointer-events: none !important;
}
.styles-module__drawCanvas___7cG9U.styles-module__active___-zoN6 {
  pointer-events: auto !important;
  cursor: crosshair !important;
}
.styles-module__drawCanvas___7cG9U.styles-module__active___-zoN6[data-stroke-hover] {
  cursor: pointer !important;
}

.styles-module__dragSelection___kZLq2 {
  position: fixed;
  top: 0;
  left: 0;
  border: 2px solid color-mix(in srgb, var(--agentation-color-green) 60%, transparent);
  border-radius: 4px;
  background-color: color-mix(in srgb, var(--agentation-color-green) 8%, transparent);
  pointer-events: none;
  z-index: 99997;
  will-change: transform, width, height;
  contain: layout style;
}

.styles-module__dragCount___KM90j {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background-color: var(--agentation-color-green);
  color: white;
  font-size: 0.875rem;
  font-weight: 600;
  padding: 0.25rem 0.5rem;
  border-radius: 1rem;
  min-width: 1.5rem;
  text-align: center;
}

.styles-module__highlightsContainer___-0xzG {
  position: fixed;
  top: 0;
  left: 0;
  pointer-events: none;
  z-index: 99996;
}

.styles-module__selectedElementHighlight___fyVlI {
  position: fixed;
  top: 0;
  left: 0;
  border: 2px solid color-mix(in srgb, var(--agentation-color-green) 50%, transparent);
  border-radius: 4px;
  background: color-mix(in srgb, var(--agentation-color-green) 6%, transparent);
  pointer-events: none;
  will-change: transform, width, height;
  contain: layout style;
}

[data-agentation-theme=light] .styles-module__toolbarContainer___dIhma {
  background: #fff;
  color: rgba(0, 0, 0, 0.85);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08), 0 4px 16px rgba(0, 0, 0, 0.06), 0 0 0 1px rgba(0, 0, 0, 0.04);
}
[data-agentation-theme=light] .styles-module__toolbarContainer___dIhma.styles-module__collapsed___Rydsn:hover {
  background: #f5f5f5;
}
[data-agentation-theme=light] .styles-module__controlButton___8Q0jc {
  color: rgba(0, 0, 0, 0.5);
}
[data-agentation-theme=light] .styles-module__controlButton___8Q0jc:hover:not(:disabled):not([data-active=true]):not([data-failed=true]):not([data-auto-sync=true]):not([data-error=true]):not([data-no-hover=true]) {
  background: rgba(0, 0, 0, 0.06);
  color: rgba(0, 0, 0, 0.85);
}
[data-agentation-theme=light] .styles-module__controlButton___8Q0jc[data-active=true] {
  color: var(--agentation-color-blue);
  background: color-mix(in srgb, var(--agentation-color-blue) 15%, transparent);
}
[data-agentation-theme=light] .styles-module__controlButton___8Q0jc[data-error=true] {
  color: var(--agentation-color-red);
  background: color-mix(in srgb, var(--agentation-color-red) 15%, transparent);
}
[data-agentation-theme=light] .styles-module__controlButton___8Q0jc[data-danger]:hover:not(:disabled):not([data-active=true]):not([data-failed=true]) {
  color: var(--agentation-color-red);
  background: color-mix(in srgb, var(--agentation-color-red) 15%, transparent);
}
[data-agentation-theme=light] .styles-module__controlButton___8Q0jc[data-auto-sync=true] {
  color: var(--agentation-color-green);
  background: transparent;
}
[data-agentation-theme=light] .styles-module__controlButton___8Q0jc[data-failed=true] {
  color: var(--agentation-color-red);
  background: color-mix(in srgb, var(--agentation-color-red) 15%, transparent);
}
[data-agentation-theme=light] .styles-module__buttonTooltip___Burd9 {
  background: #fff;
  color: rgba(0, 0, 0, 0.85);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08), 0 4px 16px rgba(0, 0, 0, 0.06), 0 0 0 1px rgba(0, 0, 0, 0.04);
}
[data-agentation-theme=light] .styles-module__buttonTooltip___Burd9::after {
  background: #fff;
}
[data-agentation-theme=light] .styles-module__divider___c--s1 {
  background: rgba(0, 0, 0, 0.1);
}`,dR={toolbar:"styles-module__toolbar___wNsdK",markersLayer:"styles-module__markersLayer___-25j1",fixedMarkersLayer:"styles-module__fixedMarkersLayer___ffyX6",controlsContent:"styles-module__controlsContent___9GJWU",disableTransitions:"styles-module__disableTransitions___EopxO",toolbarContainer:"styles-module__toolbarContainer___dIhma",entrance:"styles-module__entrance___sgHd8",toolbarEnter:"styles-module__toolbarEnter___u8RRu",hiding:"styles-module__hiding___1td44",toolbarHide:"styles-module__toolbarHide___y8kaT",collapsed:"styles-module__collapsed___Rydsn",expanded:"styles-module__expanded___ofKPx",serverConnected:"styles-module__serverConnected___Gfbou",toggleContent:"styles-module__toggleContent___0yfyP",visible:"styles-module__visible___KHwEW",hidden:"styles-module__hidden___Ae8H4",badge:"styles-module__badge___2XsgF",fadeOut:"styles-module__fadeOut___6Ut6-",badgeEnter:"styles-module__badgeEnter___mVQLj",controlButton:"styles-module__controlButton___8Q0jc",statusShowing:"styles-module__statusShowing___te6iu",buttonBadge:"styles-module__buttonBadge___NeFWb",mcpIndicator:"styles-module__mcpIndicator___zGJeL",connected:"styles-module__connected___7c28g",mcpIndicatorPulseConnected:"styles-module__mcpIndicatorPulseConnected___EDodZ",connecting:"styles-module__connecting___uo-CW",mcpIndicatorPulseConnecting:"styles-module__mcpIndicatorPulseConnecting___cCYte",connectionIndicatorWrapper:"styles-module__connectionIndicatorWrapper___L-e-3",connectionIndicator:"styles-module__connectionIndicator___afk9p",connectionIndicatorVisible:"styles-module__connectionIndicatorVisible___C-i5B",connectionIndicatorConnected:"styles-module__connectionIndicatorConnected___IY8pR",connectionPulse:"styles-module__connectionPulse___-Zycw",connectionIndicatorDisconnected:"styles-module__connectionIndicatorDisconnected___kmpaZ",connectionIndicatorConnecting:"styles-module__connectionIndicatorConnecting___QmSLH",buttonWrapper:"styles-module__buttonWrapper___rBcdv",buttonTooltip:"styles-module__buttonTooltip___Burd9",tooltipsInSession:"styles-module__tooltipsInSession___-0lHH",sendButtonWrapper:"styles-module__sendButtonWrapper___UUxG6",sendButtonVisible:"styles-module__sendButtonVisible___WPSQU",shortcut:"styles-module__shortcut___lEAQk",tooltipBelow:"styles-module__tooltipBelow___m6ats",tooltipsHidden:"styles-module__tooltipsHidden___VtLJG",tooltipVisible:"styles-module__tooltipVisible___0jcCv",buttonWrapperAlignLeft:"styles-module__buttonWrapperAlignLeft___myzIp",buttonWrapperAlignRight:"styles-module__buttonWrapperAlignRight___HCQFR",divider:"styles-module__divider___c--s1",overlay:"styles-module__overlay___Q1O9y",hoverHighlight:"styles-module__hoverHighlight___ogakW",enter:"styles-module__enter___WFIki",hoverHighlightIn:"styles-module__hoverHighlightIn___6WYHY",multiSelectOutline:"styles-module__multiSelectOutline___cSJ-m",fadeIn:"styles-module__fadeIn___b9qmf",exit:"styles-module__exit___fyOJ0",singleSelectOutline:"styles-module__singleSelectOutline___QhX-O",hoverTooltip:"styles-module__hoverTooltip___bvLk7",hoverTooltipIn:"styles-module__hoverTooltipIn___FYGQx",hoverReactPath:"styles-module__hoverReactPath___gx1IJ",hoverElementName:"styles-module__hoverElementName___QMLMl",marker:"styles-module__marker___6sQrs",clearing:"styles-module__clearing___FQ--7",markerIn:"styles-module__markerIn___5FaAP",markerOut:"styles-module__markerOut___GU5jX",pending:"styles-module__pending___2IHLC",fixed:"styles-module__fixed___dBMHC",multiSelect:"styles-module__multiSelect___YWiuz",hovered:"styles-module__hovered___ZgXIy",renumber:"styles-module__renumber___nCTxD",renumberRoll:"styles-module__renumberRoll___Wgbq3",markerTooltip:"styles-module__markerTooltip___aLJID",tooltipIn:"styles-module__tooltipIn___0N31w",markerQuote:"styles-module__markerQuote___FHmrz",markerNote:"styles-module__markerNote___QkrrS",markerHint:"styles-module__markerHint___2iF-6",settingsPanel:"styles-module__settingsPanel___OxX3Y",settingsHeader:"styles-module__settingsHeader___pwDY9",settingsBrand:"styles-module__settingsBrand___0gJeM",settingsBrandSlash:"styles-module__settingsBrandSlash___uTG18",settingsVersion:"styles-module__settingsVersion___TUcFq",settingsSection:"styles-module__settingsSection___m-YM2",settingsLabel:"styles-module__settingsLabel___8UjfX",cycleButton:"styles-module__cycleButton___FMKfw",cycleDot:"styles-module__cycleDot___nPgLY",dropdownButton:"styles-module__dropdownButton___16NPz",toggleLabel:"styles-module__toggleLabel___Xm8Aa",customCheckbox:"styles-module__customCheckbox___U39ax",sliderLabel:"styles-module__sliderLabel___U8sPr",slider:"styles-module__slider___GLdxp",themeToggle:"styles-module__themeToggle___2rUjA",settingsOption:"styles-module__settingsOption___UNa12",selected:"styles-module__selected___OwRqP",settingsPanelContainer:"styles-module__settingsPanelContainer___Xksv8",settingsPage:"styles-module__settingsPage___6YfHH",slideLeft:"styles-module__slideLeft___Ps01J",automationsPage:"styles-module__automationsPage___uvCq6",slideIn:"styles-module__slideIn___4-qXe",settingsNavLink:"styles-module__settingsNavLink___wCzJt",settingsNavLinkRight:"styles-module__settingsNavLinkRight___ZWwhj",mcpNavIndicator:"styles-module__mcpNavIndicator___cl9pO",mcpPulse:"styles-module__mcpPulse___uNggr",settingsBackButton:"styles-module__settingsBackButton___bIe2j",automationHeader:"styles-module__automationHeader___InP0r",automationDescription:"styles-module__automationDescription___NKlmo",learnMoreLink:"styles-module__learnMoreLink___8xv-x",autoSendRow:"styles-module__autoSendRow___UblX5",autoSendLabel:"styles-module__autoSendLabel___icDc2",active:"styles-module__active___-zoN6",webhookUrlInput:"styles-module__webhookUrlInput___2375C",settingsSectionExtraPadding:"styles-module__settingsSectionExtraPadding___jdhFV",settingsSectionGrow:"styles-module__settingsSectionGrow___h-5HZ",settingsRow:"styles-module__settingsRow___3sdhc",settingsRowMarginTop:"styles-module__settingsRowMarginTop___zA0Sp",dropdownContainer:"styles-module__dropdownContainer___BVnxe",settingsRowDisabled:"styles-module__settingsRowDisabled___EgS0V",toggleSwitch:"styles-module__toggleSwitch___l4Ygm",cycleButtonText:"styles-module__cycleButtonText___fD1LR",cycleTextIn:"styles-module__cycleTextIn___Q6zJf",cycleDots:"styles-module__cycleDots___LWuoQ",dropdownMenu:"styles-module__dropdownMenu___k73ER",scaleIn:"styles-module__scaleIn___c-r1K",dropdownItem:"styles-module__dropdownItem___ylsLj",settingsLabelMarker:"styles-module__settingsLabelMarker___ewdtV",settingsOptions:"styles-module__settingsOptions___LyrBA",sliderContainer:"styles-module__sliderContainer___ducXj",sliderLabels:"styles-module__sliderLabels___FhLDB",colorOptions:"styles-module__colorOptions___iHCNX",colorOption:"styles-module__colorOption___IodiY",colorOptionRing:"styles-module__colorOptionRing___U2xpo",settingsToggle:"styles-module__settingsToggle___fBrFn",settingsToggleMarginBottom:"styles-module__settingsToggleMarginBottom___MZUyF",checked:"styles-module__checked___mnZLo",toggleSlider:"styles-module__toggleSlider___wprIn",disabled:"styles-module__disabled___332Jw",mcpStatusDot:"styles-module__mcpStatusDot___ibgkc",disconnected:"styles-module__disconnected___cHPxR",mcpPulseError:"styles-module__mcpPulseError___fov9B",drawCanvas:"styles-module__drawCanvas___7cG9U",dragSelection:"styles-module__dragSelection___kZLq2",dragCount:"styles-module__dragCount___KM90j",highlightsContainer:"styles-module__highlightsContainer___-0xzG",selectedElementHighlight:"styles-module__selectedElementHighlight___fyVlI",scaleOut:"styles-module__scaleOut___Wctwz",slideUp:"styles-module__slideUp___kgD36",slideDown:"styles-module__slideDown___zcdje"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-page-toolbar-css-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-page-toolbar-css-styles",document.head.appendChild(J);J.textContent=uR}var K4=dR,MB=[{value:"compact",label:"Compact"},{value:"standard",label:"Standard"},{value:"detailed",label:"Detailed"},{value:"forensic",label:"Forensic"}];function n_(J,H,Y="standard"){if(J.length===0)return"";let K=typeof window<"u"?`${window.innerWidth}×${window.innerHeight}`:"unknown",W=`## Page Feedback: ${H}
`;if(Y==="forensic"){if(W+=`
**Environment:**
`,W+=`- Viewport: ${K}
`,typeof window<"u")W+=`- URL: ${window.location.href}
`,W+=`- User Agent: ${navigator.userAgent}
`,W+=`- Timestamp: ${new Date().toISOString()}
`,W+=`- Device Pixel Ratio: ${window.devicePixelRatio}
`;W+=`
---
`}else if(Y!=="compact")W+=`**Viewport:** ${K}
`;return W+=`
`,J.forEach((O,A)=>{if(Y==="compact"){if(W+=`${A+1}. **${O.element}**${O.sourceFile?` (${O.sourceFile})`:""}: ${O.comment}`,O.selectedText)W+=` (re: "${O.selectedText.slice(0,30)}${O.selectedText.length>30?"...":""}")`;W+=`
`}else if(Y==="forensic"){if(W+=`### ${A+1}. ${O.element}
`,O.isMultiSelect&&O.fullPath)W+=`*Forensic data shown for first element of selection*
`;if(O.fullPath)W+=`**Full DOM Path:** ${O.fullPath}
`;if(O.cssClasses)W+=`**CSS Classes:** ${O.cssClasses}
`;if(O.boundingBox)W+=`**Position:** x:${Math.round(O.boundingBox.x)}, y:${Math.round(O.boundingBox.y)} (${Math.round(O.boundingBox.width)}×${Math.round(O.boundingBox.height)}px)
`;if(W+=`**Annotation at:** ${O.x.toFixed(1)}% from left, ${Math.round(O.y)}px from top
`,O.selectedText)W+=`**Selected text:** "${O.selectedText}"
`;if(O.nearbyText&&!O.selectedText)W+=`**Context:** ${O.nearbyText.slice(0,100)}
`;if(O.computedStyles)W+=`**Computed Styles:** ${O.computedStyles}
`;if(O.accessibility)W+=`**Accessibility:** ${O.accessibility}
`;if(O.nearbyElements)W+=`**Nearby Elements:** ${O.nearbyElements}
`;if(O.sourceFile)W+=`**Source:** ${O.sourceFile}
`;if(O.reactComponents)W+=`**React:** ${O.reactComponents}
`;W+=`**Feedback:** ${O.comment}

`}else{if(W+=`### ${A+1}. ${O.element}
`,W+=`**Location:** ${O.elementPath}
`,O.sourceFile)W+=`**Source:** ${O.sourceFile}
`;if(O.reactComponents)W+=`**React:** ${O.reactComponents}
`;if(Y==="detailed"){if(O.cssClasses)W+=`**Classes:** ${O.cssClasses}
`;if(O.boundingBox)W+=`**Position:** ${Math.round(O.boundingBox.x)}px, ${Math.round(O.boundingBox.y)}px (${Math.round(O.boundingBox.width)}×${Math.round(O.boundingBox.height)}px)
`}if(O.selectedText)W+=`**Selected text:** "${O.selectedText}"
`;if(Y==="detailed"&&O.nearbyText&&!O.selectedText)W+=`**Context:** ${O.nearbyText.slice(0,100)}
`;W+=`**Feedback:** ${O.comment}

`}}),W.trim()}var pR=`@keyframes styles-module__markerIn___x4G8D {
  0% {
    opacity: 0;
    transform: translate(-50%, -50%) scale(0.3);
  }
  100% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1);
  }
}
@keyframes styles-module__markerOut___6VhQN {
  0% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1);
  }
  100% {
    opacity: 0;
    transform: translate(-50%, -50%) scale(0.3);
  }
}
@keyframes styles-module__tooltipIn___aJslQ {
  from {
    opacity: 0;
    transform: translateX(-50%) translateY(2px) scale(0.891);
  }
  to {
    opacity: 1;
    transform: translateX(-50%) translateY(0) scale(0.909);
  }
}
@keyframes styles-module__renumberRoll___akV9B {
  0% {
    transform: translateX(-40%);
    opacity: 0;
  }
  100% {
    transform: translateX(0);
    opacity: 1;
  }
}
.styles-module__marker___9CKF7 {
  position: absolute;
  width: 22px;
  height: 22px;
  background: var(--agentation-color-blue);
  color: white;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.6875rem;
  font-weight: 600;
  transform: translate(-50%, -50%) scale(1);
  opacity: 1;
  cursor: pointer;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2), inset 0 0 0 1px rgba(0, 0, 0, 0.04);
  user-select: none;
  will-change: transform, opacity;
  contain: layout style;
  z-index: 1;
}
.styles-module__marker___9CKF7:hover {
  z-index: 2;
}
.styles-module__marker___9CKF7:not(.styles-module__enter___8kI3q):not(.styles-module__exit___KBdR3):not(.styles-module__clearing___8rM7K) {
  transition: background-color 0.15s ease, transform 0.1s ease;
}
.styles-module__marker___9CKF7.styles-module__enter___8kI3q {
  animation: styles-module__markerIn___x4G8D 0.25s cubic-bezier(0.22, 1, 0.36, 1) both;
}
.styles-module__marker___9CKF7.styles-module__exit___KBdR3 {
  animation: styles-module__markerOut___6VhQN 0.2s ease-out both;
  pointer-events: none;
}
.styles-module__marker___9CKF7.styles-module__clearing___8rM7K {
  animation: styles-module__markerOut___6VhQN 0.15s ease-out both;
  pointer-events: none;
}
.styles-module__marker___9CKF7:not(.styles-module__enter___8kI3q):not(.styles-module__exit___KBdR3):not(.styles-module__clearing___8rM7K):hover {
  transform: translate(-50%, -50%) scale(1.1);
}
.styles-module__marker___9CKF7.styles-module__pending___BiY-U {
  position: fixed;
  background-color: var(--agentation-color-blue);
  cursor: default;
}
.styles-module__marker___9CKF7.styles-module__fixed___aKrQO {
  position: fixed;
}
.styles-module__marker___9CKF7.styles-module__multiSelect___CPfTC {
  background-color: var(--agentation-color-green);
  width: 26px;
  height: 26px;
  border-radius: 6px;
  font-size: 0.75rem;
}
.styles-module__marker___9CKF7.styles-module__multiSelect___CPfTC.styles-module__pending___BiY-U {
  background-color: var(--agentation-color-green);
}
.styles-module__marker___9CKF7.styles-module__hovered___-mg2N {
  background-color: var(--agentation-color-red);
}

.styles-module__renumber___16lvD {
  display: block;
  animation: styles-module__renumberRoll___akV9B 0.2s ease-out;
}

.styles-module__markerTooltip___-VUm- {
  position: absolute;
  top: calc(100% + 10px);
  left: 50%;
  transform: translateX(-50%) scale(0.909);
  z-index: 100002;
  background: #1a1a1a;
  padding: 8px 0.75rem;
  border-radius: 0.75rem;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-weight: 400;
  color: #fff;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.08);
  min-width: 120px;
  max-width: 200px;
  pointer-events: none;
  cursor: default;
}
.styles-module__markerTooltip___-VUm-.styles-module__enter___8kI3q {
  animation: styles-module__tooltipIn___aJslQ 0.1s ease-out forwards;
}

.styles-module__markerQuote___tQake {
  display: block;
  font-size: 12px;
  font-style: italic;
  color: rgba(255, 255, 255, 0.6);
  margin-bottom: 0.3125rem;
  line-height: 1.4;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.styles-module__markerNote___Rh4eI {
  display: block;
  font-size: 13px;
  font-weight: 400;
  line-height: 1.4;
  color: #fff;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  padding-bottom: 2px;
}

[data-agentation-theme=light] .styles-module__markerTooltip___-VUm- {
  background: #fff;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.12), 0 0 0 1px rgba(0, 0, 0, 0.06);
}
[data-agentation-theme=light] .styles-module__markerTooltip___-VUm- .styles-module__markerQuote___tQake {
  color: rgba(0, 0, 0, 0.5);
}
[data-agentation-theme=light] .styles-module__markerTooltip___-VUm- .styles-module__markerNote___Rh4eI {
  color: rgba(0, 0, 0, 0.85);
}`,cR={marker:"styles-module__marker___9CKF7",enter:"styles-module__enter___8kI3q",exit:"styles-module__exit___KBdR3",clearing:"styles-module__clearing___8rM7K",markerIn:"styles-module__markerIn___x4G8D",markerOut:"styles-module__markerOut___6VhQN",pending:"styles-module__pending___BiY-U",fixed:"styles-module__fixed___aKrQO",multiSelect:"styles-module__multiSelect___CPfTC",hovered:"styles-module__hovered___-mg2N",renumber:"styles-module__renumber___16lvD",renumberRoll:"styles-module__renumberRoll___akV9B",markerTooltip:"styles-module__markerTooltip___-VUm-",tooltipIn:"styles-module__tooltipIn___aJslQ",markerQuote:"styles-module__markerQuote___tQake",markerNote:"styles-module__markerNote___Rh4eI"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-annotation-marker-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-annotation-marker-styles",document.head.appendChild(J);J.textContent=pR}var tZ=cR;function t_({annotation:J,globalIndex:H,layerIndex:Y,layerSize:K,isExiting:W,isClearing:O,isAnimated:A,isHovered:C,isDeleting:x,isEditingAny:J4,renumberFrom:b,markerClickBehavior:g,tooltipStyle:R,onHoverEnter:o,onHoverLeave:p,onClick:q4,onContextMenu:h}){let t=(C||x)&&!J4,I4=t&&g==="delete",u4=J.isMultiSelect,i4=u4?"var(--agentation-color-green)":"var(--agentation-color-accent)",g7=W?tZ.exit:O?tZ.clearing:!A?tZ.enter:"",h7=W?`${(K-1-Y)*20}ms`:`${Y*20}ms`;return w5.jsxs("div",{className:`${tZ.marker} ${u4?tZ.multiSelect:""} ${g7} ${I4?tZ.hovered:""}`,"data-annotation-marker":!0,style:{left:`${J.x}%`,top:J.y,backgroundColor:I4?void 0:i4,animationDelay:h7},onMouseEnter:()=>o(J),onMouseLeave:p,onClick:(T4)=>{if(T4.stopPropagation(),!W)q4(J)},onContextMenu:h?(T4)=>{if(g==="delete"){if(T4.preventDefault(),T4.stopPropagation(),!W)h(J)}}:void 0,children:[t?I4?w5.jsx(z3,{size:u4?18:16}):w5.jsx($O,{size:16}):w5.jsx("span",{className:b!==null&&H>=b?tZ.renumber:void 0,children:H+1}),C&&!J4&&w5.jsxs("div",{className:`${tZ.markerTooltip} ${tZ.enter}`,style:R,children:[w5.jsxs("span",{className:tZ.markerQuote,children:[J.element,J.selectedText&&` "${J.selectedText.slice(0,30)}${J.selectedText.length>30?"...":""}"`]}),w5.jsx("span",{className:tZ.markerNote,children:J.comment})]})]})}function lR({x:J,y:H,isMultiSelect:Y,isExiting:K}){return w5.jsx("div",{className:`${tZ.marker} ${tZ.pending} ${Y?tZ.multiSelect:""} ${K?tZ.exit:tZ.enter}`,style:{left:`${J}%`,top:H,backgroundColor:Y?"var(--agentation-color-green)":"var(--agentation-color-accent)"},children:w5.jsx(lV,{size:12})})}function e_({annotation:J,fixed:H}){let Y=J.isMultiSelect;return w5.jsx("div",{className:`${tZ.marker} ${H?tZ.fixed:""} ${tZ.hovered} ${Y?tZ.multiSelect:""} ${tZ.exit}`,"data-annotation-marker":!0,style:{left:`${J.x}%`,top:J.y},children:w5.jsx(z3,{size:Y?12:10})})}var sR=`.styles-module__switchContainer___Ka-AB {
  display: flex;
  align-items: center;
  position: relative;
  padding: 2px;
  width: 24px;
  height: 16px;
  border-radius: 8px;
  background-color: #cdcdcd;
  transition: background-color 0.15s, opacity 0.15s;
}
[data-agentation-theme=dark] .styles-module__switchContainer___Ka-AB {
  background-color: #484848;
}
.styles-module__switchContainer___Ka-AB:has(.styles-module__switchInput___kYDSD:checked) {
  background-color: var(--agentation-color-blue);
}
.styles-module__switchContainer___Ka-AB:has(.styles-module__switchInput___kYDSD:disabled) {
  opacity: 0.3;
}

.styles-module__switchInput___kYDSD {
  position: absolute;
  z-index: 1;
  inset: 0;
  border-radius: inherit;
  opacity: 0;
  cursor: pointer;
}
.styles-module__switchInput___kYDSD:disabled {
  cursor: not-allowed;
}

.styles-module__switchThumb___4sCPH {
  border-radius: 50%;
  width: 12px;
  height: 12px;
  background-color: #fff;
  transition: transform 0.15s;
}
.styles-module__switchContainer___Ka-AB:has(.styles-module__switchInput___kYDSD:checked) .styles-module__switchThumb___4sCPH {
  transform: translateX(8px);
}`,aR={switchContainer:"styles-module__switchContainer___Ka-AB",switchInput:"styles-module__switchInput___kYDSD",switchThumb:"styles-module__switchThumb___4sCPH"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-switch-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-switch-styles",document.head.appendChild(J);J.textContent=sR}var UH=aR,VH=({className:J="",...H})=>{return PB.jsxs("div",{className:`${UH.switchContainer} ${J}`,children:[PB.jsx("input",{className:UH.switchInput,type:"checkbox",...H}),PB.jsx("div",{className:UH.switchThumb})]})},iR=`.styles-module__checkboxContainer___joqZk {
  display: flex;
  justify-content: center;
  align-items: center;
  position: relative;
  border: 1px solid rgba(26, 26, 26, 0.2);
  border-radius: 4px;
  width: 14px;
  height: 14px;
  background-color: #fff;
  transition: background-color 0.2s ease;
}
[data-agentation-theme=dark] .styles-module__checkboxContainer___joqZk {
  border-color: rgba(255, 255, 255, 0.2);
  background-color: #252525;
}
.styles-module__checkboxContainer___joqZk:has(.styles-module__checkboxInput___ECzzO:checked) {
  background-color: #1a1a1a;
}
[data-agentation-theme=dark] .styles-module__checkboxContainer___joqZk:has(.styles-module__checkboxInput___ECzzO:checked) {
  background-color: #fff;
}

.styles-module__checkboxInput___ECzzO {
  position: absolute;
  z-index: 1;
  inset: -1px;
  border-radius: inherit;
  opacity: 0;
  cursor: pointer;
}

.styles-module__checkboxCheck___fUXpr {
  color: #fafafa;
}
[data-agentation-theme=dark] .styles-module__checkboxCheck___fUXpr {
  color: #1a1a1a;
}

.styles-module__checkboxCheckPath___cDyh8 {
  stroke-dasharray: 9.29px;
  stroke-dashoffset: 9.29px;
  color: #fafafa;
  transition: stroke-dashoffset 0.1s ease;
}
[data-agentation-theme=dark] .styles-module__checkboxCheckPath___cDyh8 {
  color: #1a1a1a;
}
.styles-module__checkboxContainer___joqZk:has(.styles-module__checkboxInput___ECzzO:checked) .styles-module__checkboxCheckPath___cDyh8 {
  transition-duration: 0.2s;
  stroke-dashoffset: 0;
}`,oR={checkboxContainer:"styles-module__checkboxContainer___joqZk",checkboxInput:"styles-module__checkboxInput___ECzzO",checkboxCheck:"styles-module__checkboxCheck___fUXpr",checkboxCheckPath:"styles-module__checkboxCheckPath___cDyh8"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-checkbox-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-checkbox-styles",document.head.appendChild(J);J.textContent=iR}var sz=oR,rR=({className:J="",...H})=>{return E0.jsxs("div",{className:`${sz.checkboxContainer} ${J}`,children:[E0.jsx("input",{className:sz.checkboxInput,type:"checkbox",...H}),E0.jsx("svg",{className:sz.checkboxCheck,width:"14",height:"14",viewBox:"0 0 14 14",fill:"none",children:E0.jsx("path",{className:sz.checkboxCheckPath,d:"M3.94 7L6.13 9.19L10.5 4.81",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})})]})},nR=`.styles-module__container___w8eAF {
  display: flex;
  align-items: center;
  height: 24px;
}

.styles-module__label___J5mxE {
  padding-inline: 8px 2px;
  line-height: 20px;
  font-size: 13px;
  letter-spacing: -0.15px;
  color: rgba(26, 26, 26, 0.5);
  cursor: pointer;
}
[data-agentation-theme=dark] .styles-module__label___J5mxE {
  color: rgba(255, 255, 255, 0.5);
}`,tR={container:"styles-module__container___w8eAF",label:"styles-module__label___J5mxE"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-checkbox-field-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-checkbox-field-styles",document.head.appendChild(J);J.textContent=nR}var Z3=tR,G3=({className:J="",label:H,tooltip:Y,checked:K,onChange:W,...O})=>{let A=M3.useId();return w0.jsxs("div",{className:`${Z3.container} ${J}`,...O,children:[w0.jsx(rR,{id:A,onChange:W,checked:K}),w0.jsx("label",{className:Z3.label,htmlFor:A,children:H}),Y&&w0.jsx(JG,{content:Y})]})},eR=`@keyframes styles-module__cycleTextIn___VBNTi {
  0% {
    opacity: 0;
    transform: translateY(-6px);
  }
  100% {
    opacity: 1;
    transform: translateY(0);
  }
}
@keyframes styles-module__scaleIn___QpQ8E {
  from {
    opacity: 0;
    transform: scale(0.85);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}
@keyframes styles-module__mcpPulse___5Q3Jj {
  0% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-green) 50%, transparent);
  }
  70% {
    box-shadow: 0 0 0 6px color-mix(in srgb, var(--agentation-color-green) 0%, transparent);
  }
  100% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-green) 0%, transparent);
  }
}
@keyframes styles-module__mcpPulseError___VHxhx {
  0% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-red) 50%, transparent);
  }
  70% {
    box-shadow: 0 0 0 6px color-mix(in srgb, var(--agentation-color-red) 0%, transparent);
  }
  100% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--agentation-color-red) 0%, transparent);
  }
}
@keyframes styles-module__themeIconIn___qUWMV {
  0% {
    opacity: 0;
    transform: scale(0.8) rotate(-30deg);
  }
  100% {
    opacity: 1;
    transform: scale(1) rotate(0deg);
  }
}
.styles-module__settingsPanel___qNkn- {
  position: absolute;
  right: 5px;
  bottom: calc(100% + 0.5rem);
  z-index: 1;
  overflow: hidden;
  background: #1c1c1c;
  border-radius: 16px;
  padding: 12px 0;
  width: 100%;
  max-width: 253px;
  min-width: 205px;
  cursor: default;
  opacity: 1;
  box-shadow: 0 1px 8px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.04);
  transition: background-color 0.25s ease, box-shadow 0.25s ease;
}
.styles-module__settingsPanel___qNkn-::before, .styles-module__settingsPanel___qNkn-::after {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  width: 16px;
  z-index: 2;
  pointer-events: none;
}
.styles-module__settingsPanel___qNkn-::before {
  left: 0;
  background: linear-gradient(to right, #1c1c1c 0%, transparent 100%);
}
.styles-module__settingsPanel___qNkn-::after {
  right: 0;
  background: linear-gradient(to left, #1c1c1c 0%, transparent 100%);
}
.styles-module__settingsPanel___qNkn- .styles-module__settingsHeader___Fn1DP,
.styles-module__settingsPanel___qNkn- .styles-module__settingsBrand___OoKlM,
.styles-module__settingsPanel___qNkn- .styles-module__settingsBrandSlash___Q-AU9,
.styles-module__settingsPanel___qNkn- .styles-module__settingsVersion___rXmL9,
.styles-module__settingsPanel___qNkn- .styles-module__settingsSection___n5V-4,
.styles-module__settingsPanel___qNkn- .styles-module__settingsLabel___VCVOQ,
.styles-module__settingsPanel___qNkn- .styles-module__cycleButton___XMBx3,
.styles-module__settingsPanel___qNkn- .styles-module__cycleDot___zgSXY,
.styles-module__settingsPanel___qNkn- .styles-module__dropdownButton___mKHe8,
.styles-module__settingsPanel___qNkn- .styles-module__sliderLabel___6K5v1,
.styles-module__settingsPanel___qNkn- .styles-module__slider___v5z-c,
.styles-module__settingsPanel___qNkn- .styles-module__themeToggle___3imlT {
  transition: background-color 0.25s ease, color 0.25s ease, border-color 0.25s ease;
}
.styles-module__settingsPanel___qNkn-.styles-module__enter___wginS {
  opacity: 1;
  transform: translateY(0) scale(1);
  filter: blur(0px);
  transition: opacity 0.2s ease, transform 0.2s ease, filter 0.2s ease;
}
.styles-module__settingsPanel___qNkn-.styles-module__exit___A4iJc {
  opacity: 0;
  transform: translateY(8px) scale(0.95);
  filter: blur(5px);
  pointer-events: none;
  transition: opacity 0.1s ease, transform 0.1s ease, filter 0.1s ease;
}
[data-agentation-theme=dark] .styles-module__settingsPanel___qNkn- {
  background: #1a1a1a;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.08);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___qNkn- .styles-module__settingsLabel___VCVOQ {
  color: rgba(255, 255, 255, 0.6);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___qNkn- .styles-module__settingsOption___JoyH- {
  color: rgba(255, 255, 255, 0.85);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___qNkn- .styles-module__settingsOption___JoyH-:hover {
  background: rgba(255, 255, 255, 0.1);
}
[data-agentation-theme=dark] .styles-module__settingsPanel___qNkn- .styles-module__settingsOption___JoyH-.styles-module__selected___k1-Vq {
  background: rgba(255, 255, 255, 0.15);
  color: #fff;
}

.styles-module__settingsPanelContainer___5it-H {
  overflow: visible;
  position: relative;
  display: flex;
  padding: 0 16px;
}

.styles-module__settingsPage___BMn-3 {
  min-width: 100%;
  flex-basis: 0;
  flex-shrink: 0;
  transition: transform 0.2s ease, opacity 0.2s ease;
  transition-delay: 0s;
  opacity: 1;
}

.styles-module__settingsPage___BMn-3.styles-module__slideLeft___qUvW4 {
  transform: translateX(-24px);
  opacity: 0;
  pointer-events: none;
}

.styles-module__automationsPage___N7By0 {
  position: absolute;
  top: 0;
  left: 24px;
  width: 100%;
  height: 100%;
  padding: 0 16px 4px;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  transition: transform 0.2s ease, opacity 0.2s ease;
  opacity: 0;
  pointer-events: none;
}

.styles-module__automationsPage___N7By0.styles-module__slideIn___uXDSu {
  transform: translateX(-24px);
  opacity: 1;
  pointer-events: auto;
}

.styles-module__settingsHeader___Fn1DP {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 24px;
}

.styles-module__settingsBrand___OoKlM {
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: -0.0094em;
  color: #fff;
  text-decoration: none;
}

.styles-module__settingsBrandSlash___Q-AU9 {
  color: var(--agentation-color-accent);
  transition: color 0.2s ease;
}

.styles-module__settingsVersion___rXmL9 {
  font-size: 11px;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.4);
  margin-left: auto;
  letter-spacing: -0.0094em;
}

.styles-module__themeToggle___3imlT {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  margin-left: 8px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: rgba(255, 255, 255, 0.4);
  transition: background-color 0.15s ease, color 0.15s ease;
  cursor: pointer;
}
.styles-module__themeToggle___3imlT:hover {
  background: rgba(255, 255, 255, 0.1);
  color: rgba(255, 255, 255, 0.8);
}
[data-agentation-theme=light] .styles-module__themeToggle___3imlT {
  color: rgba(0, 0, 0, 0.4);
}
[data-agentation-theme=light] .styles-module__themeToggle___3imlT:hover {
  background: rgba(0, 0, 0, 0.06);
  color: rgba(0, 0, 0, 0.7);
}

.styles-module__themeIconWrapper___pyaYa {
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  width: 20px;
  height: 20px;
}

.styles-module__themeIcon___w7lAm {
  display: flex;
  align-items: center;
  justify-content: center;
  animation: styles-module__themeIconIn___qUWMV 0.35s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
}

.styles-module__settingsSectionGrow___eZTRw {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.styles-module__settingsRow___y-tDE {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 24px;
}
.styles-module__settingsRow___y-tDE.styles-module__settingsRowMarginTop___uLpGb {
  margin-top: 8px;
}

.styles-module__settingsRowDisabled___ydl3Q .styles-module__settingsLabel___VCVOQ {
  color: rgba(255, 255, 255, 0.2);
}
[data-agentation-theme=light] .styles-module__settingsRowDisabled___ydl3Q .styles-module__settingsLabel___VCVOQ {
  color: rgba(0, 0, 0, 0.2);
}

.styles-module__settingsLabel___VCVOQ {
  display: flex;
  align-items: center;
  column-gap: 2px;
  line-height: 20px;
  font-size: 13px;
  font-weight: 400;
  letter-spacing: -0.15px;
  color: rgba(255, 255, 255, 0.5);
}
[data-agentation-theme=light] .styles-module__settingsLabel___VCVOQ {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__cycleButton___XMBx3 {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0;
  border: none;
  background: transparent;
  font-size: 0.8125rem;
  font-weight: 500;
  color: #fff;
  cursor: pointer;
  letter-spacing: -0.0094em;
}
[data-agentation-theme=light] .styles-module__cycleButton___XMBx3 {
  color: rgba(0, 0, 0, 0.85);
}
.styles-module__cycleButton___XMBx3:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.styles-module__cycleButtonText___mbbnD {
  display: inline-block;
  animation: styles-module__cycleTextIn___VBNTi 0.2s ease-out;
}

.styles-module__cycleDots___ehp6i {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.styles-module__cycleDot___zgSXY {
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.3);
  transform: scale(0.667);
  transition: background-color 0.25s ease-out, transform 0.25s ease-out;
}
.styles-module__cycleDot___zgSXY.styles-module__active___dpAhM {
  background: #fff;
  transform: scale(1);
}
[data-agentation-theme=light] .styles-module__cycleDot___zgSXY {
  background: rgba(0, 0, 0, 0.2);
}
[data-agentation-theme=light] .styles-module__cycleDot___zgSXY.styles-module__active___dpAhM {
  background: rgba(0, 0, 0, 0.7);
}

.styles-module__colorOptions___pbxZx {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 6px;
  height: 26px;
}

.styles-module__colorOption___Co955 {
  padding: 0;
  position: relative;
  border-radius: 50%;
  width: 20px;
  height: 20px;
  background-color: #fff;
  cursor: pointer;
}
[data-agentation-theme=dark] .styles-module__colorOption___Co955 {
  background-color: #1a1a1a;
}
.styles-module__colorOption___Co955::before, .styles-module__colorOption___Co955::after {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: 50%;
  background-color: var(--swatch);
  transition: opacity 0.2s, transform 0.2s;
}
@supports (color: color(display-p3 0 0 0)) {
  .styles-module__colorOption___Co955::before, .styles-module__colorOption___Co955::after {
    --color: var(--swatch-p3);
  }
}
.styles-module__colorOption___Co955::after {
  z-index: -1;
  transform: scale(1.2);
  opacity: 0;
}
.styles-module__colorOption___Co955.styles-module__selected___k1-Vq::before {
  transform: scale(0.8);
}
.styles-module__colorOption___Co955.styles-module__selected___k1-Vq::after {
  opacity: 1;
}

.styles-module__settingsNavLink___uYIwM {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  height: 24px;
  padding: 0;
  border: none;
  background: transparent;
  font-family: inherit;
  line-height: 20px;
  font-size: 13px;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.5);
  transition: color 0.15s ease;
  cursor: pointer;
}
.styles-module__settingsNavLink___uYIwM:hover {
  color: rgba(255, 255, 255, 0.9);
}
.styles-module__settingsNavLink___uYIwM svg {
  color: rgba(255, 255, 255, 0.4);
  transition: color 0.15s ease;
}
.styles-module__settingsNavLink___uYIwM:hover svg {
  color: #fff;
}
[data-agentation-theme=light] .styles-module__settingsNavLink___uYIwM {
  color: rgba(0, 0, 0, 0.5);
}
[data-agentation-theme=light] .styles-module__settingsNavLink___uYIwM:hover {
  color: rgba(0, 0, 0, 0.8);
}
[data-agentation-theme=light] .styles-module__settingsNavLink___uYIwM svg {
  color: rgba(0, 0, 0, 0.25);
}
[data-agentation-theme=light] .styles-module__settingsNavLink___uYIwM:hover svg {
  color: rgba(0, 0, 0, 0.8);
}

.styles-module__settingsNavLinkRight___XBUzC {
  display: flex;
  align-items: center;
  gap: 6px;
}

.styles-module__settingsBackButton___fflll {
  display: flex;
  align-items: center;
  gap: 4px;
  height: 24px;
  background: transparent;
  font-family: inherit;
  line-height: 20px;
  font-size: 13px;
  font-weight: 500;
  letter-spacing: -0.15px;
  color: #fff;
  cursor: pointer;
  transition: transform 0.12s cubic-bezier(0.32, 0.72, 0, 1);
}
.styles-module__settingsBackButton___fflll svg {
  opacity: 0.4;
  flex-shrink: 0;
  transition: opacity 0.15s ease, transform 0.18s cubic-bezier(0.32, 0.72, 0, 1);
}
.styles-module__settingsBackButton___fflll:hover svg {
  opacity: 1;
}
[data-agentation-theme=light] .styles-module__settingsBackButton___fflll {
  color: rgba(0, 0, 0, 0.85);
  border-bottom-color: rgba(0, 0, 0, 0.08);
}

.styles-module__automationHeader___Avra9 {
  display: flex;
  align-items: center;
  gap: 0.125rem;
  font-size: 0.8125rem;
  font-weight: 400;
  color: #fff;
}
[data-agentation-theme=light] .styles-module__automationHeader___Avra9 {
  color: rgba(0, 0, 0, 0.85);
}

.styles-module__automationDescription___vFTmJ {
  font-size: 0.6875rem;
  font-weight: 300;
  color: rgba(255, 255, 255, 0.5);
  margin-top: 2px;
  line-height: 14px;
}
[data-agentation-theme=light] .styles-module__automationDescription___vFTmJ {
  color: rgba(0, 0, 0, 0.5);
}

.styles-module__learnMoreLink___cG7OI {
  color: rgba(255, 255, 255, 0.8);
  text-decoration-line: underline;
  text-decoration-style: dotted;
  text-decoration-color: rgba(255, 255, 255, 0.2);
  text-underline-offset: 2px;
  transition: color 0.15s ease;
}
.styles-module__learnMoreLink___cG7OI:hover {
  color: #fff;
}
[data-agentation-theme=light] .styles-module__learnMoreLink___cG7OI {
  color: rgba(0, 0, 0, 0.6);
  text-decoration-color: rgba(0, 0, 0, 0.2);
}
[data-agentation-theme=light] .styles-module__learnMoreLink___cG7OI:hover {
  color: rgba(0, 0, 0, 0.85);
}

.styles-module__autoSendContainer___VpkXk {
  display: flex;
  align-items: center;
}

.styles-module__autoSendLabel___ngNdC {
  padding-inline-end: 8px;
  font-size: 11px;
  font-weight: 400;
  color: rgba(255, 255, 255, 0.4);
  transition: color 0.15s, opacity 0.15s;
  cursor: pointer;
}
.styles-module__autoSendLabel___ngNdC.styles-module__active___dpAhM {
  color: #66b8ff;
  color: color(display-p3 0.4 0.72 1);
}
[data-agentation-theme=light] .styles-module__autoSendLabel___ngNdC {
  color: rgba(0, 0, 0, 0.4);
}
[data-agentation-theme=light] .styles-module__autoSendLabel___ngNdC.styles-module__active___dpAhM {
  color: var(--agentation-color-blue);
}
.styles-module__autoSendLabel___ngNdC.styles-module__disabled___9AZYS {
  opacity: 0.3;
  cursor: not-allowed;
}

.styles-module__mcpStatusDot___8AMxP {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.styles-module__mcpStatusDot___8AMxP.styles-module__connecting___QEO1r {
  background-color: var(--agentation-color-yellow);
  animation: styles-module__mcpPulse___5Q3Jj 1.5s infinite;
}
.styles-module__mcpStatusDot___8AMxP.styles-module__connected___WyFkx {
  background-color: var(--agentation-color-green);
  animation: styles-module__mcpPulse___5Q3Jj 2.5s ease-in-out infinite;
}
.styles-module__mcpStatusDot___8AMxP.styles-module__disconnected___mvmvQ {
  background-color: var(--agentation-color-red);
  animation: styles-module__mcpPulseError___VHxhx 2s infinite;
}

.styles-module__mcpNavIndicator___auBHI {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.styles-module__mcpNavIndicator___auBHI.styles-module__connected___WyFkx {
  background-color: var(--agentation-color-green);
  animation: styles-module__mcpPulse___5Q3Jj 2.5s ease-in-out infinite;
}
.styles-module__mcpNavIndicator___auBHI.styles-module__connecting___QEO1r {
  background-color: var(--agentation-color-yellow);
  animation: styles-module__mcpPulse___5Q3Jj 1.5s ease-in-out infinite;
}

.styles-module__webhookUrlInput___WDDDC {
  display: block;
  width: 100%;
  flex: 1;
  min-height: 60px;
  box-sizing: border-box;
  margin-top: 11px;
  padding: 8px 10px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.03);
  font-family: inherit;
  font-size: 0.75rem;
  font-weight: 400;
  color: #fff;
  outline: none;
  resize: none;
  user-select: text;
  transition: border-color 0.15s ease, background-color 0.15s ease, box-shadow 0.15s ease;
}
.styles-module__webhookUrlInput___WDDDC::placeholder {
  color: rgba(255, 255, 255, 0.3);
}
.styles-module__webhookUrlInput___WDDDC:focus {
  border-color: rgba(255, 255, 255, 0.3);
  background: rgba(255, 255, 255, 0.08);
}
[data-agentation-theme=light] .styles-module__webhookUrlInput___WDDDC {
  border-color: rgba(0, 0, 0, 0.1);
  background: rgba(0, 0, 0, 0.03);
  color: rgba(0, 0, 0, 0.85);
}
[data-agentation-theme=light] .styles-module__webhookUrlInput___WDDDC::placeholder {
  color: rgba(0, 0, 0, 0.3);
}
[data-agentation-theme=light] .styles-module__webhookUrlInput___WDDDC:focus {
  border-color: rgba(0, 0, 0, 0.25);
  background: rgba(0, 0, 0, 0.05);
}

[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- {
  background: #fff;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08), 0 4px 16px rgba(0, 0, 0, 0.06), 0 0 0 1px rgba(0, 0, 0, 0.04);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn-::before {
  background: linear-gradient(to right, #fff 0%, transparent 100%);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn-::after {
  background: linear-gradient(to left, #fff 0%, transparent 100%);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__settingsHeader___Fn1DP {
  border-bottom-color: rgba(0, 0, 0, 0.08);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__settingsBrand___OoKlM {
  color: #E5484D;
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__settingsVersion___rXmL9 {
  color: rgba(0, 0, 0, 0.4);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__settingsSection___n5V-4 {
  border-top-color: rgba(0, 0, 0, 0.08);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__settingsLabel___VCVOQ {
  color: rgba(0, 0, 0, 0.5);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__cycleButton___XMBx3 {
  color: rgba(0, 0, 0, 0.85);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__cycleDot___zgSXY {
  background: rgba(0, 0, 0, 0.2);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__cycleDot___zgSXY.styles-module__active___dpAhM {
  background: rgba(0, 0, 0, 0.7);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__dropdownButton___mKHe8 {
  color: rgba(0, 0, 0, 0.85);
}
[data-agentation-theme=light] .styles-module__settingsPanel___qNkn- .styles-module__dropdownButton___mKHe8:hover {
  background: rgba(0, 0, 0, 0.05);
}

.styles-module__checkboxField___ZrSqv:not(:first-child) {
  margin-top: 8px;
}

.styles-module__divider___h6Yux {
  margin-block: 8px;
  width: 100%;
  height: 1px;
  background-color: rgba(26, 26, 26, 0.07);
}
[data-agentation-theme=dark] .styles-module__divider___h6Yux {
  background-color: rgba(255, 255, 255, 0.07);
}`,ZM={settingsPanel:"styles-module__settingsPanel___qNkn-",settingsHeader:"styles-module__settingsHeader___Fn1DP",settingsBrand:"styles-module__settingsBrand___OoKlM",settingsBrandSlash:"styles-module__settingsBrandSlash___Q-AU9",settingsVersion:"styles-module__settingsVersion___rXmL9",settingsSection:"styles-module__settingsSection___n5V-4",settingsLabel:"styles-module__settingsLabel___VCVOQ",cycleButton:"styles-module__cycleButton___XMBx3",cycleDot:"styles-module__cycleDot___zgSXY",dropdownButton:"styles-module__dropdownButton___mKHe8",sliderLabel:"styles-module__sliderLabel___6K5v1",slider:"styles-module__slider___v5z-c",themeToggle:"styles-module__themeToggle___3imlT",enter:"styles-module__enter___wginS",exit:"styles-module__exit___A4iJc",settingsOption:"styles-module__settingsOption___JoyH-",selected:"styles-module__selected___k1-Vq",settingsPanelContainer:"styles-module__settingsPanelContainer___5it-H",settingsPage:"styles-module__settingsPage___BMn-3",slideLeft:"styles-module__slideLeft___qUvW4",automationsPage:"styles-module__automationsPage___N7By0",slideIn:"styles-module__slideIn___uXDSu",themeIconWrapper:"styles-module__themeIconWrapper___pyaYa",themeIcon:"styles-module__themeIcon___w7lAm",themeIconIn:"styles-module__themeIconIn___qUWMV",settingsSectionGrow:"styles-module__settingsSectionGrow___eZTRw",settingsRow:"styles-module__settingsRow___y-tDE",settingsRowMarginTop:"styles-module__settingsRowMarginTop___uLpGb",settingsRowDisabled:"styles-module__settingsRowDisabled___ydl3Q",cycleButtonText:"styles-module__cycleButtonText___mbbnD",cycleTextIn:"styles-module__cycleTextIn___VBNTi",cycleDots:"styles-module__cycleDots___ehp6i",active:"styles-module__active___dpAhM",colorOptions:"styles-module__colorOptions___pbxZx",colorOption:"styles-module__colorOption___Co955",settingsNavLink:"styles-module__settingsNavLink___uYIwM",settingsNavLinkRight:"styles-module__settingsNavLinkRight___XBUzC",settingsBackButton:"styles-module__settingsBackButton___fflll",automationHeader:"styles-module__automationHeader___Avra9",automationDescription:"styles-module__automationDescription___vFTmJ",learnMoreLink:"styles-module__learnMoreLink___cG7OI",autoSendContainer:"styles-module__autoSendContainer___VpkXk",autoSendLabel:"styles-module__autoSendLabel___ngNdC",disabled:"styles-module__disabled___9AZYS",mcpStatusDot:"styles-module__mcpStatusDot___8AMxP",connecting:"styles-module__connecting___QEO1r",mcpPulse:"styles-module__mcpPulse___5Q3Jj",connected:"styles-module__connected___WyFkx",disconnected:"styles-module__disconnected___mvmvQ",mcpPulseError:"styles-module__mcpPulseError___VHxhx",mcpNavIndicator:"styles-module__mcpNavIndicator___auBHI",webhookUrlInput:"styles-module__webhookUrlInput___WDDDC",checkboxField:"styles-module__checkboxField___ZrSqv",divider:"styles-module__divider___h6Yux",scaleIn:"styles-module__scaleIn___QpQ8E"};if(typeof document<"u"){let J=document.getElementById("feedback-tool-styles-settings-panel-styles");if(!J)J=document.createElement("style"),J.id="feedback-tool-styles-settings-panel-styles",document.head.appendChild(J);J.textContent=eR}var h4=ZM;function GM({settings:J,onSettingsChange:H,isDarkMode:Y,onToggleTheme:K,isDevMode:W,connectionStatus:O,endpoint:A,isVisible:C,toolbarNearBottom:x,settingsPage:J4,onSettingsPageChange:b,onHideToolbar:g}){return y4.jsx("div",{className:`${h4.settingsPanel} ${C?h4.enter:h4.exit}`,style:x?{bottom:"auto",top:"calc(100% + 0.5rem)"}:void 0,"data-agentation-settings-panel":!0,children:y4.jsxs("div",{className:h4.settingsPanelContainer,children:[y4.jsxs("div",{className:`${h4.settingsPage} ${J4==="automations"?h4.slideLeft:""}`,children:[y4.jsxs("div",{className:h4.settingsHeader,children:[y4.jsx("a",{className:h4.settingsBrand,href:"https://agentation.com",target:"_blank",rel:"noopener noreferrer",children:y4.jsx("svg",{width:"72",height:"16",viewBox:"0 0 676 151",fill:"none",xmlns:"http://www.w3.org/2000/svg",children:y4.jsx("path",{d:"M79.6666 100.561L104.863 15.5213C107.828 4.03448 99.1201 -3.00582 88.7449 1.25541L3.52015 39.6065C1.48217 40.5329 0 42.7562 0 45.1647C0 48.6848 2.77907 51.4639 6.29922 51.4639C7.22558 51.4639 8.15193 51.2786 9.07829 50.9081L93.7472 12.7422C97.2674 11.0748 93.7472 8.29572 92.6356 12.1864L67.624 97.2259C66.5123 100.931 69.4767 105.193 73.7379 105.193C76.517 105.193 79.1108 103.155 79.6666 100.561ZM663.641 100.005C665.679 107.231 677.537 104.081 675.499 96.8553L666.05 66.2856C663.456 57.7631 655.489 55.7251 648.82 61.098L618.991 86.6654C617.324 87.9623 621.029 89.815 621.214 88.1476L625.846 61.6538C626.958 55.3546 624.179 50.5375 615.841 50.5375L579.158 51.0934C576.008 51.0934 578.417 53.8724 578.417 57.022C578.417 60.1716 580.825 61.6538 583.975 61.6538L616.212 60.9127C616.397 60.9127 614.544 59.6158 614.544 59.8011L609.727 88.7034C607.875 99.6344 617.694 102.784 626.031 95.7437L655.86 70.1763L654.192 69.6205L663.641 100.005ZM571.191 89.0739C555.443 88.7034 562.298 61.4685 578.787 61.8391C594.72 62.0243 587.124 89.2592 571.191 89.0739ZM571.006 100.375C601.575 100.931 611.024 51.6492 579.158 51.0934C547.847 50.5375 540.065 99.8197 571.006 100.375ZM521.909 46.4616C525.985 46.4616 529.505 42.9414 529.505 38.6802C529.505 34.4189 525.985 31.0841 521.909 31.0841C517.833 31.0841 514.127 34.6042 514.127 38.6802C514.127 42.7562 517.648 46.4616 521.909 46.4616ZM472.256 103.525C493.192 103.71 515.98 73.3259 519.13 62.3949L509.866 60.9127C505.234 73.3259 497.638 101.672 519.871 102.043C536.545 102.228 552.479 85.3685 563.595 70.1763C564.151 69.2499 564.706 68.1383 564.706 66.8414C564.706 63.6918 563.965 61.098 560.816 61.098C558.963 61.098 557.296 62.0243 556.184 63.5065C546.365 77.0313 530.802 90.9266 522.094 90.7414C511.904 90.5561 517.462 71.4732 519.871 64.9887C523.391 55.7251 512.831 53.5019 509.681 60.9127C506.531 68.6941 488.19 92.4088 475.035 92.2235C467.439 92.0383 464.29 83.8863 472.441 59.9864L486.707 17.7445C487.634 14.4097 485.41 10.519 481.334 10.519C478.741 10.519 476.517 12.1864 475.962 14.4097L461.696 56.4662C451.506 86.4801 455.211 103.155 472.256 103.525ZM447.43 42.5709L496.527 41.4593C499.306 41.4593 501.529 39.0507 501.529 36.2717C501.529 33.3073 499.306 31.0841 496.341 31.0841L447.245 32.1957C444.466 32.1957 442.242 34.4189 442.242 37.3833C442.242 40.1624 444.466 42.5709 447.43 42.5709ZM422.974 106.304C435.387 106.489 457.249 94.8173 472.441 53.8724C473.553 50.7228 472.071 48.3143 468.365 48.3143C466.142 48.3143 464.29 49.6112 463.548 51.6492C450.394 87.2212 431.682 96.1142 424.456 95.929C419.454 95.929 417.972 93.3352 418.713 85.5538C419.454 78.1429 410.376 74.9933 406.114 81.1073C401.297 87.777 394.442 94.2615 385.549 94.0763C370.172 93.891 376.471 67.0267 399.815 67.3972C408.338 67.5825 414.452 71.4732 417.045 76.6608C417.786 78.3282 419.454 79.6251 421.492 79.6251C424.271 79.6251 426.679 77.2166 426.679 74.4375C426.679 73.6964 426.494 72.9553 426.124 72.2143C421.862 63.6918 412.414 57.3926 400 57.2073C363.502 56.6515 353.497 104.451 383.326 104.822C397.036 105.193 410.005 94.0763 413.34 85.9243C412.599 86.8507 408.338 86.6654 408.523 84.4422C407.411 97.4111 410.931 106.119 422.974 106.304ZM335.897 104.266C335.897 115.012 347.569 117.606 347.569 103.34C347.569 89.0739 358.5 54.4282 361.464 45.1647L396.666 43.6825C405.929 43.1267 404.262 33.1221 397.036 33.3073L364.984 34.4189L368.875 22.7469C369.801 20.1531 370.542 17.9298 370.542 16.2624C370.542 13.4833 368.504 11.8159 365.911 11.8159C362.946 11.8159 360.352 12.7422 357.573 21.0794L352.942 35.16L330.153 36.0864C326.263 36.4569 323.483 38.1244 323.483 41.6445C323.483 45.5352 326.448 47.0174 330.709 46.8321L349.421 45.9058C345.901 56.6515 335.897 90.7414 335.897 104.266ZM186.939 78.6988C193.979 56.4662 212.877 54.984 212.877 62.9507C212.877 68.3236 203.984 77.0313 186.939 78.6988ZM113.942 150.955C142.844 152.437 159.704 111.492 160.63 80.5515C161.556 73.3259 153.96 70.3616 148.773 75.7344C141.918 83.1453 129.505 93.1499 119.685 93.1499C103.011 93.1499 116.165 59.8011 143.956 59.8011C149.514 59.8011 153.59 61.6538 156.184 64.0623C160.815 68.3236 170.82 62.0243 165.818 56.0957C161.927 51.4639 155.072 48.129 144.882 48.129C102.455 48.129 83.7426 105.007 116.721 105.007C134.692 105.007 151.367 88.3329 155.257 82.7747C154.516 83.5158 149.329 81.2925 149.699 79.4398L149.143 83.5158C148.958 107.045 134.322 141.506 116.536 139.838C113.386 139.468 112.089 137.43 112.089 134.836C112.089 128.907 122.094 119.273 145.067 113.53C159.518 109.824 152.293 101.487 143.4 104.081C111.163 113.53 99.6759 127.425 99.6759 137.8C99.6759 145.026 105.605 150.584 113.942 150.955ZM194.72 109.454C214.359 109.454 239 95.3732 251.228 77.9577C250.301 82.96 246.596 96.8553 246.596 101.487C246.596 110.01 254.748 109.454 261.232 102.784L288.097 75.5491L290.32 85.7391C293.284 99.4491 299.213 104.822 308.847 104.822C326.263 104.822 342.196 85.7391 349.421 74.8081L344.049 63.6918C339.787 74.8081 321.631 92.5941 311.626 92.5941C306.994 92.5941 304.771 89.815 303.289 83.7011L300.325 71.2879C297.916 60.7275 289.023 58.3189 279.018 68.1383L261.788 84.8127L264.382 69.991C266.235 59.2453 255.674 58.1337 250.116 65.915C241.779 77.0313 216.767 97.7817 196.387 97.7817C187.865 97.7817 185.456 93.7057 185.456 88.3329C230.848 84.998 239.185 47.2027 208.986 47.2027C172.858 47.2027 157.11 109.454 194.72 109.454Z",fill:"currentColor"})})}),y4.jsxs("p",{className:h4.settingsVersion,children:["v","3.0.2"]}),y4.jsx("button",{className:h4.themeToggle,onClick:K,title:Y?"Switch to light mode":"Switch to dark mode",children:y4.jsx("span",{className:h4.themeIconWrapper,children:y4.jsx("span",{className:h4.themeIcon,children:Y?y4.jsx(GO,{size:20}):y4.jsx(BO,{size:20})},Y?"sun":"moon")})})]}),y4.jsx("div",{className:h4.divider}),y4.jsxs("div",{className:h4.settingsSection,children:[y4.jsxs("div",{className:h4.settingsRow,children:[y4.jsxs("div",{className:h4.settingsLabel,children:["Output Detail",y4.jsx(JG,{content:"Controls how much detail is included in the copied output"})]}),y4.jsxs("button",{className:h4.cycleButton,onClick:()=>{let o=(MB.findIndex((p)=>p.value===J.outputDetail)+1)%MB.length;H({outputDetail:MB[o].value})},children:[y4.jsx("span",{className:h4.cycleButtonText,children:MB.find((R)=>R.value===J.outputDetail)?.label},J.outputDetail),y4.jsx("span",{className:h4.cycleDots,children:MB.map((R)=>y4.jsx("span",{className:`${h4.cycleDot} ${J.outputDetail===R.value?h4.active:""}`},R.value))})]})]}),y4.jsxs("div",{className:`${h4.settingsRow} ${h4.settingsRowMarginTop} ${!W?h4.settingsRowDisabled:""}`,children:[y4.jsxs("div",{className:h4.settingsLabel,children:["React Components",y4.jsx(JG,{content:!W?"Disabled — production builds minify component names, making detection unreliable. Use in development mode.":"Include React component names in annotations"})]}),y4.jsx(VH,{checked:W&&J.reactEnabled,onChange:(R)=>H({reactEnabled:R.target.checked}),disabled:!W})]}),y4.jsxs("div",{className:`${h4.settingsRow} ${h4.settingsRowMarginTop}`,children:[y4.jsxs("div",{className:h4.settingsLabel,children:["Hide Until Restart",y4.jsx(JG,{content:"Hides the toolbar until you open a new tab"})]}),y4.jsx(VH,{checked:!1,onChange:(R)=>{if(R.target.checked)g()}})]})]}),y4.jsx("div",{className:h4.divider}),y4.jsxs("div",{className:h4.settingsSection,children:[y4.jsx("div",{className:`${h4.settingsLabel} ${h4.settingsLabelMarker}`,children:"Marker Color"}),y4.jsx("div",{className:h4.colorOptions,children:NB.map((R)=>y4.jsx("button",{className:`${h4.colorOption} ${J.annotationColorId===R.id?h4.selected:""}`,style:{"--swatch":R.srgb,"--swatch-p3":R.p3},onClick:()=>H({annotationColorId:R.id}),title:R.label,type:"button"},R.id))})]}),y4.jsx("div",{className:h4.divider}),y4.jsxs("div",{className:h4.settingsSection,children:[y4.jsx(G3,{className:"checkbox-field",label:"Clear on copy/send",checked:J.autoClearAfterCopy,onChange:(R)=>H({autoClearAfterCopy:R.target.checked}),tooltip:"Automatically clear annotations after copying"}),y4.jsx(G3,{className:h4.checkboxField,label:"Block page interactions",checked:J.blockInteractions,onChange:(R)=>H({blockInteractions:R.target.checked})})]}),y4.jsx("div",{className:h4.divider}),y4.jsxs("button",{className:h4.settingsNavLink,onClick:()=>b("automations"),children:[y4.jsx("span",{children:"Manage MCP & Webhooks"}),y4.jsxs("span",{className:h4.settingsNavLinkRight,children:[A&&O!=="disconnected"&&y4.jsx("span",{className:`${h4.mcpNavIndicator} ${h4[O]}`}),y4.jsx("svg",{width:"16",height:"16",viewBox:"0 0 16 16",fill:"none",xmlns:"http://www.w3.org/2000/svg",children:y4.jsx("path",{d:"M7.5 12.5L12 8L7.5 3.5",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})})]})]})]}),y4.jsxs("div",{className:`${h4.settingsPage} ${h4.automationsPage} ${J4==="automations"?h4.slideIn:""}`,children:[y4.jsxs("button",{className:h4.settingsBackButton,onClick:()=>b("main"),children:[y4.jsx(QO,{size:16}),y4.jsx("span",{children:"Manage MCP & Webhooks"})]}),y4.jsx("div",{className:h4.divider}),y4.jsxs("div",{className:h4.settingsSection,children:[y4.jsxs("div",{className:h4.settingsRow,children:[y4.jsxs("span",{className:h4.automationHeader,children:["MCP Connection",y4.jsx(JG,{content:"Connect via Model Context Protocol to let AI agents like Claude Code receive annotations in real-time."})]}),A&&y4.jsx("div",{className:`${h4.mcpStatusDot} ${h4[O]}`,title:O==="connected"?"Connected":O==="connecting"?"Connecting...":"Disconnected"})]}),y4.jsxs("p",{className:h4.automationDescription,style:{paddingBottom:6},children:["MCP connection allows agents to receive and act on annotations."," ",y4.jsx("a",{href:"https://agentation.dev/mcp",target:"_blank",rel:"noopener noreferrer",className:h4.learnMoreLink,children:"Learn more"})]})]}),y4.jsx("div",{className:h4.divider}),y4.jsxs("div",{className:`${h4.settingsSection} ${h4.settingsSectionGrow}`,children:[y4.jsxs("div",{className:h4.settingsRow,children:[y4.jsxs("span",{className:h4.automationHeader,children:["Webhooks",y4.jsx(JG,{content:"Send annotation data to any URL endpoint when annotations change. Useful for custom integrations."})]}),y4.jsxs("div",{className:h4.autoSendContainer,children:[y4.jsx("label",{htmlFor:"agentation-auto-send",className:`${h4.autoSendLabel} ${J.webhooksEnabled?h4.active:""} ${!J.webhookUrl?h4.disabled:""}`,children:"Auto-Send"}),y4.jsx(VH,{id:"agentation-auto-send",checked:J.webhooksEnabled,onChange:(R)=>H({webhooksEnabled:R.target.checked}),disabled:!J.webhookUrl})]})]}),y4.jsx("p",{className:h4.automationDescription,children:"The webhook URL will receive live annotation changes and annotation data."}),y4.jsx("textarea",{className:h4.webhookUrlInput,placeholder:"Webhook URL",value:J.webhookUrl,onKeyDown:(R)=>R.stopPropagation(),onChange:(R)=>H({webhookUrl:R.target.value})})]})]})]})})}function OH(J,H="filtered"){let{name:Y,path:K}=T0(J);if(H==="off")return{name:Y,elementName:Y,path:K,reactComponents:null};let W=wR(J,{mode:H});return{name:W.path?`${W.path} ${Y}`:Y,elementName:Y,path:K,reactComponents:W.path}}var B3=!1,FH={outputDetail:"standard",autoClearAfterCopy:!1,annotationColorId:"blue",blockInteractions:!0,reactEnabled:!0,markerClickBehavior:"edit",webhookUrl:"",webhooksEnabled:!0},u6=(J)=>{if(!J||!J.trim())return!1;try{let H=new URL(J.trim());return H.protocol==="http:"||H.protocol==="https:"}catch{return!1}},BM={compact:"off",standard:"filtered",detailed:"smart",forensic:"all"},NB=[{id:"indigo",label:"Indigo",srgb:"#6155F5",p3:"color(display-p3 0.38 0.33 0.96)"},{id:"blue",label:"Blue",srgb:"#0088FF",p3:"color(display-p3 0.00 0.53 1.00)"},{id:"cyan",label:"Cyan",srgb:"#00C3D0",p3:"color(display-p3 0.00 0.76 0.82)"},{id:"green",label:"Green",srgb:"#34C759",p3:"color(display-p3 0.20 0.78 0.35)"},{id:"yellow",label:"Yellow",srgb:"#FFCC00",p3:"color(display-p3 1.00 0.80 0.00)"},{id:"orange",label:"Orange",srgb:"#FF8D28",p3:"color(display-p3 1.00 0.55 0.16)"},{id:"red",label:"Red",srgb:"#FF383C",p3:"color(display-p3 1.00 0.22 0.24)"}],$M=()=>{if(typeof document>"u")return;if(document.getElementById("agentation-color-tokens"))return;let J=document.createElement("style");J.id="agentation-color-tokens",J.textContent=[...NB.map((H)=>`
      [data-agentation-accent="${H.id}"] {
        --agentation-color-accent: ${H.srgb};
      }

      @supports (color: color(display-p3 0 0 0)) {
        [data-agentation-accent="${H.id}"] {
          --agentation-color-accent: ${H.p3};
        }
      }
    `),`:root {
      ${NB.map((H)=>`--agentation-color-${H.id}: ${H.srgb};`).join(`
`)}
    }`,`@supports (color: color(display-p3 0 0 0)) {
      :root {
        ${NB.map((H)=>`--agentation-color-${H.id}: ${H.p3};`).join(`
`)}
      }
    }`].join(""),document.head.appendChild(J)};$M();function zG(J,H){let Y=document.elementFromPoint(J,H);if(!Y)return null;while(Y?.shadowRoot){let K=Y.shadowRoot.elementFromPoint(J,H);if(!K||K===Y)break;Y=K}return Y}function RH(J){let H=J;while(H&&H!==document.body){let K=window.getComputedStyle(H).position;if(K==="fixed"||K==="sticky")return!0;H=H.parentElement}return!1}function QG(J){return J.status!=="resolved"&&J.status!=="dismissed"}function az(J){let H=EH(J),Y=H.found?H:hR(J);if(Y.found&&Y.source)return mR(Y.source,"path");return}function N3({demoAnnotations:J,demoDelay:H=1000,enableDemoMode:Y=!1,onAnnotationAdd:K,onAnnotationDelete:W,onAnnotationUpdate:O,onAnnotationsClear:A,onCopy:C,onSubmit:x,copyToClipboard:J4=!0,endpoint:b,sessionId:g,onSessionCreated:R,webhookUrl:o,className:p}={}){let[q4,h]=m.useState(!1),[t,I4]=m.useState([]),[u4,i4]=m.useState(!0),[g7,h7]=m.useState(()=>LR()),[T4,p4]=m.useState(!1),N7=m.useRef(null);m.useEffect(()=>{let F=(I)=>{let w=N7.current;if(w&&w.contains(I.target))I.stopPropagation()},N=["mousedown","click","pointerdown"];return N.forEach((I)=>document.body.addEventListener(I,F)),()=>{N.forEach((I)=>document.body.removeEventListener(I,F))}},[]);let[Y4,l4]=m.useState(!1),[d4,b4]=m.useState(!1),[n4,B4]=m.useState(null),[L4,O4]=m.useState({x:0,y:0}),[$4,C4]=m.useState(null),[R7,s]=m.useState(!1),[c4,Q7]=m.useState("idle"),[W7,EZ]=m.useState(!1),[I2,u7]=m.useState(!1),[AZ,eZ]=m.useState(null),[Z5,M4]=m.useState(null),[_2,uZ]=m.useState([]),[Y2,qZ]=m.useState(null),[s7,M2]=m.useState(null),[N4,U4]=m.useState(null),[D4,z7]=m.useState(null),[J7,t4]=m.useState([]),[b7,o7]=m.useState(0),[S7,A7]=m.useState(!1),[o4,f]=m.useState(!1),[u,G4]=m.useState(!1),[z4,S4]=m.useState(!1),[m4,j4]=m.useState(!1),[_,E]=m.useState("main"),[a,H4]=m.useState(!1),[e,x4]=m.useState(!1),[F4,E4]=m.useState(!1),[Q4,M7]=m.useState([]),[U7,H7]=m.useState(null),f7=m.useRef(!1),[X7,e7]=m.useState(!1),[kZ,dZ]=m.useState(!1),[yZ,N2]=m.useState(1),[t5,P8]=m.useState("new-page"),[wZ,G5]=m.useState(""),[D2,AB]=m.useState(!1),[K7,b2]=m.useState(null),V9=m.useRef(!1),XG=m.useRef({rearrange:null,placements:[]}),K6=m.useRef({rearrange:null,placements:[]}),[A8,x0]=m.useState(0),[CB,TB]=m.useState(0),[EB,YG]=m.useState(0),[f2,p6]=m.useState(0),Y5=m.useRef(new Set),O9=m.useRef(new Set),P2=m.useRef(null),c6=m.useRef(),jG=e&&q4&&!F4&&X7;m.useEffect(()=>{if(jG){dZ(!1);let F=C0(()=>{dZ(!0)});return()=>cancelAnimationFrame(F)}else dZ(!1)},[jG]);let e5=m.useRef(new Map),I5=m.useRef(new Map),l6=m.useRef(),[j5,S0]=m.useState(!1),[m2,v0]=m.useState([]),k0=m.useRef(m2);k0.current=m2;let[y0,nz]=m.useState(null),KG=m.useRef(null),vH=m.useRef(!1),tz=m.useRef([]),wB=m.useRef(0),g0=m.useRef(null),WG=m.useRef(null),kH=m.useRef(1),[b0,f0]=m.useState(!1),x5=m.useRef(null),[gZ,C8]=m.useState([]),S5=m.useRef({cmd:!1,shift:!1}),L2=()=>{H4(!0)},ez=()=>{H4(!1)},F9=()=>{if(!b0)x5.current=q7(()=>f0(!0),850)},Z6=()=>{if(x5.current)clearTimeout(x5.current),x5.current=null;f0(!1),ez()};m.useEffect(()=>{return()=>{if(x5.current)clearTimeout(x5.current)}},[]);let[T7,IB]=m.useState(()=>{try{let F=JSON.parse(localStorage.getItem("feedback-toolbar-settings")??"");return{...FH,...F,annotationColorId:NB.find((N)=>N.id===F.annotationColorId)?F.annotationColorId:FH.annotationColorId}}catch{return FH}}),[K5,T8]=m.useState(!0),[m0,R9]=m.useState(!1),_G=()=>{N7.current?.classList.add(K4.disableTransitions),T8((F)=>!F),C0(()=>{N7.current?.classList.remove(K4.disableTransitions)})},h0=!0,pZ=h0&&T7.reactEnabled?BM[T7.outputDetail]:"off",[iZ,M9]=m.useState(g??null),u0=m.useRef(!1),[B5,s6]=m.useState(b?"connecting":"disconnected"),[CZ,LG]=m.useState(null),[a6,d0]=m.useState(!1),[E8,N9]=m.useState(null),UG=m.useRef(!1),[p0,w8]=m.useState(new Set),[xB,VG]=m.useState(new Set),[D9,OG]=m.useState(!1),[ZQ,v5]=m.useState(!1),[k5,c0]=m.useState(!1),i6=m.useRef(null),W5=m.useRef(null),o6=m.useRef(null),I8=m.useRef(null),y5=m.useRef(!1),W6=m.useRef(0),x2=m.useRef(null),SB=m.useRef(null),P9=8,g5=50,l0=m.useRef(null),S2=m.useRef(null),v2=m.useRef(null),B7=typeof window<"u"?window.location.pathname:"/";m.useEffect(()=>{if(z4)j4(!0);else{H4(!1),E("main");let F=q7(()=>j4(!1),0);return()=>clearTimeout(F)}},[z4]);let x8=q4&&u4&&!e;m.useEffect(()=>{if(x8){b4(!1),l4(!0),w8(new Set);let F=q7(()=>{w8((N)=>{let I=new Set(N);return t.forEach((w)=>I.add(w.id)),I})},350);return()=>clearTimeout(F)}else if(Y4){b4(!0);let F=q7(()=>{l4(!1),b4(!1)},250);return()=>clearTimeout(F)}},[x8]),m.useEffect(()=>{f(!0),o7(window.scrollY);let F=KH(B7);if(I4(F.filter(QG)),!B3)R9(!0),B3=!0,q7(()=>R9(!1),750);try{let N=localStorage.getItem("feedback-toolbar-theme");if(N!==null)T8(N==="dark")}catch(N){}try{let N=localStorage.getItem("feedback-toolbar-position");if(N){let I=JSON.parse(N);if(typeof I.x==="number"&&typeof I.y==="number")LG(I)}}catch(N){}},[B7]),m.useEffect(()=>{if(o4)localStorage.setItem("feedback-toolbar-settings",JSON.stringify(T7))},[T7,o4]),m.useEffect(()=>{if(o4)localStorage.setItem("feedback-toolbar-theme",K5?"dark":"light")},[K5,o4]);let FG=m.useRef(!1);m.useEffect(()=>{let F=FG.current;if(FG.current=a6,F&&!a6&&CZ&&o4)localStorage.setItem("feedback-toolbar-position",JSON.stringify(CZ))},[a6,CZ,o4]),m.useEffect(()=>{if(!b||!o4||u0.current)return;u0.current=!0,s6("connecting"),(async()=>{try{let N=WR(B7),I=g||N,w=!1;if(I)try{let v=await a_(b,I);M9(v.id),s6("connected"),WH(B7,v.id),w=!0;let i=KH(B7),V4=new Set(v.annotations.map((g4)=>g4.id)),P4=i.filter((g4)=>{if(V4.has(g4.id))return!1;return!0});if(P4.length>0){let s4=`${typeof window<"u"?window.location.origin:""}${B7}`,$7=(await Promise.allSettled(P4.map((Z7)=>P0(b,v.id,{...Z7,sessionId:v.id,url:s4})))).map((Z7,k4)=>{if(Z7.status==="fulfilled")return Z7.value;return console.warn("[Agentation] Failed to sync annotation:",Z7.reason),P4[k4]}),D7=[...v.annotations,...$7];I4(D7.filter(QG)),OB(B7,D7.filter(QG),v.id)}else I4(v.annotations.filter(QG)),OB(B7,v.annotations.filter(QG),v.id)}catch(v){console.warn("[Agentation] Could not join session, creating new:",v),_R(B7)}if(!w){let v=typeof window<"u"?window.location.href:"/",i=await _H(b,v);M9(i.id),s6("connected"),WH(B7,i.id),R?.(i.id);let V4=QR(),P4=typeof window<"u"?window.location.origin:"",g4=[];for(let[s4,r4]of V4){let $7=r4.filter((k4)=>!k4._syncedTo);if($7.length===0)continue;let D7=`${P4}${s4}`,Z7=s4===B7;g4.push((async()=>{try{let k4=Z7?i:await _H(b,D7),cZ=(await Promise.allSettled($7.map((a7)=>P0(b,k4.id,{...a7,sessionId:k4.id,url:D7})))).map((a7,HZ)=>{if(a7.status==="fulfilled")return a7.value;return console.warn("[Agentation] Failed to sync annotation:",a7.reason),$7[HZ]}).filter(QG);if(OB(s4,cZ,k4.id),Z7){let a7=new Set($7.map((HZ)=>HZ.id));I4((HZ)=>{let Y7=HZ.filter((L7)=>!a7.has(L7.id));return[...cZ,...Y7]})}}catch(k4){console.warn(`[Agentation] Failed to sync annotations for ${s4}:`,k4)}})())}await Promise.allSettled(g4)}}catch(N){s6("disconnected"),console.warn("[Agentation] Failed to initialize session, using local storage:",N)}})()},[b,g,o4,R,B7]),m.useEffect(()=>{if(!b||!o4)return;let F=async()=>{try{if((await fetch(`${b}/health`)).ok)s6("connected");else s6("disconnected")}catch{s6("disconnected")}};F();let N=HO(F,1e4);return()=>clearInterval(N)},[b,o4]),m.useEffect(()=>{if(!b||!o4||!iZ)return;let F=new EventSource(`${b}/sessions/${iZ}/events`),N=["resolved","dismissed"],I=(w)=>{try{let v=JSON.parse(w.data);if(N.includes(v.payload?.status)){let i=v.payload.id,V4=v.payload.kind;if(V4==="placement"){for(let[P4,g4]of e5.current)if(g4===i){e5.current.delete(P4),M7((s4)=>s4.filter((r4)=>r4.id!==P4));break}}else if(V4==="rearrange"){for(let[P4,g4]of I5.current)if(g4===i){I5.current.delete(P4),b2((s4)=>{if(!s4)return null;let r4=s4.sections.filter(($7)=>$7.id!==P4);if(r4.length===0)return null;return{...s4,sections:r4}});break}}else VG((P4)=>new Set(P4).add(i)),q7(()=>{I4((P4)=>P4.filter((g4)=>g4.id!==i)),VG((P4)=>{let g4=new Set(P4);return g4.delete(i),g4})},150)}}catch{}};return F.addEventListener("annotation.updated",I),()=>{F.removeEventListener("annotation.updated",I),F.close()}},[b,o4,iZ]),m.useEffect(()=>{if(!b||!o4)return;let F=SB.current==="disconnected",N=B5==="connected";if(SB.current=B5,F&&N)(async()=>{try{let w=KH(B7);if(w.length===0)return;let i=`${typeof window<"u"?window.location.origin:""}${B7}`,V4=iZ,P4=[];if(V4)try{P4=(await a_(b,V4)).annotations}catch{V4=null}if(!V4)V4=(await _H(b,i)).id,M9(V4),WH(B7,V4);let g4=new Set(P4.map((r4)=>r4.id)),s4=w.filter((r4)=>!g4.has(r4.id));if(s4.length>0){let $7=(await Promise.allSettled(s4.map((k4)=>P0(b,V4,{...k4,sessionId:V4,url:i})))).map((k4,zZ)=>{if(k4.status==="fulfilled")return k4.value;return console.warn("[Agentation] Failed to sync annotation on reconnect:",k4.reason),s4[zZ]}),Z7=[...P4,...$7].filter(QG);I4(Z7),OB(B7,Z7,V4)}}catch(w){console.warn("[Agentation] Failed to sync on reconnect:",w)}})()},[B5,b,o4,iZ,B7]);let b5=m.useCallback(()=>{if(T4)return;p4(!0),S4(!1),h(!1),q7(()=>{UR(!0),h7(!0),p4(!1)},400)},[T4]);m.useEffect(()=>{if(!Y)return;if(!o4||!J||J.length===0)return;if(t.length>0)return;let F=[];return F.push(q7(()=>{h(!0)},H-200)),J.forEach((N,I)=>{let w=H+I*300;F.push(q7(()=>{let v=document.querySelector(N.selector);if(!v)return;let i=v.getBoundingClientRect(),{name:V4,path:P4}=T0(v),g4={id:`demo-${Date.now()}-${I}`,x:(i.left+i.width/2)/window.innerWidth*100,y:i.top+i.height/2+window.scrollY,comment:N.comment,element:V4,elementPath:P4,timestamp:Date.now(),selectedText:N.selectedText,boundingBox:{x:i.left,y:i.top+window.scrollY,width:i.width,height:i.height},nearbyText:UB(v),cssClasses:VB(v)};I4((s4)=>[...s4,g4])},w))}),()=>{F.forEach(clearTimeout)}},[Y,o4,J,H]),m.useEffect(()=>{let F=()=>{if(o7(window.scrollY),A7(!0),v2.current)clearTimeout(v2.current);v2.current=q7(()=>{A7(!1)},150)};return window.addEventListener("scroll",F,{passive:!0}),()=>{if(window.removeEventListener("scroll",F),v2.current)clearTimeout(v2.current)}},[]),m.useEffect(()=>{if(o4&&t.length>0)if(iZ)OB(B7,t,iZ);else O3(B7,t);else if(o4&&t.length===0)localStorage.removeItem(rz(B7))},[t,B7,o4,iZ]),m.useEffect(()=>{if(o4&&!f7.current){f7.current=!0;let F=JR(B7);if(F.length>0)M7(F)}},[o4,B7]),m.useEffect(()=>{if(o4&&f7.current&&!X7)if(Q4.length>0)qR(B7,Q4);else HR(B7)},[Q4,B7,o4,X7]),m.useEffect(()=>{if(o4&&!V9.current){V9.current=!0;let F=XR(B7);if(F){let N={...F,sections:F.sections.map((I)=>({...I,currentRect:I.currentRect??{...I.originalRect}}))};b2(N)}}},[o4,B7]),m.useEffect(()=>{if(o4&&V9.current&&!X7)if(K7)YR(B7,K7);else jR(B7)},[K7,B7,o4,X7]);let s0=m.useRef(!1);m.useEffect(()=>{if(o4&&!s0.current){s0.current=!0;let F=KR(B7);if(F){if(K6.current={rearrange:F.rearrange,placements:F.placements||[]},F.purpose)G5(F.purpose)}}},[o4,B7]),m.useEffect(()=>{if(!o4||!s0.current)return;let F=K6.current;if(X7)if((K7?.sections?.length??0)>0||Q4.length>0||wZ)s_(B7,{rearrange:K7,placements:Q4,purpose:wZ});else cz(B7);else if((F.rearrange?.sections?.length??0)>0||F.placements.length>0||wZ)s_(B7,{rearrange:F.rearrange,placements:F.placements,purpose:wZ});else cz(B7)},[K7,Q4,wZ,X7,B7,o4]),m.useEffect(()=>{if(e&&!K7)b2({sections:[],originalOrder:[],detectedAt:Date.now()})},[e,K7]),m.useEffect(()=>{if(!b||!iZ)return;let F=e5.current,N=new Set(Q4.map((I)=>I.id));for(let I of Q4){if(F.has(I.id))continue;F.set(I.id,"");let w=typeof window<"u"?window.location.pathname+window.location.search+window.location.hash:B7;P0(b,iZ,{id:I.id,x:I.x/window.innerWidth*100,y:I.y,comment:`Place ${I.type} at (${Math.round(I.x)}, ${Math.round(I.y)}), ${I.width}×${I.height}px${I.text?` — "${I.text}"`:""}`,element:`[design:${I.type}]`,elementPath:"[placement]",timestamp:I.timestamp,url:w,intent:"change",severity:"important",kind:"placement",placement:{componentType:I.type,width:I.width,height:I.height,scrollY:I.scrollY,text:I.text}}).then((v)=>{if(F.has(I.id))F.set(I.id,v.id)}).catch((v)=>{console.warn("[Agentation] Failed to sync placement annotation:",v),F.delete(I.id)})}for(let[I,w]of F)if(!N.has(I)){if(F.delete(I),w)U9(b,w).catch(()=>{})}},[Q4,b,iZ,B7]),m.useEffect(()=>{if(!b||!iZ)return;if(l6.current)clearTimeout(l6.current);return l6.current=q7(()=>{let F=I5.current;if(!K7||K7.sections.length===0){for(let[,w]of F)if(w)U9(b,w).catch(()=>{});F.clear();return}let N=new Set(K7.sections.map((w)=>w.id)),I=typeof window<"u"?window.location.pathname+window.location.search+window.location.hash:B7;for(let w of K7.sections){let{originalRect:v,currentRect:i}=w;if(!(Math.abs(v.x-i.x)>1||Math.abs(v.y-i.y)>1||Math.abs(v.width-i.width)>1||Math.abs(v.height-i.height)>1)){let g4=F.get(w.id);if(g4)F.delete(w.id),U9(b,g4).catch(()=>{});continue}let P4=F.get(w.id);if(P4)i_(b,P4,{comment:`Move ${w.label} section (${w.tagName}) — from (${Math.round(v.x)},${Math.round(v.y)}) ${Math.round(v.width)}×${Math.round(v.height)} to (${Math.round(i.x)},${Math.round(i.y)}) ${Math.round(i.width)}×${Math.round(i.height)}`}).catch((g4)=>{console.warn("[Agentation] Failed to update rearrange annotation:",g4)});else F.set(w.id,""),P0(b,iZ,{id:w.id,x:i.x/window.innerWidth*100,y:i.y,comment:`Move ${w.label} section (${w.tagName}) — from (${Math.round(v.x)},${Math.round(v.y)}) ${Math.round(v.width)}×${Math.round(v.height)} to (${Math.round(i.x)},${Math.round(i.y)}) ${Math.round(i.width)}×${Math.round(i.height)}`,element:w.selector,elementPath:"[rearrange]",timestamp:Date.now(),url:I,intent:"change",severity:"important",kind:"rearrange",rearrange:{selector:w.selector,label:w.label,tagName:w.tagName,originalRect:v,currentRect:i}}).then((g4)=>{if(F.has(w.id))F.set(w.id,g4.id)}).catch((g4)=>{console.warn("[Agentation] Failed to sync rearrange annotation:",g4),F.delete(w.id)})}for(let[w,v]of F)if(!N.has(w)){if(F.delete(w),v)U9(b,v).catch(()=>{})}},300),()=>{if(l6.current)clearTimeout(l6.current)}},[K7,b,iZ,B7]);let r6=m.useRef(new Map);m.useLayoutEffect(()=>{let F=K7?.sections??[],N=new Set;if((e||F4)&&q4)for(let I of F){N.add(I.id);try{let w=document.querySelector(I.selector);if(!w)continue;if(!r6.current.has(I.id)){let v={transform:w.style.transform,transformOrigin:w.style.transformOrigin,opacity:w.style.opacity,position:w.style.position,zIndex:w.style.zIndex,display:w.style.display},i=[],V4=w.parentElement;while(V4&&V4!==document.body){let g4=getComputedStyle(V4);if(g4.overflow!=="visible"||g4.overflowX!=="visible"||g4.overflowY!=="visible")i.push({el:V4,overflow:V4.style.overflow}),V4.style.overflow="visible";V4=V4.parentElement}if(getComputedStyle(w).display==="inline")w.style.display="inline-block";r6.current.set(I.id,{el:w,origStyles:v,ancestors:i}),w.style.transformOrigin="top left",w.style.zIndex="9999"}}catch{}}for(let[I,w]of r6.current)if(!N.has(I)){let{el:v,origStyles:i,ancestors:V4}=w;v.style.transition="transform 0.4s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.4s cubic-bezier(0.22, 1, 0.36, 1)",v.style.transform=i.transform,v.style.transformOrigin=i.transformOrigin,v.style.opacity=i.opacity,v.style.position=i.position,v.style.zIndex=i.zIndex,r6.current.delete(I),q7(()=>{v.style.transition="",v.style.display=i.display;for(let P4 of V4)P4.el.style.overflow=P4.overflow},450)}},[K7,e,F4,q4]),m.useEffect(()=>{return()=>{for(let[,F]of r6.current){let{el:N,origStyles:I,ancestors:w}=F;N.style.transition="transform 0.4s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.4s cubic-bezier(0.22, 1, 0.36, 1)",N.style.transform=I.transform,N.style.transformOrigin=I.transformOrigin,N.style.opacity=I.opacity,N.style.position=I.position,N.style.zIndex=I.zIndex,q7(()=>{N.style.transition="",N.style.display=I.display;for(let v of w)v.el.style.overflow=v.overflow},450)}r6.current.clear()}},[]);let A9=m.useCallback(()=>{E4(!0),x4(!1),H7(null),clearTimeout(c6.current),c6.current=q7(()=>{E4(!1)},300)},[]),vB=m.useCallback(()=>{if(e)E4(!0),x4(!1),H7(null),clearTimeout(c6.current),c6.current=q7(()=>{E4(!1)},300);h(!1)},[e]),RG=m.useCallback(()=>{if(u)return;YO(),G4(!0)},[u]),MG=m.useCallback(()=>{if(!u)return;S_(),G4(!1)},[u]),NG=m.useCallback(()=>{if(u)MG();else RG()},[u,RG,MG]),S8=m.useCallback(()=>{if(gZ.length===0)return;let F=gZ[0],N=F.element,I=gZ.length>1,w=gZ.map((v)=>v.element.getBoundingClientRect());if(!I){let v=w[0],i=RH(N);C4({x:v.left/window.innerWidth*100,y:i?v.top:v.top+window.scrollY,clientY:v.top,element:F.name,elementPath:F.path,boundingBox:{x:v.left,y:i?v.top:v.top+window.scrollY,width:v.width,height:v.height},isFixed:i,fullPath:uz(N),accessibility:hz(N),computedStyles:mz(N),computedStylesObj:fz(N),nearbyElements:bz(N),cssClasses:VB(N),nearbyText:UB(N),reactComponents:F.reactComponents,sourceFile:az(N)})}else{let v={left:Math.min(...w.map((k4)=>k4.left)),top:Math.min(...w.map((k4)=>k4.top)),right:Math.max(...w.map((k4)=>k4.right)),bottom:Math.max(...w.map((k4)=>k4.bottom))},i=gZ.slice(0,5).map((k4)=>k4.name).join(", "),V4=gZ.length>5?` +${gZ.length-5} more`:"",P4=w.map((k4)=>({x:k4.left,y:k4.top+window.scrollY,width:k4.width,height:k4.height})),s4=gZ[gZ.length-1].element,r4=w[w.length-1],$7=r4.left+r4.width/2,D7=r4.top+r4.height/2,Z7=RH(s4);C4({x:$7/window.innerWidth*100,y:Z7?D7:D7+window.scrollY,clientY:D7,element:`${gZ.length} elements: ${i}${V4}`,elementPath:"multi-select",boundingBox:{x:v.left,y:v.top+window.scrollY,width:v.right-v.left,height:v.bottom-v.top},isMultiSelect:!0,isFixed:Z7,elementBoundingBoxes:P4,multiSelectElements:gZ.map((k4)=>k4.element),targetElement:s4,fullPath:uz(N),accessibility:hz(N),computedStyles:mz(N),computedStylesObj:fz(N),nearbyElements:bz(N),cssClasses:VB(N),nearbyText:UB(N),sourceFile:az(N)})}C8([]),B4(null)},[gZ]);m.useEffect(()=>{if(!q4){if(C4(null),U4(null),z7(null),t4([]),B4(null),S4(!1),C8([]),S5.current={cmd:!1,shift:!1},u)MG()}},[q4,u,MG]),m.useEffect(()=>{return()=>{S_()}},[]),m.useEffect(()=>{if(!q4)return;let F=["p","span","h1","h2","h3","h4","h5","h6","li","td","th","label","blockquote","figcaption","caption","legend","dt","dd","pre","code","em","strong","b","i","u","s","a","time","address","cite","q","abbr","dfn","mark","small","sub","sup","[contenteditable]"].join(", "),N=":not([data-agentation-root]):not([data-agentation-root] *)",I=document.createElement("style");return I.id="feedback-cursor-styles",I.textContent=`
      body ${N} {
        cursor: crosshair !important;
      }

      body :is(${F})${N} {
        cursor: text !important;
      }
    `,document.head.appendChild(I),()=>{let w=document.getElementById("feedback-cursor-styles");if(w)w.remove()}},[q4]),m.useEffect(()=>{if(y0!==null&&q4)return document.documentElement.setAttribute("data-drawing-hover",""),()=>document.documentElement.removeAttribute("data-drawing-hover")},[y0,q4]),m.useEffect(()=>{if(!q4||$4||j5||e)return;let F=(N)=>{let I=N.composedPath()[0]||N.target;if(t2(I,"[data-feedback-toolbar]")){B4(null);return}let w=zG(N.clientX,N.clientY);if(!w||t2(w,"[data-feedback-toolbar]")){B4(null);return}let{name:v,elementName:i,path:V4,reactComponents:P4}=OH(w,pZ),g4=w.getBoundingClientRect();B4({element:v,elementName:i,elementPath:V4,rect:g4,reactComponents:P4}),O4({x:N.clientX,y:N.clientY})};return document.addEventListener("mousemove",F),()=>document.removeEventListener("mousemove",F)},[q4,$4,j5,e,pZ,m2]);let n6=m.useCallback((F)=>{if(U4(F),eZ(null),M4(null),uZ([]),F.elementBoundingBoxes?.length){let N=[];for(let I of F.elementBoundingBoxes){let w=I.x+I.width/2,v=I.y+I.height/2-window.scrollY,i=zG(w,v);if(i)N.push(i)}t4(N),z7(null)}else if(F.boundingBox){let N=F.boundingBox,I=N.x+N.width/2,w=F.isFixed?N.y+N.height/2:N.y+N.height/2-window.scrollY,v=zG(I,w);if(v){let i=v.getBoundingClientRect(),V4=i.width/N.width,P4=i.height/N.height;if(V4<0.5||P4<0.5)z7(null);else z7(v)}else z7(null);t4([])}else z7(null),t4([])},[]);m.useEffect(()=>{if(!q4||j5||e)return;let F=(N)=>{if(y5.current){y5.current=!1;return}let I=N.composedPath()[0]||N.target;if(t2(I,"[data-feedback-toolbar]"))return;if(t2(I,"[data-annotation-popup]"))return;if(t2(I,"[data-annotation-marker]"))return;if(N.metaKey&&N.shiftKey&&!$4&&!N4){N.preventDefault(),N.stopPropagation();let ZZ=zG(N.clientX,N.clientY);if(!ZZ)return;let cZ=ZZ.getBoundingClientRect(),{name:a7,path:HZ,reactComponents:Y7}=OH(ZZ,pZ),L7=gZ.findIndex((LZ)=>LZ.element===ZZ);if(L7>=0)C8((LZ)=>LZ.filter((UZ,G2)=>G2!==L7));else C8((LZ)=>[...LZ,{element:ZZ,rect:cZ,name:a7,path:HZ,reactComponents:Y7??void 0}]);return}let w=t2(I,"button, a, input, select, textarea, [role='button'], [onclick]");if(T7.blockInteractions&&w)N.preventDefault(),N.stopPropagation();if($4){if(w&&!T7.blockInteractions)return;N.preventDefault(),l0.current?.shake();return}if(N4){if(w&&!T7.blockInteractions)return;N.preventDefault(),S2.current?.shake();return}N.preventDefault();let v=zG(N.clientX,N.clientY);if(!v)return;let{name:i,path:V4,reactComponents:P4}=OH(v,pZ),g4=v.getBoundingClientRect(),s4=N.clientX/window.innerWidth*100,r4=RH(v),$7=r4?N.clientY:N.clientY+window.scrollY,D7=window.getSelection(),Z7;if(D7&&D7.toString().trim().length>0)Z7=D7.toString().trim().slice(0,500);let k4=fz(v),zZ=mz(v);C4({x:s4,y:$7,clientY:N.clientY,element:i,elementPath:V4,selectedText:Z7,boundingBox:{x:g4.left,y:r4?g4.top:g4.top+window.scrollY,width:g4.width,height:g4.height},nearbyText:UB(v),cssClasses:VB(v),isFixed:r4,fullPath:uz(v),accessibility:hz(v),computedStyles:zZ,computedStylesObj:k4,nearbyElements:bz(v),reactComponents:P4??void 0,sourceFile:az(v),targetElement:v}),B4(null)};return document.addEventListener("click",F,!0),()=>document.removeEventListener("click",F,!0)},[q4,j5,e,$4,N4,T7.blockInteractions,pZ,gZ]),m.useEffect(()=>{if(!q4)return;let F=(w)=>{if(w.key==="Meta")S5.current.cmd=!0;if(w.key==="Shift")S5.current.shift=!0},N=(w)=>{let v=S5.current.cmd&&S5.current.shift;if(w.key==="Meta")S5.current.cmd=!1;if(w.key==="Shift")S5.current.shift=!1;let i=S5.current.cmd&&S5.current.shift;if(v&&!i&&gZ.length>0)S8()},I=()=>{S5.current={cmd:!1,shift:!1},C8([])};return document.addEventListener("keydown",F),document.addEventListener("keyup",N),window.addEventListener("blur",I),()=>{document.removeEventListener("keydown",F),document.removeEventListener("keyup",N),window.removeEventListener("blur",I)}},[q4,gZ,S8]),m.useEffect(()=>{if(!q4||$4||j5||e)return;let F=(N)=>{let I=N.composedPath()[0]||N.target;if(t2(I,"[data-feedback-toolbar]"))return;if(t2(I,"[data-annotation-marker]"))return;if(t2(I,"[data-annotation-popup]"))return;if(new Set(["P","SPAN","H1","H2","H3","H4","H5","H6","LI","TD","TH","LABEL","BLOCKQUOTE","FIGCAPTION","CAPTION","LEGEND","DT","DD","PRE","CODE","EM","STRONG","B","I","U","S","A","TIME","ADDRESS","CITE","Q","ABBR","DFN","MARK","SMALL","SUB","SUP"]).has(I.tagName)||I.isContentEditable)return;N.preventDefault(),i6.current={x:N.clientX,y:N.clientY}};return document.addEventListener("mousedown",F),()=>document.removeEventListener("mousedown",F)},[q4,$4,j5,e]),m.useEffect(()=>{if(!q4||$4)return;let F=(N)=>{if(!i6.current)return;let I=N.clientX-i6.current.x,w=N.clientY-i6.current.y,v=I*I+w*w,i=P9*P9;if(!k5&&v>=i)W5.current=i6.current,c0(!0),N.preventDefault();if((k5||v>=i)&&W5.current){if(o6.current){let Y7=Math.min(W5.current.x,N.clientX),L7=Math.min(W5.current.y,N.clientY),LZ=Math.abs(N.clientX-W5.current.x),UZ=Math.abs(N.clientY-W5.current.y);o6.current.style.transform=`translate(${Y7}px, ${L7}px)`,o6.current.style.width=`${LZ}px`,o6.current.style.height=`${UZ}px`}let V4=Date.now();if(V4-W6.current<g5)return;W6.current=V4;let P4=W5.current.x,g4=W5.current.y,s4=Math.min(P4,N.clientX),r4=Math.min(g4,N.clientY),$7=Math.max(P4,N.clientX),D7=Math.max(g4,N.clientY),Z7=(s4+$7)/2,k4=(r4+D7)/2,zZ=new Set,ZZ=[[s4,r4],[$7,r4],[s4,D7],[$7,D7],[Z7,k4],[Z7,r4],[Z7,D7],[s4,k4],[$7,k4]];for(let[Y7,L7]of ZZ){let LZ=document.elementsFromPoint(Y7,L7);for(let UZ of LZ)if(UZ instanceof HTMLElement)zZ.add(UZ)}let cZ=document.querySelectorAll("button, a, input, img, p, h1, h2, h3, h4, h5, h6, li, label, td, th, div, span, section, article, aside, nav");for(let Y7 of cZ)if(Y7 instanceof HTMLElement){let L7=Y7.getBoundingClientRect(),LZ=L7.left+L7.width/2,UZ=L7.top+L7.height/2,G2=LZ>=s4&&LZ<=$7&&UZ>=r4&&UZ<=D7,lZ=Math.min(L7.right,$7)-Math.max(L7.left,s4),oZ=Math.min(L7.bottom,D7)-Math.max(L7.top,r4),G8=lZ>0&&oZ>0?lZ*oZ:0,$5=L7.width*L7.height,_5=$5>0?G8/$5:0;if(G2||_5>0.5)zZ.add(Y7)}let a7=[],HZ=new Set(["BUTTON","A","INPUT","IMG","P","H1","H2","H3","H4","H5","H6","LI","LABEL","TD","TH","SECTION","ARTICLE","ASIDE","NAV"]);for(let Y7 of zZ){if(t2(Y7,"[data-feedback-toolbar]")||t2(Y7,"[data-annotation-marker]"))continue;let L7=Y7.getBoundingClientRect();if(L7.width>window.innerWidth*0.8&&L7.height>window.innerHeight*0.5)continue;if(L7.width<10||L7.height<10)continue;if(L7.left<$7&&L7.right>s4&&L7.top<D7&&L7.bottom>r4){let LZ=Y7.tagName,UZ=HZ.has(LZ);if(!UZ&&(LZ==="DIV"||LZ==="SPAN")){let G2=Y7.textContent&&Y7.textContent.trim().length>0,lZ=Y7.onclick!==null||Y7.getAttribute("role")==="button"||Y7.getAttribute("role")==="link"||Y7.classList.contains("clickable")||Y7.hasAttribute("data-clickable");if((G2||lZ)&&!Y7.querySelector("p, h1, h2, h3, h4, h5, h6, button, a"))UZ=!0}if(UZ){let G2=!1;for(let lZ of a7)if(lZ.left<=L7.left&&lZ.right>=L7.right&&lZ.top<=L7.top&&lZ.bottom>=L7.bottom){G2=!0;break}if(!G2)a7.push(L7)}}}if(I8.current){let Y7=I8.current;while(Y7.children.length>a7.length)Y7.removeChild(Y7.lastChild);a7.forEach((L7,LZ)=>{let UZ=Y7.children[LZ];if(!UZ)UZ=document.createElement("div"),UZ.className=K4.selectedElementHighlight,Y7.appendChild(UZ);UZ.style.transform=`translate(${L7.left}px, ${L7.top}px)`,UZ.style.width=`${L7.width}px`,UZ.style.height=`${L7.height}px`})}}};return document.addEventListener("mousemove",F,{passive:!0}),()=>document.removeEventListener("mousemove",F)},[q4,$4,k5,P9]),m.useEffect(()=>{if(!q4)return;let F=(N)=>{let I=k5,w=W5.current;if(k5&&w){y5.current=!0;let v=Math.min(w.x,N.clientX),i=Math.min(w.y,N.clientY),V4=Math.max(w.x,N.clientX),P4=Math.max(w.y,N.clientY),g4=[],s4="button, a, input, img, p, h1, h2, h3, h4, h5, h6, li, label, td, th";document.querySelectorAll(s4).forEach((Z7)=>{if(!(Z7 instanceof HTMLElement))return;if(t2(Z7,"[data-feedback-toolbar]")||t2(Z7,"[data-annotation-marker]"))return;let k4=Z7.getBoundingClientRect();if(k4.width>window.innerWidth*0.8&&k4.height>window.innerHeight*0.5)return;if(k4.width<10||k4.height<10)return;if(k4.left<V4&&k4.right>v&&k4.top<P4&&k4.bottom>i)g4.push({element:Z7,rect:k4})});let r4=g4.filter(({element:Z7})=>!g4.some(({element:k4})=>k4!==Z7&&Z7.contains(k4))),$7=N.clientX/window.innerWidth*100,D7=N.clientY+window.scrollY;if(r4.length>0){let Z7=r4.reduce((HZ,{rect:Y7})=>({left:Math.min(HZ.left,Y7.left),top:Math.min(HZ.top,Y7.top),right:Math.max(HZ.right,Y7.right),bottom:Math.max(HZ.bottom,Y7.bottom)}),{left:1/0,top:1/0,right:-1/0,bottom:-1/0}),k4=r4.slice(0,5).map(({element:HZ})=>T0(HZ).name).join(", "),zZ=r4.length>5?` +${r4.length-5} more`:"",ZZ=r4[0].element,cZ=fz(ZZ),a7=mz(ZZ);C4({x:$7,y:D7,clientY:N.clientY,element:`${r4.length} elements: ${k4}${zZ}`,elementPath:"multi-select",boundingBox:{x:Z7.left,y:Z7.top+window.scrollY,width:Z7.right-Z7.left,height:Z7.bottom-Z7.top},isMultiSelect:!0,fullPath:uz(ZZ),accessibility:hz(ZZ),computedStyles:a7,computedStylesObj:cZ,nearbyElements:bz(ZZ),cssClasses:VB(ZZ),nearbyText:UB(ZZ),sourceFile:az(ZZ)})}else{let Z7=Math.abs(V4-v),k4=Math.abs(P4-i);if(Z7>20&&k4>20)C4({x:$7,y:D7,clientY:N.clientY,element:"Area selection",elementPath:`region at (${Math.round(v)}, ${Math.round(i)})`,boundingBox:{x:v,y:i+window.scrollY,width:Z7,height:k4},isMultiSelect:!0})}B4(null)}else if(I)y5.current=!0;if(i6.current=null,W5.current=null,c0(!1),I8.current)I8.current.innerHTML=""};return document.addEventListener("mouseup",F),()=>document.removeEventListener("mouseup",F)},[q4,k5]);let h2=m.useCallback(async(F,N,I)=>{let w=T7.webhookUrl||o;if(!w||!T7.webhooksEnabled&&!I)return!1;try{return(await fetch(w,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({event:F,timestamp:Date.now(),url:typeof window<"u"?window.location.href:void 0,...N})})).ok}catch(v){return console.warn("[Agentation] Webhook failed:",v),!1}},[o,T7.webhookUrl,T7.webhooksEnabled]),a0=m.useCallback((F)=>{if(!$4)return;let N={id:Date.now().toString(),x:$4.x,y:$4.y,comment:F,element:$4.element,elementPath:$4.elementPath,timestamp:Date.now(),selectedText:$4.selectedText,boundingBox:$4.boundingBox,nearbyText:$4.nearbyText,cssClasses:$4.cssClasses,isMultiSelect:$4.isMultiSelect,isFixed:$4.isFixed,fullPath:$4.fullPath,accessibility:$4.accessibility,computedStyles:$4.computedStyles,nearbyElements:$4.nearbyElements,reactComponents:$4.reactComponents,sourceFile:$4.sourceFile,elementBoundingBoxes:$4.elementBoundingBoxes,...b&&iZ?{sessionId:iZ,url:typeof window<"u"?window.location.href:void 0,status:"pending"}:{}};if(I4((I)=>[...I,N]),x2.current=N.id,q7(()=>{x2.current=null},300),q7(()=>{w8((I)=>new Set(I).add(N.id))},250),K?.(N),h2("annotation.add",{annotation:N}),OG(!0),q7(()=>{C4(null),OG(!1)},150),window.getSelection()?.removeAllRanges(),b&&iZ)P0(b,iZ,N).then((I)=>{if(I.id!==N.id)I4((w)=>w.map((v)=>v.id===N.id?{...v,id:I.id}:v)),w8((w)=>{let v=new Set(w);return v.delete(N.id),v.add(I.id),v})}).catch((I)=>{console.warn("[Agentation] Failed to sync annotation:",I)})},[$4,K,h2,b,iZ]),Z2=m.useCallback(()=>{OG(!0),q7(()=>{C4(null),OG(!1)},150)},[]),DG=m.useCallback((F)=>{let N=t.findIndex((w)=>w.id===F),I=t[N];if(N4?.id===F)v5(!0),q7(()=>{U4(null),z7(null),t4([]),v5(!1)},150);if(qZ(F),VG((w)=>new Set(w).add(F)),I)W?.(I),h2("annotation.delete",{annotation:I});if(b)U9(b,F).catch((w)=>{console.warn("[Agentation] Failed to delete annotation from server:",w)});q7(()=>{if(I4((w)=>w.filter((v)=>v.id!==F)),VG((w)=>{let v=new Set(w);return v.delete(F),v}),qZ(null),N<t.length-1)M2(N),q7(()=>M2(null),200)},150)},[t,N4,W,h2,b]),t6=m.useCallback((F)=>{if(!F){eZ(null),M4(null),uZ([]);return}if(eZ(F.id),F.elementBoundingBoxes?.length){let N=[];for(let I of F.elementBoundingBoxes){let w=I.x+I.width/2,v=I.y+I.height/2-window.scrollY,V4=document.elementsFromPoint(w,v).find((P4)=>!P4.closest("[data-annotation-marker]")&&!P4.closest("[data-agentation-root]"));if(V4)N.push(V4)}uZ(N),M4(null)}else if(F.boundingBox){let N=F.boundingBox,I=N.x+N.width/2,w=F.isFixed?N.y+N.height/2:N.y+N.height/2-window.scrollY,v=zG(I,w);if(v){let i=v.getBoundingClientRect(),V4=i.width/N.width,P4=i.height/N.height;if(V4<0.5||P4<0.5)M4(null);else M4(v)}else M4(null);uZ([])}else M4(null),uZ([])},[]),e6=m.useCallback((F)=>{if(!N4)return;let N={...N4,comment:F};if(I4((I)=>I.map((w)=>w.id===N4.id?N:w)),O?.(N),h2("annotation.update",{annotation:N}),b)i_(b,N4.id,{comment:F}).catch((I)=>{console.warn("[Agentation] Failed to update annotation on server:",I)});v5(!0),q7(()=>{U4(null),z7(null),t4([]),v5(!1)},150)},[N4,O,h2,b]),i0=m.useCallback(()=>{v5(!0),q7(()=>{U4(null),z7(null),t4([]),v5(!1)},150)},[]),_6=m.useCallback(()=>{let F=t.length,N=Q4.length>0||!!K7;if(F===0&&m2.length===0&&!N)return;if(A?.(t),h2("annotations.clear",{annotations:t}),b){Promise.all(t.map((v)=>U9(b,v.id).catch((i)=>{console.warn("[Agentation] Failed to delete annotation from server:",i)})));for(let[,v]of e5.current)if(v)U9(b,v).catch(()=>{});e5.current.clear();for(let[,v]of I5.current)if(v)U9(b,v).catch(()=>{});I5.current.clear()}u7(!0),EZ(!0),v0([]);let I=KG.current;if(I){let v=I.getContext("2d");if(v)v.clearRect(0,0,I.width,I.height)}if(Q4.length>0||K7)YG((v)=>v+1),p6((v)=>v+1),q7(()=>{M7([]),b2(null)},200);if(X7)e7(!1);if(wZ)G5("");K6.current={rearrange:null,placements:[]},cz(B7);let w=F*30+200;q7(()=>{I4([]),w8(new Set),localStorage.removeItem(rz(B7)),u7(!1)},w),q7(()=>EZ(!1),1500)},[B7,t,m2,Q4,K7,X7,wZ,A,h2,b]),PG=m.useCallback(async()=>{let F=typeof window<"u"?window.location.pathname+window.location.search+window.location.hash:B7,N=e&&X7,I;if(N){if(Q4.length===0&&!K7&&!wZ)return;I=""}else{if(I=n_(t,F,T7.outputDetail),!I&&m2.length===0&&Q4.length===0&&!K7)return;if(!I)I=`## Page Feedback: ${F}
`}if(!N&&m2.length>0){let w=new Set;for(let P4 of t)if(P4.drawingIndex!=null)w.add(P4.drawingIndex);let v=KG.current;if(v)v.style.visibility="hidden";let i=[],V4=window.scrollY;for(let P4=0;P4<m2.length;P4++){if(w.has(P4))continue;let g4=m2[P4];if(g4.points.length<2)continue;let s4=g4.fixed?g4.points:g4.points.map((YZ)=>({x:YZ.x,y:YZ.y-V4})),r4=1/0,$7=1/0,D7=-1/0,Z7=-1/0;for(let YZ of s4)r4=Math.min(r4,YZ.x),$7=Math.min($7,YZ.y),D7=Math.max(D7,YZ.x),Z7=Math.max(Z7,YZ.y);let k4=D7-r4,zZ=Z7-$7,ZZ=Math.hypot(k4,zZ),cZ=s4[0],a7=s4[s4.length-1],HZ=Math.hypot(a7.x-cZ.x,a7.y-cZ.y),Y7,L7=HZ<ZZ*0.35,LZ=k4/Math.max(zZ,1);if(L7&&ZZ>20){let YZ=Math.max(k4,zZ)*0.15,r7=0;for(let f5 of s4){let yB=f5.x-r4<YZ,o0=D7-f5.x<YZ,B8=f5.y-$7<YZ,T9=Z7-f5.y<YZ;if((yB||o0)&&(B8||T9))r7++}Y7=r7>s4.length*0.15?"box":"circle"}else if(LZ>3&&zZ<40)Y7="underline";else if(HZ>ZZ*0.5)Y7="arrow";else Y7="drawing";let UZ=Math.min(10,s4.length),G2=Math.max(1,Math.floor(s4.length/UZ)),lZ=new Set,oZ=[],G8=[cZ];for(let YZ=G2;YZ<s4.length-1;YZ+=G2)G8.push(s4[YZ]);G8.push(a7);for(let YZ of G8){let r7=zG(YZ.x,YZ.y);if(!r7||lZ.has(r7))continue;if(t2(r7,"[data-feedback-toolbar]"))continue;lZ.add(r7);let{name:f5}=T0(r7);if(!oZ.includes(f5))oZ.push(f5)}let $5=`${Math.round(r4)},${Math.round($7)} → ${Math.round(D7)},${Math.round(Z7)}`,_5;if((Y7==="circle"||Y7==="box")&&oZ.length>0)_5=`${Y7==="box"?"Boxed":"Circled"} **${oZ[0]}**${oZ.length>1?` (and ${oZ.slice(1).join(", ")})`:""} (region: ${$5})`;else if(Y7==="underline"&&oZ.length>0)_5=`Underlined **${oZ[0]}** (${$5})`;else if(Y7==="arrow"&&oZ.length>=2)_5=`Arrow from **${oZ[0]}** to **${oZ[oZ.length-1]}** (${Math.round(cZ.x)},${Math.round(cZ.y)} → ${Math.round(a7.x)},${Math.round(a7.y)})`;else if(oZ.length>0)_5=`${Y7==="arrow"?"Arrow":"Drawing"} near **${oZ.join("**, **")}** (region: ${$5})`;else _5=`Drawing at ${$5}`;i.push(_5)}if(v)v.style.visibility="";if(i.length>0)I+=`
**Drawings:**
`,i.forEach((P4,g4)=>{I+=`${g4+1}. ${P4}
`})}if(Q4.length>0||N&&wZ)I+=`
`+c_(Q4,{width:window.innerWidth,height:window.innerHeight},{blankCanvas:X7,wireframePurpose:wZ||void 0},T7.outputDetail);if(K7){let w=l_(K7,T7.outputDetail,{width:window.innerWidth,height:window.innerHeight});if(w)I+=`
`+w}if(J4)try{await navigator.clipboard.writeText(I)}catch{}if(C?.(I),s(!0),q7(()=>s(!1),2000),T7.autoClearAfterCopy)q7(()=>_6(),500)},[t,m2,Q4,K7,X7,e,t5,wZ,B7,T7.outputDetail,pZ,T7.autoClearAfterCopy,_6,J4,C]),AG=m.useCallback(async()=>{let F=typeof window<"u"?window.location.pathname+window.location.search+window.location.hash:B7,N=n_(t,F,T7.outputDetail);if(!N&&Q4.length===0&&!K7)return;if(!N)N=`## Page Feedback: ${F}
`;if(Q4.length>0)N+=`
`+c_(Q4,{width:window.innerWidth,height:window.innerHeight},{blankCanvas:X7,wireframePurpose:wZ||void 0},T7.outputDetail);if(K7){let w=l_(K7,T7.outputDetail,{width:window.innerWidth,height:window.innerHeight});if(w)N+=`
`+w}if(x)x(N,t);Q7("sending"),await new Promise((w)=>q7(w,150));let I=await h2("submit",{output:N,annotations:t},!0);if(Q7(I?"sent":"failed"),q7(()=>Q7("idle"),2500),I&&T7.autoClearAfterCopy)q7(()=>_6(),500)},[x,h2,t,Q4,K7,X7,t5,B7,T7.outputDetail,pZ,T7.autoClearAfterCopy,_6]);m.useEffect(()=>{if(!E8)return;let F=10,N=(w)=>{let v=w.clientX-E8.x,i=w.clientY-E8.y,V4=Math.sqrt(v*v+i*i);if(!a6&&V4>F)d0(!0);if(a6||V4>F){let P4=E8.toolbarX+v,g4=E8.toolbarY+i,s4=20,r4=337,$7=44,Z7=r4-(q4?B5==="connected"?297:257:44),k4=s4-Z7,zZ=window.innerWidth-s4-r4;P4=Math.max(k4,Math.min(zZ,P4)),g4=Math.max(s4,Math.min(window.innerHeight-$7-s4,g4)),LG({x:P4,y:g4})}},I=()=>{if(a6)UG.current=!0;d0(!1),N9(null)};return document.addEventListener("mousemove",N),document.addEventListener("mouseup",I),()=>{document.removeEventListener("mousemove",N),document.removeEventListener("mouseup",I)}},[E8,a6,q4,B5]);let GQ=m.useCallback((F)=>{if(F.target.closest("button")||F.target.closest("[data-agentation-settings-panel]"))return;let N=F.currentTarget.parentElement;if(!N)return;let I=N.getBoundingClientRect(),w=CZ?.x??I.left,v=CZ?.y??I.top;N9({x:F.clientX,y:F.clientY,toolbarX:w,toolbarY:v})},[CZ]);if(m.useEffect(()=>{if(!CZ)return;let F=()=>{let{x:v,y:i}=CZ,g4=20-(337-(q4?B5==="connected"?297:257:44)),s4=window.innerWidth-20-337;if(v=Math.max(g4,Math.min(s4,v)),i=Math.max(20,Math.min(window.innerHeight-44-20,i)),v!==CZ.x||i!==CZ.y)LG({x:v,y:i})};return F(),window.addEventListener("resize",F),()=>window.removeEventListener("resize",F)},[CZ,q4,B5]),m.useEffect(()=>{let F=(N)=>{let I=N.target,w=I.tagName==="INPUT"||I.tagName==="TEXTAREA"||I.isContentEditable;if(N.key==="Escape"){if(e){if(U7)H7(null);else A9();return}if(j5){S0(!1);return}if(gZ.length>0){C8([]);return}if($4);else if(q4)L2(),h(!1)}if((N.metaKey||N.ctrlKey)&&N.shiftKey&&(N.key==="f"||N.key==="F")){if(N.preventDefault(),L2(),q4)vB();else h(!0);return}if(w||N.metaKey||N.ctrlKey)return;if(N.key==="p"||N.key==="P")N.preventDefault(),L2(),NG();if(N.key==="l"||N.key==="L"){if(N.preventDefault(),L2(),j5)S0(!1);if(z4)S4(!1);if($4)Z2();if(e)A9();else x4(!0)}if(N.key==="h"||N.key==="H"){if(t.length>0)N.preventDefault(),L2(),i4((v)=>!v)}if(N.key==="c"||N.key==="C"){if(t.length>0||Q4.length>0||K7)N.preventDefault(),L2(),PG()}if(N.key==="x"||N.key==="X"){if(t.length>0||Q4.length>0||K7){if(N.preventDefault(),L2(),_6(),Q4.length>0)M7([]);if(K7)b2(null)}}if(N.key==="s"||N.key==="S"){let v=u6(T7.webhookUrl)||u6(o||"");if(t.length>0&&v&&c4==="idle")N.preventDefault(),L2(),AG()}};return document.addEventListener("keydown",F),()=>document.removeEventListener("keydown",F)},[q4,j5,e,U7,Q4,K7,$4,t.length,T7.webhookUrl,o,c4,AG,NG,PG,_6,gZ]),!o4)return null;if(g7)return null;let Z8=t.length>0,k2=t.filter((F)=>!xB.has(F.id)&&F.kind!=="placement"&&F.kind!=="rearrange"),kB=k2.length>0,CG=t.filter((F)=>xB.has(F.id)),C9=(F)=>{let i=F.x/100*window.innerWidth,V4=typeof F.y==="string"?parseFloat(F.y):F.y,P4={};if(window.innerHeight-V4-22-10<80)P4.top="auto",P4.bottom="calc(100% + 10px)";let s4=i-100,r4=10;if(s4<r4){let $7=r4-s4;P4.left=`calc(50% + ${$7}px)`}else if(s4+200>window.innerWidth-r4){let $7=s4+200-(window.innerWidth-r4);P4.left=`calc(50% - ${$7}px)`}return P4};return $3.createPortal(W4.jsxs("div",{ref:N7,style:{display:"contents"},"data-agentation-theme":K5?"dark":"light","data-agentation-accent":T7.annotationColorId,"data-agentation-root":"",children:[W4.jsx("div",{className:`${K4.toolbar}${p?` ${p}`:""}`,"data-feedback-toolbar":!0,"data-agentation-toolbar":!0,style:CZ?{left:CZ.x,top:CZ.y,right:"auto",bottom:"auto"}:void 0,children:W4.jsxs("div",{className:`${K4.toolbarContainer} ${q4?K4.expanded:K4.collapsed} ${m0?K4.entrance:""} ${T4?K4.hiding:""} ${!T7.webhooksEnabled&&(u6(T7.webhookUrl)||u6(o||""))?K4.serverConnected:""}`,onClick:!q4?(F)=>{if(UG.current){UG.current=!1,F.preventDefault();return}h(!0)}:void 0,onMouseDown:GQ,role:!q4?"button":void 0,tabIndex:!q4?0:-1,title:!q4?"Start feedback mode":void 0,children:[W4.jsxs("div",{className:`${K4.toggleContent} ${!q4?K4.visible:K4.hidden}`,children:[W4.jsx(sV,{size:24}),kB&&W4.jsx("span",{className:`${K4.badge} ${q4?K4.fadeOut:""} ${m0?K4.entrance:""}`,children:k2.length})]}),W4.jsxs("div",{className:`${K4.controlsContent} ${q4?K4.visible:K4.hidden} ${CZ&&CZ.y<100?K4.tooltipBelow:""} ${a||z4?K4.tooltipsHidden:""} ${b0?K4.tooltipsInSession:""}`,onMouseEnter:F9,onMouseLeave:Z6,children:[W4.jsxs("div",{className:`${K4.buttonWrapper} ${CZ&&CZ.x<120?K4.buttonWrapperAlignLeft:""}`,children:[W4.jsx("button",{className:K4.controlButton,onClick:(F)=>{F.stopPropagation(),L2(),NG()},"data-active":u,children:W4.jsx(nV,{size:24,isPaused:u})}),W4.jsxs("span",{className:K4.buttonTooltip,children:[u?"Resume animations":"Pause animations",W4.jsx("span",{className:K4.shortcut,children:"P"})]})]}),W4.jsxs("div",{className:K4.buttonWrapper,children:[W4.jsx("button",{className:`${K4.controlButton} ${!K5?K4.light:""}`,onClick:(F)=>{if(F.stopPropagation(),L2(),j5)S0(!1);if(z4)S4(!1);if($4)Z2();if(e)A9();else x4(!0)},"data-active":e,style:e&&X7?{color:"#f97316",background:"rgba(249, 115, 22, 0.25)"}:void 0,children:W4.jsx(JO,{size:21})}),W4.jsxs("span",{className:K4.buttonTooltip,children:[e?"Exit layout mode":"Layout mode",W4.jsx("span",{className:K4.shortcut,children:"L"})]})]}),W4.jsxs("div",{className:K4.buttonWrapper,children:[W4.jsx("button",{className:K4.controlButton,onClick:(F)=>{F.stopPropagation(),L2(),i4(!u4)},disabled:!Z8||e,children:W4.jsx(rV,{size:24,isOpen:u4})}),W4.jsxs("span",{className:K4.buttonTooltip,children:[u4?"Hide markers":"Show markers",W4.jsx("span",{className:K4.shortcut,children:"H"})]})]}),W4.jsxs("div",{className:K4.buttonWrapper,children:[W4.jsx("button",{className:`${K4.controlButton} ${R7?K4.statusShowing:""}`,onClick:(F)=>{F.stopPropagation(),L2(),PG()},disabled:e&&X7?Q4.length===0&&!K7?.sections?.length:!Z8&&m2.length===0&&Q4.length===0&&!K7?.sections?.length,"data-active":R7,children:W4.jsx(iV,{size:24,copied:R7,tint:e&&X7&&(Q4.length>0||!!K7?.sections?.length)?"#f97316":void 0})}),W4.jsxs("span",{className:K4.buttonTooltip,children:[e&&X7?"Copy layout":"Copy feedback",W4.jsx("span",{className:K4.shortcut,children:"C"})]})]}),W4.jsxs("div",{className:`${K4.buttonWrapper} ${K4.sendButtonWrapper} ${q4&&!T7.webhooksEnabled&&(u6(T7.webhookUrl)||u6(o||""))?K4.sendButtonVisible:""}`,children:[W4.jsxs("button",{className:`${K4.controlButton} ${c4==="sent"||c4==="failed"?K4.statusShowing:""}`,onClick:(F)=>{F.stopPropagation(),L2(),AG()},disabled:!Z8||!u6(T7.webhookUrl)&&!u6(o||"")||c4==="sending","data-no-hover":c4==="sent"||c4==="failed",tabIndex:u6(T7.webhookUrl)||u6(o||"")?0:-1,children:[W4.jsx(oV,{size:24,state:c4}),Z8&&c4==="idle"&&W4.jsx("span",{className:K4.buttonBadge,children:t.length})]}),W4.jsxs("span",{className:K4.buttonTooltip,children:["Send Annotations",W4.jsx("span",{className:K4.shortcut,children:"S"})]})]}),W4.jsxs("div",{className:K4.buttonWrapper,children:[W4.jsx("button",{className:K4.controlButton,onClick:(F)=>{F.stopPropagation(),L2(),_6()},disabled:!Z8&&m2.length===0&&Q4.length===0&&!K7?.sections?.length,"data-danger":!0,children:W4.jsx(eV,{size:24})}),W4.jsxs("span",{className:K4.buttonTooltip,children:["Clear all",W4.jsx("span",{className:K4.shortcut,children:"X"})]})]}),W4.jsxs("div",{className:K4.buttonWrapper,children:[W4.jsx("button",{className:K4.controlButton,onClick:(F)=>{if(F.stopPropagation(),L2(),e)A9();S4(!z4)},children:W4.jsx(tV,{size:24})}),b&&B5!=="disconnected"&&W4.jsx("span",{className:`${K4.mcpIndicator} ${K4[B5]} ${z4?K4.hidden:""}`,title:B5==="connected"?"MCP Connected":"MCP Connecting..."}),W4.jsx("span",{className:K4.buttonTooltip,children:"Settings"})]}),W4.jsx("div",{className:K4.divider}),W4.jsxs("div",{className:`${K4.buttonWrapper} ${CZ&&typeof window<"u"&&CZ.x>window.innerWidth-120?K4.buttonWrapperAlignRight:""}`,children:[W4.jsx("button",{className:K4.controlButton,onClick:(F)=>{F.stopPropagation(),L2(),vB()},children:W4.jsx(ZO,{size:24})}),W4.jsxs("span",{className:K4.buttonTooltip,children:["Exit",W4.jsx("span",{className:K4.shortcut,children:"Esc"})]})]})]}),W4.jsx(yF,{visible:e&&q4,activeType:U7,onSelect:(F)=>{H7(U7===F?null:F)},isDarkMode:K5,sectionCount:K7?.sections.length??0,onDetectSections:()=>{let F=sF(),N=K7?.sections??[],I=new Set(N.map((V4)=>V4.selector)),w=F.filter((V4)=>!I.has(V4.selector)),v=[...N,...w],i=[...K7?.originalOrder??[],...w.map((V4)=>V4.id)];b2({sections:v,originalOrder:i,detectedAt:Date.now()})},placementCount:Q4.length,onClearPlacements:()=>{YG((F)=>F+1),p6((F)=>F+1),q7(()=>{b2({sections:[],originalOrder:[],detectedAt:Date.now()})},200)},blankCanvas:X7,onBlankCanvasChange:(F)=>{let N={sections:[],originalOrder:[],detectedAt:Date.now()};if(F)XG.current={rearrange:K7,placements:Q4},b2(K6.current.rearrange||N),M7(K6.current.placements),H7(null);else K6.current={rearrange:K7,placements:Q4},b2(XG.current.rearrange||N),M7(XG.current.placements);e7(F)},wireframePurpose:wZ,onWireframePurposeChange:G5,Tooltip:JG,onDragStart:(F,N)=>{N.preventDefault();let I=f4[F],w=null,v=!1,i=N.clientX,V4=N.clientY,g4=N.target.closest("[data-feedback-toolbar]")?.getBoundingClientRect().top??window.innerHeight,s4=($7)=>{let D7=$7.clientX-i,Z7=$7.clientY-V4;if(!v&&(Math.abs(D7)>4||Math.abs(Z7)>4))v=!0,w=document.createElement("div"),w.className=`${Z4.dragPreview}${X7?` ${Z4.dragPreviewWireframe}`:""}`,document.body.appendChild(w);if(!w)return;let k4=Math.max(0,g4-$7.clientY),zZ=Math.min(1,k4/180),ZZ=1-Math.pow(1-zZ,2),cZ=28,a7=20,HZ=Math.min(140,I.width*0.18),Y7=Math.min(90,I.height*0.18),L7=cZ+(HZ-cZ)*ZZ,LZ=a7+(Y7-a7)*ZZ;w.style.width=`${L7}px`,w.style.height=`${LZ}px`,w.style.left=`${$7.clientX-L7/2}px`,w.style.top=`${$7.clientY-LZ/2}px`,w.style.opacity=`${0.5+0.5*ZZ}`,w.textContent=ZZ>0.25?F:""},r4=($7)=>{if(window.removeEventListener("mousemove",s4),window.removeEventListener("mouseup",r4),w)document.body.removeChild(w);if(v){let{width:D7,height:Z7}=I,k4=window.scrollY,zZ=Math.max(0,$7.clientX-D7/2),ZZ=Math.max(0,$7.clientY+k4-Z7/2),cZ={id:`dp-${Date.now()}-${Math.random().toString(36).slice(2,7)}`,type:F,x:zZ,y:ZZ,width:D7,height:Z7,scrollY:k4,timestamp:Date.now()};M7((a7)=>[...a7,cZ]),H7(null),Y5.current=new Set,x0((a7)=>a7+1)}};window.addEventListener("mousemove",s4),window.addEventListener("mouseup",r4)}}),W4.jsx(GM,{settings:T7,onSettingsChange:(F)=>IB((N)=>({...N,...F})),isDarkMode:K5,onToggleTheme:_G,isDevMode:h0,connectionStatus:B5,endpoint:b,isVisible:m4,toolbarNearBottom:!!CZ&&CZ.y<230,settingsPage:_,onSettingsPageChange:E,onHideToolbar:b5})]})}),(e||F4)&&W4.jsx("div",{className:`${Z4.blankCanvas} ${kZ?Z4.visible:""} ${D2?Z4.gridActive:""}`,style:{"--canvas-opacity":yZ},"data-feedback-toolbar":!0}),e&&X7&&kZ&&W4.jsxs("div",{className:Z4.wireframeNotice,"data-feedback-toolbar":!0,children:[W4.jsxs("div",{className:Z4.wireframeOpacityRow,children:[W4.jsx("span",{className:Z4.wireframeOpacityLabel,children:"Toggle Opacity"}),W4.jsx("input",{type:"range",className:Z4.wireframeOpacitySlider,min:0,max:1,step:0.01,value:yZ,onChange:(F)=>N2(Number(F.target.value))})]}),W4.jsxs("div",{className:Z4.wireframeNoticeTitleRow,children:[W4.jsx("span",{className:Z4.wireframeNoticeTitle,children:"Wireframe Mode"}),W4.jsx("span",{className:Z4.wireframeNoticeDivider}),W4.jsx("button",{className:Z4.wireframeStartOver,onClick:()=>{YG((F)=>F+1),b2({sections:[],originalOrder:[],detectedAt:Date.now()}),K6.current={rearrange:null,placements:[]},G5(""),cz(B7)},children:"Start Over"})]}),"Drag components onto the canvas.",W4.jsx("br",{}),"Copied output will only include the wireframed layout."]}),(e||F4)&&W4.jsx(IF,{placements:Q4,onChange:M7,activeComponent:F4?null:U7,onActiveComponentChange:H7,isDarkMode:K5,exiting:F4,onInteractionChange:AB,passthrough:!U7,extraSnapRects:K7?.sections.map((F)=>F.currentRect),deselectSignal:A8,clearSignal:EB,wireframe:X7,onSelectionChange:(F,N)=>{if(Y5.current=F,!N)O9.current=new Set,TB((I)=>I+1)},onDragMove:(F,N)=>{let I=O9.current;if(!I.size||!K7)return;if(!P2.current){P2.current=new Map;for(let w of K7.sections)if(I.has(w.id))P2.current.set(w.id,{x:w.currentRect.x,y:w.currentRect.y})}for(let w of K7.sections){if(!I.has(w.id))continue;if(!P2.current.get(w.id))continue;let i=document.querySelector(`[data-rearrange-section="${w.id}"]`);if(i)i.style.transform=`translate(${F}px, ${N}px)`}},onDragEnd:(F,N,I)=>{let w=O9.current,v=P2.current;if(P2.current=null,!w.size||!K7||!v)return;for(let i of w){let V4=document.querySelector(`[data-rearrange-section="${i}"]`);if(V4)V4.style.transform=""}if(I)b2((i)=>{if(!i)return i;return{...i,sections:i.sections.map((V4)=>{let P4=v.get(V4.id);if(!P4)return V4;return{...V4,currentRect:{...V4.currentRect,x:Math.max(0,P4.x+F),y:Math.max(0,P4.y+N)}}})}})}}),(e||F4)&&K7&&W4.jsx(oF,{rearrangeState:K7,onChange:b2,isDarkMode:K5,exiting:F4,blankCanvas:X7,extraSnapRects:Q4.map((F)=>({x:F.x,y:F.y,width:F.width,height:F.height})),clearSignal:f2,deselectSignal:CB,onSelectionChange:(F,N)=>{if(O9.current=F,!N)Y5.current=new Set,x0((I)=>I+1)},onDragMove:(F,N)=>{let I=Y5.current;if(!I.size)return;if(!P2.current){P2.current=new Map;for(let w of Q4)if(I.has(w.id))P2.current.set(w.id,{x:w.x,y:w.y})}for(let w of I){let v=document.querySelector(`[data-design-placement="${w}"]`);if(v)v.style.transform=`translate(${F}px, ${N}px)`}},onDragEnd:(F,N,I)=>{let w=Y5.current,v=P2.current;if(P2.current=null,!w.size||!v)return;for(let i of w){let V4=document.querySelector(`[data-design-placement="${i}"]`);if(V4)V4.style.transform=""}if(I)M7((i)=>i.map((V4)=>{let P4=v.get(V4.id);if(!P4)return V4;return{...V4,x:Math.max(0,P4.x+F),y:Math.max(0,P4.y+N)}}))}}),W4.jsx("canvas",{ref:KG,className:`${K4.drawCanvas} ${j5?K4.active:""}`,style:{opacity:x8?1:0,transition:"opacity 0.15s ease"},"data-feedback-toolbar":!0}),W4.jsxs("div",{className:K4.markersLayer,"data-feedback-toolbar":!0,children:[Y4&&k2.filter((F)=>!F.isFixed).map((F,N,I)=>W4.jsx(t_,{annotation:F,globalIndex:k2.findIndex((w)=>w.id===F.id),layerIndex:N,layerSize:I.length,isExiting:d4,isClearing:I2,isAnimated:p0.has(F.id),isHovered:!d4&&AZ===F.id,isDeleting:Y2===F.id,isEditingAny:!!N4,renumberFrom:s7,markerClickBehavior:T7.markerClickBehavior,tooltipStyle:C9(F),onHoverEnter:(w)=>!d4&&w.id!==x2.current&&t6(w),onHoverLeave:()=>t6(null),onClick:(w)=>T7.markerClickBehavior==="delete"?DG(w.id):n6(w),onContextMenu:n6},F.id)),Y4&&!d4&&CG.filter((F)=>!F.isFixed).map((F)=>W4.jsx(e_,{annotation:F},F.id))]}),W4.jsxs("div",{className:K4.fixedMarkersLayer,"data-feedback-toolbar":!0,children:[Y4&&k2.filter((F)=>F.isFixed).map((F,N,I)=>W4.jsx(t_,{annotation:F,globalIndex:k2.findIndex((w)=>w.id===F.id),layerIndex:N,layerSize:I.length,isExiting:d4,isClearing:I2,isAnimated:p0.has(F.id),isHovered:!d4&&AZ===F.id,isDeleting:Y2===F.id,isEditingAny:!!N4,renumberFrom:s7,markerClickBehavior:T7.markerClickBehavior,tooltipStyle:C9(F),onHoverEnter:(w)=>!d4&&w.id!==x2.current&&t6(w),onHoverLeave:()=>t6(null),onClick:(w)=>T7.markerClickBehavior==="delete"?DG(w.id):n6(w),onContextMenu:n6},F.id)),Y4&&!d4&&CG.filter((F)=>F.isFixed).map((F)=>W4.jsx(e_,{annotation:F,fixed:!0},F.id))]}),q4&&W4.jsxs("div",{className:K4.overlay,"data-feedback-toolbar":!0,style:$4||N4?{zIndex:99999}:void 0,children:[n4?.rect&&!$4&&!S7&&!k5&&W4.jsx("div",{className:`${K4.hoverHighlight} ${K4.enter}`,style:{left:n4.rect.left,top:n4.rect.top,width:n4.rect.width,height:n4.rect.height,borderColor:"color-mix(in srgb, var(--agentation-color-accent) 50%, transparent)",backgroundColor:"color-mix(in srgb, var(--agentation-color-accent) 4%, transparent)"}}),gZ.filter((F)=>document.contains(F.element)).map((F,N)=>{let I=F.element.getBoundingClientRect(),w=gZ.length>1;return W4.jsx("div",{className:w?K4.multiSelectOutline:K4.singleSelectOutline,style:{position:"fixed",left:I.left,top:I.top,width:I.width,height:I.height,...w?{}:{borderColor:"color-mix(in srgb, var(--agentation-color-accent) 60%, transparent)",backgroundColor:"color-mix(in srgb, var(--agentation-color-accent) 5%, transparent)"}}},N)}),AZ&&!$4&&(()=>{let F=t.find((v)=>v.id===AZ);if(!F?.boundingBox)return null;if(F.elementBoundingBoxes?.length){if(_2.length>0)return _2.filter((v)=>document.contains(v)).map((v,i)=>{let V4=v.getBoundingClientRect();return W4.jsx("div",{className:`${K4.multiSelectOutline} ${K4.enter}`,style:{left:V4.left,top:V4.top,width:V4.width,height:V4.height}},`hover-outline-live-${i}`)});return F.elementBoundingBoxes.map((v,i)=>W4.jsx("div",{className:`${K4.multiSelectOutline} ${K4.enter}`,style:{left:v.x,top:v.y-b7,width:v.width,height:v.height}},`hover-outline-${i}`))}let N=Z5&&document.contains(Z5)?Z5.getBoundingClientRect():null,I=N?{x:N.left,y:N.top,width:N.width,height:N.height}:{x:F.boundingBox.x,y:F.isFixed?F.boundingBox.y:F.boundingBox.y-b7,width:F.boundingBox.width,height:F.boundingBox.height},w=F.isMultiSelect;return W4.jsx("div",{className:`${w?K4.multiSelectOutline:K4.singleSelectOutline} ${K4.enter}`,style:{left:I.x,top:I.y,width:I.width,height:I.height,...w?{}:{borderColor:"color-mix(in srgb, var(--agentation-color-accent) 60%, transparent)",backgroundColor:"color-mix(in srgb, var(--agentation-color-accent) 5%, transparent)"}}})})(),n4&&!$4&&!S7&&!k5&&W4.jsxs("div",{className:`${K4.hoverTooltip} ${K4.enter}`,style:{left:Math.max(8,Math.min(L4.x,window.innerWidth-100)),top:Math.max(L4.y-(n4.reactComponents?48:32),8)},children:[n4.reactComponents&&W4.jsx("div",{className:K4.hoverReactPath,children:n4.reactComponents}),W4.jsx("div",{className:K4.hoverElementName,children:n4.elementName})]}),$4&&W4.jsxs(W4.Fragment,{children:[$4.multiSelectElements?.length?$4.multiSelectElements.filter((F)=>document.contains(F)).map((F,N)=>{let I=F.getBoundingClientRect();return W4.jsx("div",{className:`${K4.multiSelectOutline} ${D9?K4.exit:K4.enter}`,style:{left:I.left,top:I.top,width:I.width,height:I.height}},`pending-multi-${N}`)}):$4.targetElement&&document.contains($4.targetElement)?(()=>{let F=$4.targetElement.getBoundingClientRect();return W4.jsx("div",{className:`${K4.singleSelectOutline} ${D9?K4.exit:K4.enter}`,style:{left:F.left,top:F.top,width:F.width,height:F.height,borderColor:"color-mix(in srgb, var(--agentation-color-accent) 60%, transparent)",backgroundColor:"color-mix(in srgb, var(--agentation-color-accent) 5%, transparent)"}})})():$4.boundingBox&&W4.jsx("div",{className:`${$4.isMultiSelect?K4.multiSelectOutline:K4.singleSelectOutline} ${D9?K4.exit:K4.enter}`,style:{left:$4.boundingBox.x,top:$4.boundingBox.y-b7,width:$4.boundingBox.width,height:$4.boundingBox.height,...$4.isMultiSelect?{}:{borderColor:"color-mix(in srgb, var(--agentation-color-accent) 60%, transparent)",backgroundColor:"color-mix(in srgb, var(--agentation-color-accent) 5%, transparent)"}}}),(()=>{let F=$4.x,N=$4.isFixed?$4.y:$4.y-b7;return W4.jsxs(W4.Fragment,{children:[W4.jsx(lR,{x:F,y:N,isMultiSelect:$4.isMultiSelect,isExiting:D9}),W4.jsx(iz,{ref:l0,element:$4.element,selectedText:$4.selectedText,computedStyles:$4.computedStylesObj,placeholder:$4.element==="Area selection"?"What should change in this area?":$4.isMultiSelect?"Feedback for this group of elements...":"What should change?",onSubmit:a0,onCancel:Z2,isExiting:D9,lightMode:!K5,accentColor:$4.isMultiSelect?"var(--agentation-color-green)":"var(--agentation-color-accent)",style:{left:Math.max(160,Math.min(window.innerWidth-160,F/100*window.innerWidth)),...N>window.innerHeight-290?{bottom:window.innerHeight-N+20}:{top:N+20}}})]})})()]}),N4&&W4.jsxs(W4.Fragment,{children:[N4.elementBoundingBoxes?.length?(()=>{if(J7.length>0)return J7.filter((F)=>document.contains(F)).map((F,N)=>{let I=F.getBoundingClientRect();return W4.jsx("div",{className:`${K4.multiSelectOutline} ${K4.enter}`,style:{left:I.left,top:I.top,width:I.width,height:I.height}},`edit-multi-live-${N}`)});return N4.elementBoundingBoxes.map((F,N)=>W4.jsx("div",{className:`${K4.multiSelectOutline} ${K4.enter}`,style:{left:F.x,top:F.y-b7,width:F.width,height:F.height}},`edit-multi-${N}`))})():(()=>{let F=D4&&document.contains(D4)?D4.getBoundingClientRect():null,N=F?{x:F.left,y:F.top,width:F.width,height:F.height}:N4.boundingBox?{x:N4.boundingBox.x,y:N4.isFixed?N4.boundingBox.y:N4.boundingBox.y-b7,width:N4.boundingBox.width,height:N4.boundingBox.height}:null;if(!N)return null;return W4.jsx("div",{className:`${N4.isMultiSelect?K4.multiSelectOutline:K4.singleSelectOutline} ${K4.enter}`,style:{left:N.x,top:N.y,width:N.width,height:N.height,...N4.isMultiSelect?{}:{borderColor:"color-mix(in srgb, var(--agentation-color-accent) 60%, transparent)",backgroundColor:"color-mix(in srgb, var(--agentation-color-accent) 5%, transparent)"}}})})(),W4.jsx(iz,{ref:S2,element:N4.element,selectedText:N4.selectedText,computedStyles:dF(N4.computedStyles),placeholder:"Edit your feedback...",initialValue:N4.comment,submitLabel:"Save",onSubmit:e6,onCancel:i0,onDelete:()=>DG(N4.id),isExiting:ZQ,lightMode:!K5,accentColor:N4.isMultiSelect?"var(--agentation-color-green)":"var(--agentation-color-accent)",style:(()=>{let F=N4.isFixed?N4.y:N4.y-b7;return{left:Math.max(160,Math.min(window.innerWidth-160,N4.x/100*window.innerWidth)),...F>window.innerHeight-290?{bottom:window.innerHeight-F+20}:{top:F+20}}})()})]}),k5&&W4.jsxs(W4.Fragment,{children:[W4.jsx("div",{ref:o6,className:K4.dragSelection}),W4.jsx("div",{ref:I8,className:K4.highlightsContainer})]})]})]}),document.body)}function D3(){let J=document.createElement("div");J.id="agentation-root",document.body.appendChild(J),A3.createRoot(J).render(P3.createElement(N3,{endpoint:"http://localhost:4747"}))}if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",D3);else D3();})();
