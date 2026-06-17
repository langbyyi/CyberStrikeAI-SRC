package burp;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.security.cert.X509Certificate;

/**
 * Opens HTTPS connections without validating server certificates (self-signed / local dev).
 * Applied per-connection only; does not change JVM-wide defaults for other Burp components.
 */
final class SslTrustAll {

    private static volatile SSLSocketFactory socketFactory;
    private static final HostnameVerifier TRUST_ALL_HOSTS = (hostname, session) -> true;

    private SslTrustAll() {
    }

    static HttpURLConnection open(URL url) throws IOException {
        return open(url, 5_000, 30_000);
    }

    static HttpURLConnection open(URL url, int connectTimeoutMs, int readTimeoutMs) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            https.setSSLSocketFactory(new TimeoutSslSocketFactory(socketFactory(), connectTimeoutMs, readTimeoutMs));
            https.setHostnameVerifier(TRUST_ALL_HOSTS);
        }
        return conn;
    }

    private static SSLSocketFactory socketFactory() {
        SSLSocketFactory sf = socketFactory;
        if (sf != null) {
            return sf;
        }
        synchronized (SslTrustAll.class) {
            sf = socketFactory;
            if (sf != null) {
                return sf;
            }
            try {
                TrustManager[] trustAll = new TrustManager[]{
                        new X509TrustManager() {
                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0];
                            }

                            @Override
                            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                            }

                            @Override
                            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                            }
                        }
                };
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, trustAll, new java.security.SecureRandom());
                sf = ctx.getSocketFactory();
                socketFactory = sf;
                return sf;
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize trust-all TLS", e);
            }
        }
    }

    /** Ensures TCP connect + socket read respect timeouts (plain HttpURLConnection SSL can hang longer). */
    private static final class TimeoutSslSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final int connectTimeoutMs;
        private final int readTimeoutMs;

        TimeoutSslSocketFactory(SSLSocketFactory delegate, int connectTimeoutMs, int readTimeoutMs) {
            this.delegate = delegate;
            this.connectTimeoutMs = connectTimeoutMs;
            this.readTimeoutMs = readTimeoutMs;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket() throws IOException {
            return tune(delegate.createSocket());
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            return tune(delegate.createSocket(s, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            Socket plain = new Socket();
            plain.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            return tune(delegate.createSocket(plain, host, port, true));
        }

        @Override
        public Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws IOException {
            Socket plain = new Socket();
            plain.bind(new InetSocketAddress(localHost, localPort));
            plain.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            return tune(delegate.createSocket(plain, host, port, true));
        }

        @Override
        public Socket createSocket(java.net.InetAddress host, int port) throws IOException {
            Socket plain = new Socket();
            plain.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            return tune(delegate.createSocket(plain, host.getHostName(), port, true));
        }

        @Override
        public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws IOException {
            Socket plain = new Socket();
            plain.bind(new InetSocketAddress(localAddress, localPort));
            plain.connect(new InetSocketAddress(address, port), connectTimeoutMs);
            return tune(delegate.createSocket(plain, address.getHostName(), port, true));
        }

        private Socket tune(Socket socket) throws IOException {
            socket.setSoTimeout(readTimeoutMs);
            return socket;
        }
    }
}
