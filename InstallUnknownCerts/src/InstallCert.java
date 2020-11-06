/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * Originally from:
 * http://blogs.sun.com/andreas/resource/InstallCert.java
 * Use:
 * java InstallCert hostname
 * Example:
 *% java InstallCert ecc.fedora.redhat.com
 */

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Class used to add the server's certificate to the KeyStore with your trusted
 * certificates.
 */
public class InstallCert {
    private static String tunnelHost = "22.147.128.100";
    private static int tunnelPort = 8080;
    private static boolean proxy = true;

    public static void main(String[] args) throws Exception {
	String host;
	int port;

	char[] passphrase;
	if ((args.length == 1) || (args.length == 2)) {
	    String[] c = args[0].split(":");
	    host = c[0];
	    port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
	    String p = (args.length == 1) ? "changeit" : args[1];
	    passphrase = p.toCharArray();
	} else {
	    System.out.println("Usage: java InstallCert <host>[:port] [passphrase]");
	    return;
	}
	String certName = "jssecacerts";
	// String certName = "C:\\Program
	// Files\\Java\\jre1.8.0_141\\lib\\security\\cacerts";
	File file = new File(certName);
	// C:\Program Files\Java\jre1.8.0_141\lib\security\cacerts
	if (file.isFile() == false) {
	    char SEP = File.separatorChar;
	    File dir = new File(System.getProperty("java.home") + SEP + "lib" + SEP + "security");
	    file = new File(dir, "jssecacerts");
	    if (file.isFile() == false) {
		file = new File(dir, "cacerts");
	    }
	}
	System.out.println("Loading KeyStore " + file + "...");
	InputStream in = new FileInputStream(file);
	KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	ks.load(in, passphrase);
	in.close();

	SSLContext context = SSLContext.getInstance("TLSv1.2");
	TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	tmf.init(ks);
	X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
	SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
	context.init(null, new TrustManager[] { tm }, null);
	SSLSocketFactory factory = context.getSocketFactory();

	//
	SSLSocket socket = null;
	if (proxy) {
	    Socket tunnel = new Socket(tunnelHost, tunnelPort);
	    doTunnelHandshake(tunnel, host, port);
	    System.out.println("Using proxy tunnel : " + (tunnelHost + ":" + tunnelPort));
	    System.out.println("Opening connection to " + host + ":" + port + "...");
	    socket = (SSLSocket) factory.createSocket(tunnel, host, port, true);
	}
	else
	{
	    System.out.println("Opening direct connection to " + host + ":" + port + "...");
	    socket = (SSLSocket) factory.createSocket(host, port);
	}

	// socket.setEnabledProtocols(new String[]{"TLSv1","TLSv1.1","TLSv1.2"});
	// socket.setEnabledCipherSuites(new
	// String[]{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"});
	// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_RSA_WITH_AES_256_CBC_SHA256,
	// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	// TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	// TLS_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
	// TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	// TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256,
	// TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	// TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
	// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	// TLS_RSA_WITH_AES_128_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	// TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	// TLS_DHE_DSS_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_GCM_SHA384,
	// TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
	// TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
	// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256,
	// TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	// TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
	//
	socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
	    public void handshakeCompleted(HandshakeCompletedEvent event) {
		System.out.println("Handshake finished!");
		System.out.println("\t CipherSuite:" + event.getCipherSuite());
		System.out.println("\t SessionId " + event.getSession());
		System.out.println("\t PeerHost " + event.getSession().getPeerHost());
	    }
	});
	//
	socket.setSoTimeout(100000);
	try {
	    System.out.println("Starting SSL handshake...");
	    socket.startHandshake();
	    System.out.println("Closing socket...");
	    socket.close();
	    System.out.println();
	    System.out.println("No errors, certificate is already trusted");
	} catch (SSLException e) {
	    System.out.println();
	    e.printStackTrace(System.out);
	}

	X509Certificate[] chain = tm.chain;
	if (chain == null) {
	    System.out.println("Could not obtain server certificate chain");
	    return;
	}

	BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

	System.out.println();
	System.out.println("Server sent " + chain.length + " certificate(s):");
	System.out.println();
	MessageDigest sha1 = MessageDigest.getInstance("SHA1");
	MessageDigest md5 = MessageDigest.getInstance("MD5");
	for (int i = 0; i < chain.length; i++) {
	    X509Certificate cert = chain[i];
	    System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
	    System.out.println("   Issuer  " + cert.getIssuerDN());
	    sha1.update(cert.getEncoded());
	    System.out.println("   sha1    " + toHexString(sha1.digest()));
	    md5.update(cert.getEncoded());
	    System.out.println("   md5     " + toHexString(md5.digest()));
	    System.out.println();
	}

	System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
	String line = reader.readLine().trim();
	int k;
	try {
	    k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
	} catch (NumberFormatException e) {
	    System.out.println("KeyStore not changed");
	    return;
	}

	X509Certificate cert = chain[k];
	String alias = host + "-" + (k + 1);
	ks.setCertificateEntry(alias, cert);

	OutputStream out = new FileOutputStream(certName);
	ks.store(out, passphrase);
	out.close();

	System.out.println();
	System.out.println(cert);
	System.out.println();
	System.out.println("Added certificate to keystore 'jssecacerts' using alias '" + alias + "'");
    }

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    private static String toHexString(byte[] bytes) {
	StringBuilder sb = new StringBuilder(bytes.length * 3);
	for (int b : bytes) {
	    b &= 0xff;
	    sb.append(HEXDIGITS[b >> 4]);
	    sb.append(HEXDIGITS[b & 15]);
	    sb.append(' ');
	}
	return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {

	private final X509TrustManager tm;
	private X509Certificate[] chain;

	SavingTrustManager(X509TrustManager tm) {
	    this.tm = tm;
	}

	public X509Certificate[] getAcceptedIssuers() {

	    /**
	     * This change has been done due to the following resolution advised for Java
	     * 1.7+ http://infposs.blogspot.kr/2013/06/installcert-and-java-7.html
	     **/

	    return new X509Certificate[0];
	    // throw new UnsupportedOperationException();
	}

	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
	    throw new UnsupportedOperationException();
	}

	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
	    this.chain = chain;
	    tm.checkServerTrusted(chain, authType);
	}
    }

    /*
     * Tell our tunnel where we want to CONNECT, and look for the right reply. Throw
     * IOException if anything goes wrong.
     */
    private static void doTunnelHandshake(Socket tunnel, String host, int port) throws IOException {
	String user_agent_dummy = "curl/7.24.0 (x86_64-apple-darwin12.0) libcurl/7.24.0 OpenSSL/0.9.8r zlib/1.2.5";
	if (System.getProperty("User-Agent") != null) {
	    user_agent_dummy = System.getProperty("User-Agent");
	}
	OutputStream out = tunnel.getOutputStream();
	String msg = "CONNECT " + host + ":" + port + " HTTP/1.1\n" + "User-Agent: " + user_agent_dummy + "\r\n\r\n";
	byte b[];
	try {
	    /*
	     * We really do want ASCII7 -- the http protocol doesn't change with locale.
	     */
	    b = msg.getBytes("ASCII7");
	} catch (UnsupportedEncodingException ignored) {
	    /*
	     * If ASCII7 isn't there, something serious is wrong, but Paranoia Is Good (tm)
	     */
	    b = msg.getBytes();
	}
	out.write(b);
	out.flush();
	System.out.println("Proxy msg : " + msg);

	/*
	 * We need to store the reply so we can create a detailed error message to the
	 * user.
	 */
	byte reply[] = new byte[200];
	int replyLen = 0;
	int newlinesSeen = 0;
	boolean headerDone = false; /* Done on first newline */

	InputStream in = tunnel.getInputStream();
	boolean error = false;

	while (newlinesSeen < 2) {
	    int i = in.read();
	    if (i < 0) {
		throw new IOException("Unexpected EOF from proxy");
	    }
	    if (i == '\n') {
		headerDone = true;
		++newlinesSeen;
	    } else if (i != '\r') {
		newlinesSeen = 0;
		if (!headerDone && replyLen < reply.length) {
		    reply[replyLen++] = (byte) i;
		}
	    }
	}

	/*
	 * Converting the byte array to a string is slightly wasteful in the case where
	 * the connection was successful, but it's insignificant compared to the network
	 * overhead.
	 */
	String replyStr;
	try {
	    replyStr = new String(reply, 0, replyLen, "ASCII7");
	} catch (UnsupportedEncodingException ignored) {
	    replyStr = new String(reply, 0, replyLen);
	}

	System.out.println("Proxy response: " + replyStr);

	/* We asked for HTTP/1.0, so we should get that back */
	if (!replyStr.startsWith("HTTP/1.0 200") && !replyStr.startsWith("HTTP/1.1 200")) {
	    throw new IOException("Unable to tunnel through " + tunnelHost + ":" + tunnelPort + ".  Proxy returns \""
		    + replyStr + "\"");
	}

	/* tunneling Handshake was successful! */
    }
}
