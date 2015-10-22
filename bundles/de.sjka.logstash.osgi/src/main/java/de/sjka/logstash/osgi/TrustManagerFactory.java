package de.sjka.logstash.osgi;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class TrustManagerFactory {
	
	public static TrustManager createTrustManager() {
		return new X509TrustManager() {
	        
			@Override
	        public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException  {
	        	throw new CertificateException("Client certificates not supported");
	        }
	        
	        @Override
	        public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
	        	// accept any
	        }

	        @Override
	        public X509Certificate[] getAcceptedIssuers() {
	            return null;
	        }
	        
	    };		
	}
	
}
