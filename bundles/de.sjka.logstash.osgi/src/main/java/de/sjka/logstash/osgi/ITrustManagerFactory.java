package de.sjka.logstash.osgi;

import javax.net.ssl.TrustManager;

public interface ITrustManagerFactory {

    public TrustManager createTrustManager();

}
