/**
 * Copyright (c) 2014-2016 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package de.sjka.logstash.osgi.internal;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.osgi.service.log.LogEntry;
import org.osgi.service.log.LogListener;
import org.osgi.service.log.LogReaderService;
import org.osgi.service.log.LogService;

import de.sjka.logstash.osgi.ILogstashConfiguration;
import de.sjka.logstash.osgi.ILogstashConfiguration.LogstashConfig;
import de.sjka.logstash.osgi.ILogstashFilter;
import de.sjka.logstash.osgi.ILogstashSerializer;
import de.sjka.logstash.osgi.ITrustManagerFactory;

/**
 * Internal implementation of the logstash sender.
 *
 * It listens to the OSGi {@link LogService} and forwards the log messages to a
 * configured logstash instance.
 *
 * @author Simon Kaufmann - Initial contribution and API.
 *
 */
public class LogstashSender implements LogListener {

    private static final int SECONDS = 1000;
    private static final int QUEUE_SIZE = 1024;

    private BlockingDeque<LogEntry> entryQueue = new LinkedBlockingDeque<>();
    private BlockingDeque<JSONObject> senderQueue = new LinkedBlockingDeque<>();
    private ExecutorService executor = Executors.newFixedThreadPool(2);

    private SSLSocketFactory sslSocketFactory;
    private ILogstashConfiguration logstashConfiguration;
    private ILogstashSerializer logstashSerializer;
    private Set<ILogstashFilter> logstashFilters = new HashSet<>();

    private String getConfig(ILogstashConfiguration.LogstashConfig key) {
        if (logstashConfiguration != null) {
            return logstashConfiguration.getConfiguration(key);
        } else {
            return key.defaultValue();
        }
    }

    private int getLogLevelConfig() {
        String configuredLoglevel = getConfig(LogstashConfig.LOGLEVEL);
        if (configuredLoglevel != null) {
            switch (configuredLoglevel.toLowerCase()) {
                case "debug":
                    return LogService.LOG_DEBUG;
                case "error":
                    return LogService.LOG_ERROR;
                case "info":
                    return LogService.LOG_INFO;
                case "warning":
                    return LogService.LOG_WARNING;
                default:
                    return LogService.LOG_WARNING;
            }
        }
        return LogService.LOG_WARNING;
    }

    @Override
    public void logged(LogEntry logEntry) {
        if (entryQueue.size() < QUEUE_SIZE) {
            entryQueue.add(logEntry);
        }
    }

    private boolean shouldSend(LogEntry logEntry) {
        if (logEntry.getLevel() <= getLogLevelConfig()) {
            if (!"true".equals(getConfig(LogstashConfig.ENABLED))) {
                return false;
            }
            for (ILogstashFilter logstashFilter : logstashFilters) {
                if (!logstashFilter.apply(logEntry)) {
                    return false;
                }
            }
        }
        return true;
    }

    private void send(JSONObject values) {
        String request = getConfig(LogstashConfig.URL);
        if (!request.endsWith("/")) {
            request += "/";
        }
        HttpURLConnection conn = null;
        try {
            String payload = values.toJSONString();
            byte[] postData = payload.getBytes(StandardCharsets.UTF_8);

            String username = getConfig(LogstashConfig.USERNAME);
            String password = getConfig(LogstashConfig.PASSWORD);

            String authString = username + ":" + password;
            byte[] authEncBytes = Base64.encodeBase64(authString.getBytes());
            String authStringEnc = new String(authEncBytes);

            URL url = new URL(request);

            conn = (HttpURLConnection) url.openConnection();
            if (request.startsWith("https") && "true".equals(getConfig(LogstashConfig.SSL_NO_CHECK))) {
                if (sslSocketFactory != null) {
                    ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
                    ((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
                        @Override
                        public boolean verify(String hostname, SSLSession session) {
                            return true;
                        }
                    });
                }
            }
            conn.setDoOutput(true);
            conn.setInstanceFollowRedirects(false);
            conn.setRequestMethod("PUT");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("charset", "utf-8");
            conn.setReadTimeout(30 * SECONDS);
            conn.setConnectTimeout(30 * SECONDS);
            if (username != null && !"".equals(username)) {
                conn.setRequestProperty("Authorization", "Basic " + authStringEnc);
            }
            conn.setUseCaches(false);
            try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
                wr.write(postData);
                wr.flush();
                wr.close();
            }
            if (conn.getResponseCode() != 200) {
                throw new IOException("Got response " + conn.getResponseCode() + " - " + conn.getResponseMessage());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    public void start() throws InterruptedException {
        executor.submit(new Preparer());
        // wait two seconds to avoid bad timing situations
        Thread.sleep(2 * SECONDS);
        executor.submit(new Sender());
    }

    public void stop() {
        if (executor != null) {
            executor.shutdown();
            executor = null;
        }
    }

    protected void bindLogReaderService(LogReaderService logReaderService) {
        System.out.println("Adding LogstashSender as a listener.");
        logReaderService.addLogListener(this);
    }

    protected void unbindLogReaderService(LogReaderService logReaderService) {
        System.out.println("Removing LogstashSender as a listener.");
        logReaderService.removeLogListener(this);
    }

    protected void bindLogstashConfiguration(ILogstashConfiguration logstashConfiguration) {
        this.logstashConfiguration = logstashConfiguration;
    }

    protected void unbindLogstashConfiguration(ILogstashConfiguration logstashConfiguration) {
        this.logstashConfiguration = null;
    }

    protected void bindTrustManagerFactory(ITrustManagerFactory trustManagerFactory) {
        try {
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            final TrustManager[] trustAllCerts = new TrustManager[] { trustManagerFactory.createTrustManager() };
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            sslSocketFactory = sslContext.getSocketFactory();
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    protected void unbindTrustManagerFactory(ITrustManagerFactory trustManagerFactory) {
        sslSocketFactory = null;
    }

    protected void bindLogstashFilter(ILogstashFilter logstashFilter) {
        this.logstashFilters.add(logstashFilter);
    }

    protected void unbindLogstashFilter(ILogstashFilter logstashFilter) {
        this.logstashFilters.remove(logstashFilter);
    }

    protected void bindLogstashSerializer(ILogstashSerializer ilLogstashSerializer) {
        this.logstashSerializer = ilLogstashSerializer;
    }

    protected void unbindLogstashSerializer(ILogstashSerializer ilLogstashSerializer) {
        this.logstashSerializer = null;
    }

    /**
     * Enriches the log entries, converts them to JSON using the {@link ILogstashSerializer} and adds them to a separate
     * queue.
     */
    private class Preparer implements Runnable {
        @Override
        public void run() {
            System.out.println("Logstash preparator started");
            try {
                while (true) {
                    if (Thread.interrupted()) {
                        throw new InterruptedException();
                    }
                    LogEntry entry = entryQueue.takeFirst();
                    try {
                        if (shouldSend(entry)) {
                            JSONObject jsonObj = logstashSerializer.serialize(entry);
                            if (senderQueue.size() < QUEUE_SIZE) {
                                senderQueue.add(jsonObj);
                            }
                        }
                    } catch (Exception e) {
                        entryQueue.putFirst(entry);
                        Thread.sleep(60 * SECONDS);
                    }
                }
            } catch (InterruptedException e) {
                // all good
            }
            System.out.println("Logstash preparator shutting down");
        }
    }

    /**
     * Sends the log entries as JSON.
     */
    private class Sender implements Runnable {
        @Override
        public void run() {
            System.out.println("Logstash sender started");
            try {
                while (true) {
                    if (Thread.interrupted()) {
                        throw new InterruptedException();
                    }
                    JSONObject jsonObj = senderQueue.takeFirst();
                    try {
                        send(jsonObj);
                    } catch (Exception e) {
                        senderQueue.putFirst(jsonObj);
                        Thread.sleep(60 * SECONDS);
                    }
                }
            } catch (InterruptedException e) {
                // all good
            }
            System.out.println("Logstash sender shutting down");
        }
    }

}
