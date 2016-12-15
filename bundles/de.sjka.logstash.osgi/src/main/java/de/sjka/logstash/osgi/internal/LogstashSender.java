package de.sjka.logstash.osgi.internal;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.osgi.framework.Bundle;
import org.osgi.service.log.LogEntry;
import org.osgi.service.log.LogListener;
import org.osgi.service.log.LogReaderService;
import org.osgi.service.log.LogService;

import com.qivicon.gateway.messagingadapter.api.MessagingPublisher;
import com.qivicon.gateway.messagingadapter.api.QbertMessage;
import com.qivicon.gateway.messagingadapter.api.QbertMessageRoutingKey;

import de.sjka.logstash.osgi.ILogstashConfiguration;
import de.sjka.logstash.osgi.ILogstashConfiguration.LogstashConfig;
import de.sjka.logstash.osgi.ILogstashFilter;
import de.sjka.logstash.osgi.ILogstashPropertyExtension;
import de.sjka.logstash.osgi.ITrustManagerFactory;

public class LogstashSender implements Runnable, LogListener {

    private static final int QUEUE_SIZE = 2 * 1024;

	private String ipAddress;
	private BlockingDeque<LogEntry> queue = new LinkedBlockingDeque<>();
	private Thread thread;

	private SSLSocketFactory sslSocketFactory;
    private ILogstashConfiguration logstashConfiguration;
    private Set<ILogstashPropertyExtension> logstashPropertyExtensions = new HashSet<>();
    private Set<ILogstashFilter> logstashFilters = new HashSet<>();
    private MessagingPublisher messagingPublisher;

	@Override
	public void run() {
		System.out.println("Logstash sender started");
		try {
			while (!Thread.interrupted()) {
				LogEntry entry = queue.takeFirst();
				try {
					process(entry);
				} catch (Exception e) {
					if (e instanceof InterruptedException) {
						throw e; // leave the loop
					}
					queue.putFirst(entry);
					Thread.sleep(5*1000);
				}
			}
		} catch (InterruptedException e) {
			// all good
		}
		System.out.println("Logstash sender shutting down");
	}

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
        if (queue.size() < QUEUE_SIZE) {
        	queue.add(logEntry);
		}
	}

	private void process(LogEntry logEntry) {
        if (logEntry.getLevel() <= getLogLevelConfig()) {
            if (!"true".equals(getConfig(LogstashConfig.ENABLED))) {
				return;
			};
	        for (ILogstashFilter logstashFilter : logstashFilters) {
	            if (!logstashFilter.apply(logEntry)) {
	                return;
	            }
	        }
            String request = getConfig(LogstashConfig.URL);
			if (!request.endsWith("/")) {
				request += "/";
			}
			try {
				JSONObject values = serializeLogEntry(logEntry);
                String payload = values.toJSONString();
                final byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
                if (messagingPublisher != null) {
                    messagingPublisher.sendDirectSync(new QbertMessage() {

                        @Override
                        public boolean hasContentType(String contentType) {
                            return true;
                        }

                        @Override
                        public QbertMessageRoutingKey getRoutingKey() {

                            return new QbertMessageRoutingKey("", "logMessages", "logMessages", "logMessages");
                        }

                        @Override
                        public Map<String, Object> getMetadata() {
                            return Collections.EMPTY_MAP;
                        }

                        @Override
                        public String getContentType() {
                            return "";
                        }

                        @Override
                        public byte[] getContent() {
                            return postData;
                        }
                    });
                } else {
                    System.out.println("MessagingPublisher is null");
                }
                System.out.println("Message:" + payload);


                String username = getConfig(LogstashConfig.USERNAME);
                String password = getConfig(LogstashConfig.PASSWORD);

				String authString = username + ":" + password;
				byte[] authEncBytes = Base64.encodeBase64(authString.getBytes());
				String authStringEnc = new String(authEncBytes);

				URL url = new URL(request);

				HttpURLConnection conn = (HttpURLConnection) url.openConnection();
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
				conn.setReadTimeout(30*1000);
				conn.setConnectTimeout(30*1000);
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
			}
		}

	}

	@SuppressWarnings("unchecked")
	private JSONObject serializeLogEntry(LogEntry logEntry) {
		JSONObject values = new JSONObject();
		values.put("severity", getSeverity(logEntry.getLevel()));
		values.put("message", logEntry.getMessage());
		if (logEntry.getBundle() != null) {
			values.put("bundle-name", logEntry.getBundle().getSymbolicName());
			values.put("bundle-version", logEntry.getBundle().getVersion().toString());
			values.put("bundle-state", getBundleState(logEntry.getBundle().getState()));
		}
		if (logEntry.getException() != null) {
			StackTraceElement[] stackTrace = logEntry.getException().getStackTrace();
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			logEntry.getException().printStackTrace(pw);
			String stackTraceString = sw.toString();
			pw.close();
			try {
				sw.close();
			} catch (IOException e) {
				// StringWriter... All good.
			}
			values.put("exception-type", logEntry.getException().getClass().getName());
			values.put("exception-message", logEntry.getException().getMessage());
			values.put("exception-stacktrace", stackTraceString);
			if (stackTrace != null && stackTrace.length > 0) {
				values.put("exception-class", stackTrace[0].getClassName());
				values.put("exception-method", stackTrace[0].getMethodName());
				values.put("exception-line", stackTrace[0].getLineNumber() + "");
				values.put("error-id", hash(stackTrace[0].getClassName(), stackTrace[0].getMethodName(), logEntry.getException().getClass().getName()));
			} else {
                values.put("error-id",
                        hash(logEntry.getBundle().getSymbolicName(), logEntry.getException().getMessage()));
			}
		} else {
			values.put("error-id", hash(logEntry.getBundle().getSymbolicName(), logEntry.getMessage()));
		}
        for (ILogstashPropertyExtension logstashPropertyExtension : logstashPropertyExtensions) {
            for (Entry<String, String> entry : logstashPropertyExtension.getExtensions(logEntry).entrySet()) {
                values.put(entry.getKey(), entry.getValue());
            }
		}
		values.put("ip", getIPAddress());
		return values;
	}

	private String hash(String... values) {
		StringBuilder sb = new StringBuilder();
		for (String value : values) {
			sb.append(value);
		}
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(sb.toString().getBytes("UTF-8"));
			StringBuffer hexString = new StringBuffer();
	        for (int i = 0; i < hash.length; i++) {
	            String hex = Integer.toHexString(0xff & hash[i]);
	            if(hex.length() == 1) {
                    hexString.append('0');
                }
	            hexString.append(hex);
	        }
	        return hexString.toString();
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	private String getBundleState(int state) {
		switch (state) {
		case Bundle.UNINSTALLED:
			return "UNINSTALLED";
		case Bundle.INSTALLED:
			return "INSTALLED";
		case Bundle.RESOLVED:
			return "RESOLVED";
		case Bundle.STARTING:
			return "STARTING";
		case Bundle.STOPPING:
			return "STOPPING";
		case Bundle.ACTIVE:
			return "ACTIVE";
		default:
			return "UNKNOWN";
		}
	}

	private String getSeverity(int level) {
		switch (level) {
		case LogService.LOG_ERROR:
			return "ERROR";
		case LogService.LOG_WARNING:
			return "WARNING";
		case LogService.LOG_INFO:
			return "INFO";
		case LogService.LOG_DEBUG:
			return "DEBUG";
		default:
			return "UNKNOWN";
		}
	}

	private String getIPAddress() {
		if (ipAddress != null) {
			return ipAddress;
		} else {
			try {
				Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
				while (networkInterfaces.hasMoreElements()) {
					NetworkInterface networkInterface = networkInterfaces.nextElement();
					Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
					while (inetAddresses.hasMoreElements()) {
						InetAddress address = inetAddresses.nextElement();
						if (address instanceof Inet4Address) {
							return address.getHostAddress();
						}
					}
				}
				ipAddress = InetAddress.getLocalHost().getHostAddress();
				return ipAddress;
			} catch (UnknownHostException | SocketException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public void start() {
		if (thread != null) {
            throw new IllegalStateException("LogstashSender thread is already running!");
		}
		thread = new Thread(this);
		thread.start();
	}

	public void stop() {
		if (thread == null) {
            throw new IllegalStateException("LogstashSender thread is not running!");
		}
		thread.interrupt();
		thread = null;
	}

    protected void bindLogReaderService(LogReaderService logReaderService) {
        System.out.println("Adding LogstashSender as a listener.");
        logReaderService.addLogListener(this);
    }

    protected void bindMessagingPublisher(MessagingPublisher messagingPublisher) {
        System.out.println("binding messagingPublisher");
        this.messagingPublisher = messagingPublisher;
    }

    protected void unbindMessagingPublisher(MessagingPublisher messagingPublisher) {
        System.out.println("Removing MessagingPublisher");
        this.messagingPublisher = null;
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

    protected void bindLogstashPropertyExtension(ILogstashPropertyExtension logstashPropertyExtension) {
        this.logstashPropertyExtensions.add(logstashPropertyExtension);
    }

    protected void unbindLogstashPropertyExtension(ILogstashPropertyExtension logstashPropertyExtension) {
        this.logstashPropertyExtensions.remove(logstashPropertyExtension);
    }

    protected void bindLogstashFilter(ILogstashFilter logstashFilter) {
        this.logstashFilters.add(logstashFilter);
    }

    protected void unbindLogstashFilter(ILogstashFilter logstashFilter) {
        this.logstashFilters.remove(logstashFilter);
    }

}
