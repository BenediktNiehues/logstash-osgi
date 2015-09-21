package de.sjka.logstash.osgi;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

import org.json.simple.JSONObject;
import org.osgi.framework.Bundle;
import org.osgi.service.log.LogEntry;
import org.osgi.service.log.LogListener;
import org.osgi.service.log.LogService;

public class LogstashSender implements Runnable, LogListener {

	private static final String PROPERTY_HOST = "de.sjka.logstash.host";
	private static final String PROPERTY_ENABLED = "de.sjka.logstash.enabled";

	private String ipAddress;
	private BlockingDeque<LogEntry> queue = new LinkedBlockingDeque<>();
	private Thread thread;

	@Override
	public void run() {
		System.out.println("Logstash sender started");
		try {
			while (!Thread.interrupted()) {
				LogEntry entry = queue.takeFirst();
				process(entry);
			}
		} catch (InterruptedException e) {
			// all good
			System.out.println("Logstash sender interrupted");
		}
		System.out.println("Logstash sender going to die");
	}

	@Override
	public void logged(LogEntry logEntry) {
		queue.add(logEntry);
	}

	private void process(LogEntry logEntry) {
		if (logEntry.getLevel() <= LogService.LOG_WARNING) {
			if (!"true".equals(System.getProperty(PROPERTY_ENABLED, "false"))) {
				return;
			};
			String host = System.getProperty(PROPERTY_HOST, "127.0.0.1:2800");
			try {
				JSONObject values = serializeLogEntry(logEntry);

				String payload = values.toJSONString();
				byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
				int postDataLength = postData.length;
				String request = "http://" + host + "/osgi";
				URL url = new URL(request);
				HttpURLConnection conn = (HttpURLConnection) url.openConnection();
				conn.setDoOutput(true);
				conn.setInstanceFollowRedirects(false);
				conn.setRequestMethod("PUT");
				conn.setRequestProperty("Content-Type", "application/json");
				conn.setRequestProperty("charset", "utf-8");
				conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));
				conn.setUseCaches(false);
				try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
					wr.write(postData);
				}
				if (conn.getResponseCode() != 200) {
					System.err.println("Got response " + conn.getResponseCode() + " - " + conn.getResponseMessage());
				}
			} catch (ConnectException e) {
				System.err.println("Could not connect to " + host);
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
			values.put("exception-class", stackTrace[0].getClassName());
			values.put("exception-method", stackTrace[0].getMethodName());
			values.put("exception-line", stackTrace[0].getLineNumber() + "");
			values.put("error-id", hash(stackTrace[0].getClassName(), stackTrace[0].getMethodName(), logEntry.getException().getClass().getName()));
		} else {
			values.put("error-id", hash(logEntry.getBundle().getSymbolicName(), logEntry.getMessage()));
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
	            if(hex.length() == 1) hexString.append('0');
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
			throw new IllegalStateException("It's running already!");
		}
		thread = new Thread(this);
		thread.start();
	}

	public void stop() {
		if (thread == null) {
			throw new IllegalStateException("It's not running!");
		}
		thread.interrupt();
		thread = null;
	}

}
