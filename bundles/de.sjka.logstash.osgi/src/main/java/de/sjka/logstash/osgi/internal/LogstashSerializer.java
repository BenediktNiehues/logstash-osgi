package de.sjka.logstash.osgi.internal;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;

import org.json.simple.JSONObject;
import org.osgi.framework.Bundle;
import org.osgi.service.log.LogEntry;
import org.osgi.service.log.LogService;

import de.sjka.logstash.osgi.ILogstashPropertyExtension;
import de.sjka.logstash.osgi.ILogstashSerializer;

/**
 * Implementation of {@link ILogstashSerializer}.
 * Serializes and enriches {@link LogEntry}.
 *
 * @author Christoph Knauf - Initial contribution and API.
 *
 */
public class LogstashSerializer implements ILogstashSerializer {

    private Set<ILogstashPropertyExtension> logstashPropertyExtensions = new HashSet<>();

    protected void start() {

    }

    @Override
    @SuppressWarnings("unchecked")
    public JSONObject serialize(LogEntry logEntry) {
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
            try (StringWriter sw = new StringWriter(); PrintWriter pw = new PrintWriter(sw)) {
                logEntry.getException().printStackTrace(pw);
                String stackTraceString = sw.toString();
                values.put("exception-type", logEntry.getException().getClass().getName());
                values.put("exception-message", logEntry.getException().getMessage());
                values.put("exception-stacktrace", stackTraceString);
            } catch (IOException e) {
                // It's a StringWriter... All good!
            }
            if (stackTrace != null && stackTrace.length > 0) {
                values.put("exception-class", stackTrace[0].getClassName());
                values.put("exception-method", stackTrace[0].getMethodName());
                values.put("exception-line", stackTrace[0].getLineNumber() + "");
                values.put("error-id", hash(stackTrace[0].getClassName(), stackTrace[0].getMethodName(),
                        logEntry.getException().getClass().getName()));
            } else {
                values.put("error-id",
                        hash(logEntry.getBundle().getSymbolicName(), logEntry.getException().getMessage()));
            }
        } else {
            values.put("error-id", hash(logEntry.getBundle().getSymbolicName(), logEntry.getMessage()));
        }
        for (ILogstashPropertyExtension logstashPropertyExtension : logstashPropertyExtensions) {
            for (Entry<String, Object> entry : logstashPropertyExtension.getExtensions(logEntry).entrySet()) {
                values.put(entry.getKey(), entry.getValue());
            }
        }
        values.put("ip", getIp());
        return values;
    }

    private String getIp() {
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress address = inetAddresses.nextElement();
                    if (address instanceof Inet4Address) {
                        if (!address.isLinkLocalAddress() && !address.isAnyLocalAddress()
                                && !address.isLoopbackAddress()) {
                            return address.getHostAddress();
                        }
                    }
                }
            }
            return "LOC_" + InetAddress.getLocalHost().getHostAddress() + "_"
                    + InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException | SocketException e) {
            return "offline_" + e.getMessage();
        }
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
                if (hex.length() == 1) {
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

    protected void bindLogstashPropertyExtension(ILogstashPropertyExtension logstashPropertyExtension) {
        this.logstashPropertyExtensions.add(logstashPropertyExtension);
    }

    protected void unbindLogstashPropertyExtension(ILogstashPropertyExtension logstashPropertyExtension) {
        this.logstashPropertyExtensions.remove(logstashPropertyExtension);
    }

}
