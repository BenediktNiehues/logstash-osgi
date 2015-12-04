package de.sjka.logstash.osgi;

import java.util.Map;

import org.osgi.service.log.LogEntry;

public interface ILogstashPropertyExtension {

    public Map<String, String> getExtensions(LogEntry logEntry);

}
