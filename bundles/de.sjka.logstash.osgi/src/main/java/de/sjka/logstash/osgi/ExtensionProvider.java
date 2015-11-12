package de.sjka.logstash.osgi;

import java.util.Collections;
import java.util.Map;

import org.osgi.service.log.LogEntry;

public class ExtensionProvider {

    public Map<String, String> getExtensions(LogEntry logEntry) {
		return Collections.emptyMap();
	}

}
