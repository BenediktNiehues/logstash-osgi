package de.sjka.logstash.osgi;

import org.osgi.service.log.LogEntry;

public interface ILogstashFilter {
    
    /**
     * Determines whether a {@link LogEntry} should be sent to logstash or not.
     * 
     * @param entry the {@link LogEntry} to be filtered
     * @return {@code true} if the entry should be sent, {@code false} if it should be filtered out
     */
    public boolean apply(LogEntry entry);

}
