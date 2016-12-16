/**
 * Copyright (c) 2014-2016 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package de.sjka.logstash.osgi;

import org.osgi.service.log.LogEntry;

/**
 * Filter for log messages.
 * 
 * Provide one or more OSGi service(s) implementing this interface in order to
 * filter a log message. If at least one filter vetoes a log message, then it
 * will not be forwarded to logstash.
 * 
 * @author Simon Kaufmann - Initial contribution and API.
 *
 */
public interface ILogstashFilter {

	/**
	 * Determines whether a {@link LogEntry} should be sent to logstash or not.
	 * 
	 * @param entry
	 *            the {@link LogEntry} to be filtered
	 * @return {@code true} if the entry should be sent, {@code false} if it
	 *         should be filtered out
	 */
	public boolean apply(LogEntry entry);

}
