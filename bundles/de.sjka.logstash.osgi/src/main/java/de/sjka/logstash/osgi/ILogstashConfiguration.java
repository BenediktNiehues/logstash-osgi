/**
 * Copyright (c) 2014-2016 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package de.sjka.logstash.osgi;

/**
 * Configuration provider for Logstash.
 * 
 * Provide an OSGi service implementing this interface in order to configure the
 * behavior of the logstash sender.
 * 
 * @author Simon Kaufmann - Initial contribution and API.
 *
 */
public interface ILogstashConfiguration {

	public enum LogstashConfig {
		URL("http://localhost/"), USERNAME(""), PASSWORD(""), SSL_NO_CHECK("false"), ENABLED("false"), LOGLEVEL(
				"warning");

		private String defaultValue;

		private LogstashConfig(String defaultValue) {
			this.defaultValue = defaultValue;
		}

		public String defaultValue() {
			return defaultValue;
		}

	}

	public String getConfiguration(LogstashConfig key);

}
