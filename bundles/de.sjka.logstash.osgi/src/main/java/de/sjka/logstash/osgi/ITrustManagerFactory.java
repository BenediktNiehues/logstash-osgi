/**
 * Copyright (c) 2014-2016 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package de.sjka.logstash.osgi;

import javax.net.ssl.TrustManager;

/**
 * Provider for a custom SSL {@link TrustManager}.
 * 
 * @author Simon Kaufmann - Initial contribution and API.
 *
 */
public interface ITrustManagerFactory {

	/**
	 * Create a custom trust manager for HTTPS connections.
	 * 
	 * @return the trust manager
	 */
	public TrustManager createTrustManager();

}
