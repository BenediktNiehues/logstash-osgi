package de.sjka.logstash.osgi;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {

	private LogReaderServiceTracker logTracker;
	private LogstashSender sender;

	public void start(BundleContext bundleContext) throws Exception {
		sender = new LogstashSender();
		sender.start();

		logTracker = new LogReaderServiceTracker(bundleContext, sender);
		logTracker.open();
	}

	public void stop(BundleContext bundleContext) throws Exception {
		if (logTracker != null) {
			logTracker.close();
			logTracker = null;
		}
		if (sender != null) {
			sender.stop();
			sender = null;
		}
	}
	
}