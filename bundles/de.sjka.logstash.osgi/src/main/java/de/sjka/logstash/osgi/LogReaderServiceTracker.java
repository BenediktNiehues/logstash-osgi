package de.sjka.logstash.osgi;

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.log.LogReaderService;
import org.osgi.util.tracker.ServiceTracker;

public class LogReaderServiceTracker extends ServiceTracker<LogReaderService, LogReaderService>{

	private final LogstashSender sender;

	public LogReaderServiceTracker(BundleContext context, LogstashSender sender) {
		super(context, LogReaderService.class.getName(), null);
		this.sender = sender;
	}
	
	@Override
	public LogReaderService addingService(ServiceReference<LogReaderService> reference) {
		System.out.println("Adding LogstashSender as a listener.");
		LogReaderService service = super.addingService(reference);
		service.addLogListener(sender);
		return service;
	}
	
	@Override
	public void remove(ServiceReference<LogReaderService> reference) {
		System.out.println("Removing LogstashSender from listeners.");
		LogReaderService service = getService(reference);
		service.removeLogListener(sender);
		super.remove(reference);
	}

}
