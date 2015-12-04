package de.sjka.logstash.osgi;

public interface ILogstashConfiguration {

    public enum LogstashConfig {
        URL("http://localhost/"),
        USERNAME(""),
        PASSWORD(""),
        SSL_NO_CHECK("false"),
        ENABLED("false");

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
