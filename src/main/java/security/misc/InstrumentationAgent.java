package security.misc;

import java.lang.instrument.Instrumentation;

public class InstrumentationAgent {
	// I ran the commands to compile the JAR file within misc folder and moved the Instrumentation jar file to libs
	// https://www.baeldung.com/java-size-of-object
	private static volatile Instrumentation globalInstrumentation;

	public static void premain(final String agentArgs, final Instrumentation inst) {
		globalInstrumentation = inst;
	}

	public static long getObjectSize(final Object object) {
		if (globalInstrumentation == null) {
			throw new IllegalStateException("Agent not initialized.");
		}
		return globalInstrumentation.getObjectSize(object);
	}
}
