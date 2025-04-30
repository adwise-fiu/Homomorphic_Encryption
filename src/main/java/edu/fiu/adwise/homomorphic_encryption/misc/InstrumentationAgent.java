/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.misc;

import java.lang.instrument.Instrumentation;

/**
 * This class serves as a Java instrumentation agent, allowing the measurement of object sizes at runtime.
 * It uses the {@link Instrumentation} API to provide functionality for determining the size of objects in memory.
 *
 * <p>To use this agent, it must be specified as a Java agent in the JVM arguments. The premain method is invoked
 * before the application's main method, initializing the instrumentation instance.</p>
 *
 * <p>For more details, refer to:
 * <a href="https://www.baeldung.com/java-size-of-object">Baeldung: Measuring Object Size in Java</a></p>
 */
public class InstrumentationAgent {
	/**
	 * A volatile reference to the {@link Instrumentation} instance, initialized by the JVM.
	 */
	private static volatile Instrumentation globalInstrumentation;

	/**
	 * The premain method is called by the JVM before the application's main method.
	 * It initializes the {@link Instrumentation} instance for use in the agent.
	 *
	 * @param agentArgs The agent arguments passed to the JVM.
	 * @param inst The {@link Instrumentation} instance provided by the JVM.
	 */
	public static void premain(final String agentArgs, final Instrumentation inst) {
		globalInstrumentation = inst;
	}

	/**
	 * Returns the size of the specified object in bytes.
	 *
	 * @param object The object whose size is to be measured.
	 * @return The size of the object in bytes.
	 * @throws IllegalStateException If the agent has not been initialized.
	 */
	public static long getObjectSize(final Object object) {
		if (globalInstrumentation == null) {
			throw new IllegalStateException("Agent not initialized.");
		}
		return globalInstrumentation.getObjectSize(object);
	}
}
