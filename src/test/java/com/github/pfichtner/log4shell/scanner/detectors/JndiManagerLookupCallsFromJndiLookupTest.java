package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class JndiManagerLookupCallsFromJndiLookupTest {

	JndiManagerLookupCallsFromJndiLookup sut = new JndiManagerLookupCallsFromJndiLookup();

	@Test
	void canDetectLookupCalls(Log4jJars log4jJars) throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut))).containsOnlyKeys(versionsWithJndiLookups(log4jJars));
	}

	static Log4jJars versionsWithJndiLookups(Log4jJars log4jJars) {
		// 2.0, 2.0.1, 2.0.2
		// @Override
		// public String lookup(LogEvent event, String key) {
		// if (key == null) {
		// return null;
		// }
		//
		// Context ctx = null;
		// try {
		// ctx = new InitialContext();
		// return (String) ctx.lookup(convertJndiName(key));
		// } catch (NamingException e) {
		// return null;
		// } finally {
		// Closer.closeSilently(ctx);
		// }
		// }

		// 2.12.2 (Quickfix)
		// @Override
		// public String lookup(LogEvent event, String key) {
		// LOGGER.warn("Attempt to use JNDI Lookup");
		// return RESULT;
		// }

		// JndiManager#lookup(String) calls introduces with version 2.1
		return log4jJars.versionsHigherOrEqualTo("2.1").not(log4jJars.versions("2.12.2"));
	}

}