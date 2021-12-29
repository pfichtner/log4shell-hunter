package com.github.pfichtner.log4shell.scanner;

import static java.util.Arrays.asList;

import java.util.ArrayList;
import java.util.List;

import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.DirContextLookupsCallsFromJndiManager;
import com.github.pfichtner.log4shell.scanner.detectors.InitialContextLookupsCalls;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccessWithJdbcPrefix;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupConstructorWithISException;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiManager;

public final class Detectors {

	private static final Log4JDetector log4jDetector = new Log4JDetector();

	private static final List<AbstractDetector> detectors = List.of( //
			new JndiManagerLookupCallsFromJndiLookup(), //
			new NamingContextLookupCallsFromJndiManager(), //
			new NamingContextLookupCallsFromJndiLookup(), //
			new DirContextLookupsCallsFromJndiManager(), //
			new Log4jPluginAnnotation(), //
			new InitialContextLookupsCalls(), //
			new IsJndiEnabledPropertyAccess(), //
			new JndiLookupConstructorWithISException(), //
			new IsJndiEnabledPropertyAccessWithJdbcPrefix() //
	);

	private Detectors() {
		super();
	}

	public static List<AbstractDetector> allDetectors() {
		return detectors;
	}

	public static List<AbstractDetector> allDetectorsWithLog4JDetector() {
		List<AbstractDetector> detectors = new ArrayList<>(asList(log4jDetector));
		detectors.addAll(allDetectors());
		return List.copyOf(detectors);
	}

}
