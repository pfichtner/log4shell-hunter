package com.github.pfichtner.log4shell.scanner;

import java.util.Collection;
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

	private static final Collection<AbstractDetector> detectors = List.of( //
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

	public static Collection<AbstractDetector> allDetectors() {
		return detectors;
	}

}
