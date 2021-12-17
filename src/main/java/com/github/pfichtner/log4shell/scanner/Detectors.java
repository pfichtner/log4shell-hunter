package com.github.pfichtner.log4shell.scanner;

import static java.util.Collections.unmodifiableList;

import java.util.Arrays;
import java.util.List;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupWithNamingContextLookupsWithoutThrowingException;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerWithDirContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerWithNamingContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.RefsToInitialContextLookups;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public final class Detectors {

	private static final List<Detector<Detections>> detectors = unmodifiableList(Arrays.asList( //
			new JndiManagerLookupCalls(), //
			new JndiManagerWithNamingContextLookups(), //
			new JndiLookupWithNamingContextLookupsWithoutThrowingException(), //
			new JndiManagerWithDirContextLookups(), //
			new Log4jPluginAnnotation(), //
			new RefsToInitialContextLookups(), //
			new IsJndiEnabledPropertyAccess() //
	));

	private Detectors() {
		super();
	}

	public static List<Detector<Detections>> allDetectors() {
		return detectors;
	}

}
