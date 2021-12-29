package com.github.pfichtner.log4shell.scanner;

import static java.util.Collections.emptySet;
import static java.util.Map.entry;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toUnmodifiableSet;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
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

public class Fingerprint {

	private static final Set<Class<? extends AbstractDetector>> a = emptySet();
	private static final Map<String, Set<Class<? extends AbstractDetector>>> mapping = mapping();

	private static Map<String, Set<Class<? extends AbstractDetector>>> mapping() {
		var b = Set.of(Log4jPluginAnnotation.class, InitialContextLookupsCalls.class);
		var c = Set.of(NamingContextLookupCallsFromJndiLookup.class, Log4jPluginAnnotation.class);
		var d = Set.of(JndiManagerLookupCallsFromJndiLookup.class, NamingContextLookupCallsFromJndiManager.class,
				Log4jPluginAnnotation.class);
		var e = Set.of(NamingContextLookupCallsFromJndiManager.class, Log4jPluginAnnotation.class,
				IsJndiEnabledPropertyAccess.class);
		var f = Set.of(JndiManagerLookupCallsFromJndiLookup.class, NamingContextLookupCallsFromJndiManager.class,
				Log4jPluginAnnotation.class, IsJndiEnabledPropertyAccess.class,
				JndiLookupConstructorWithISException.class);
		var g = Set.of(JndiManagerLookupCallsFromJndiLookup.class, DirContextLookupsCallsFromJndiManager.class,
				Log4jPluginAnnotation.class);
		var h = Set.of(JndiManagerLookupCallsFromJndiLookup.class, DirContextLookupsCallsFromJndiManager.class,
				Log4jPluginAnnotation.class, IsJndiEnabledPropertyAccess.class);
		var i = Set.of(JndiManagerLookupCallsFromJndiLookup.class, Log4jPluginAnnotation.class,
				InitialContextLookupsCalls.class, IsJndiEnabledPropertyAccess.class,
				JndiLookupConstructorWithISException.class);
		var j = Set.of(JndiManagerLookupCallsFromJndiLookup.class, Log4jPluginAnnotation.class,
				InitialContextLookupsCalls.class, IsJndiEnabledPropertyAccess.class,
				JndiLookupConstructorWithISException.class, IsJndiEnabledPropertyAccessWithJdbcPrefix.class);

		return Map.ofEntries( //
				entry("2.0-alpha1", a), //
				entry("2.0-alpha2", a), //
				entry("2.0-beta1", a), //
				entry("2.0-beta2", a), //
				entry("2.0-beta3", a), //
				entry("2.0-beta4", a), //
				entry("2.0-beta5", a), //
				entry("2.0-beta6", a), //
				entry("2.0-beta7", a), //
				entry("2.0-beta8", a), //
				entry("2.0-beta9", b), //
				entry("2.0-rc1", b), //
				entry("2.0-rc2", c), //
				entry("2.0", c), //
				entry("2.0.1", c), //
				entry("2.0.2", c), //
				entry("2.1", d), //
				entry("2.2", d), //
				entry("2.3", d), //
				entry("2.4", d), //
				entry("2.4.1", d), //
				entry("2.5", d), //
				entry("2.6", d), //
				entry("2.6.1", d), //
				entry("2.6.2", d), //
				entry("2.7", d), //
				entry("2.8", d), //
				entry("2.8.1", d), //
				entry("2.8.2", d), //
				entry("2.9.0", d), //
				entry("2.9.1", d), //
				entry("2.10.0", d), //
				entry("2.11.0", d), //
				entry("2.11.1", d), //
				entry("2.11.2", d), //
				entry("2.12.0", d), //
				entry("2.12.1", d), //
				entry("2.12.2", e), //
				entry("2.12.3", f), //
				entry("2.13.0", d), //
				entry("2.13.1", d), //
				entry("2.13.2", d), //
				entry("2.13.3", d), //
				entry("2.14.0", d), //
				entry("2.14.1", d), //
				entry("2.15.0", g), //
				entry("2.16.0", h), //
				entry("2.17.0", i), //
				entry("2.17.1", j) //
		);
	}

	public static List<String> getFingerprint(Collection<Detection> detections) {
		Set<Class<?>> classes = classes(detections);
		return mapping.entrySet().stream().filter(e -> e.getValue().equals(classes)).map(Entry::getKey)
				.collect(toList());
	}

	public static Set<Class<? extends AbstractDetector>> getDetectors(String version) {
		return mapping.get(version);
	}

	private static Set<Class<?>> classes(Collection<Detection> detections) {
		return detections.stream().map(Detection::getDetector).map(Object::getClass).collect(toUnmodifiableSet());
	}

}
