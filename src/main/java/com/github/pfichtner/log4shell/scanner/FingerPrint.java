package com.github.pfichtner.log4shell.scanner;

import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toUnmodifiableSet;

import java.util.Collection;
import java.util.HashMap;
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

public class FingerPrint {

	private static final Set<Class<? extends AbstractDetector>> a = emptySet();
	private static final Map<String, Set<Class<? extends AbstractDetector>>> mapping = mapping();

	private static Map<String, Set<Class<? extends AbstractDetector>>> mapping() {
		Map<String, Set<Class<? extends AbstractDetector>>> map = new HashMap<>();
		Set<Class<? extends AbstractDetector>> b = Set.of(Log4jPluginAnnotation.class,
				InitialContextLookupsCalls.class);
		Set<Class<? extends AbstractDetector>> c = Set.of(NamingContextLookupCallsFromJndiLookup.class,
				Log4jPluginAnnotation.class);
		Set<Class<? extends AbstractDetector>> d = Set.of(JndiManagerLookupCallsFromJndiLookup.class,
				NamingContextLookupCallsFromJndiManager.class, Log4jPluginAnnotation.class);
		Set<Class<? extends AbstractDetector>> e = Set.of(NamingContextLookupCallsFromJndiManager.class,
				Log4jPluginAnnotation.class, IsJndiEnabledPropertyAccess.class);
		Set<Class<? extends AbstractDetector>> f = Set.of(JndiManagerLookupCallsFromJndiLookup.class,
				NamingContextLookupCallsFromJndiManager.class, Log4jPluginAnnotation.class,
				IsJndiEnabledPropertyAccess.class, JndiLookupConstructorWithISException.class);
		Set<Class<? extends AbstractDetector>> g = Set.of(JndiManagerLookupCallsFromJndiLookup.class,
				DirContextLookupsCallsFromJndiManager.class, Log4jPluginAnnotation.class);
		Set<Class<? extends AbstractDetector>> h = Set.of(JndiManagerLookupCallsFromJndiLookup.class,
				DirContextLookupsCallsFromJndiManager.class, Log4jPluginAnnotation.class,
				IsJndiEnabledPropertyAccess.class);
		Set<Class<? extends AbstractDetector>> i = Set.of(JndiManagerLookupCallsFromJndiLookup.class,
				Log4jPluginAnnotation.class, InitialContextLookupsCalls.class, IsJndiEnabledPropertyAccess.class,
				JndiLookupConstructorWithISException.class);
		Set<Class<? extends AbstractDetector>> j = Set.of(JndiManagerLookupCallsFromJndiLookup.class,
				Log4jPluginAnnotation.class, InitialContextLookupsCalls.class, IsJndiEnabledPropertyAccess.class,
				JndiLookupConstructorWithISException.class, IsJndiEnabledPropertyAccessWithJdbcPrefix.class);
		map.put("2.0-alpha1", a);
		map.put("2.0-alpha2", a);
		map.put("2.0-beta1", a);
		map.put("2.0-beta2", a);
		map.put("2.0-beta3", a);
		map.put("2.0-beta4", a);
		map.put("2.0-beta5", a);
		map.put("2.0-beta6", a);
		map.put("2.0-beta7", a);
		map.put("2.0-beta8", a);
		map.put("2.0-beta9", b);
		map.put("2.0-rc1", b);
		map.put("2.0-rc2", c);
		map.put("2.0", c);
		map.put("2.0.1", c);
		map.put("2.0.2", c);
		map.put("2.1", d);
		map.put("2.2", d);
		map.put("2.3", d);
		map.put("2.4", d);
		map.put("2.4.1", d);
		map.put("2.5", d);
		map.put("2.6", d);
		map.put("2.6.1", d);
		map.put("2.6.2", d);
		map.put("2.7", d);
		map.put("2.8", d);
		map.put("2.8.1", d);
		map.put("2.8.2", d);
		map.put("2.9.0", d);
		map.put("2.9.1", d);
		map.put("2.10.0", d);
		map.put("2.11.0", d);
		map.put("2.11.1", d);
		map.put("2.11.2", d);
		map.put("2.12.0", d);
		map.put("2.12.1", d);
		map.put("2.12.2", e);
		map.put("2.12.3", f);
		map.put("2.13.0", d);
		map.put("2.13.1", d);
		map.put("2.13.2", d);
		map.put("2.13.3", d);
		map.put("2.14.0", d);
		map.put("2.14.1", d);
		map.put("2.15.0", g);
		map.put("2.16.0", h);
		map.put("2.17.0", i);
		map.put("2.17.1", j);
		return map;
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
