package com.github.pfichtner.log4shell.scanner;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Collectors.toUnmodifiableSet;
import static java.util.stream.IntStream.range;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;

public class Fingerprint {

	private static final Pattern log4jPattern = Pattern.compile("log4j-core-(.+)\\.jar");
	private static final Map<String, Set<Class<? extends AbstractDetector>>> mapping = mapping();

	private static Map<String, Set<Class<? extends AbstractDetector>>> mapping() {
		Map<String, Set<Class<? extends AbstractDetector>>> map = new HashMap<>();
		List<Class<AbstractDetector>> classes = null;
		for (String csvLine : readCsv()) {
			List<String> columns = Arrays.asList(csvLine.split("\\,"));
			String key = columns.get(0);
			List<String> values = columns.subList(1, columns.size());
			if (classes == null) {
				classes = createClassesFromHeader(values);
			} else {
				map.put(cutLog4Jcore(key), column(values, classes));
			}
		}
		return map;
	}

	private static Set<Class<? extends AbstractDetector>> column(List<String> columns,
			List<Class<AbstractDetector>> classes) {
		return range(0, columns.size()).filter(i -> "X".equals(columns.get(i))).mapToObj(i -> classes.get(i))
				.collect(toSet());
	}

	private static List<Class<AbstractDetector>> createClassesFromHeader(List<String> columns) {
		return columns.stream().map(Fingerprint::loadClass).collect(toList());
	}

	private static List<String> readCsv() {
		return new BufferedReader(new InputStreamReader(fingerprints(), UTF_8)).lines().collect(toList());
	}

	private static InputStream fingerprints() {
		return Fingerprint.class.getResourceAsStream("fingerprints.csv");
	}

	private static String cutLog4Jcore(String name) {
		Matcher matcher = log4jPattern.matcher(name);
		return matcher.matches() ? matcher.group(1) : name;
	}

	@SuppressWarnings("unchecked")
	private static Class<AbstractDetector> loadClass(String simpleClassName) {
		try {
			return (Class<AbstractDetector>) Class
					.forName(AbstractDetector.class.getPackageName() + "." + simpleClassName);
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		}
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
