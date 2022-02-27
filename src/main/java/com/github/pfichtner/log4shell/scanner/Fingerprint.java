package com.github.pfichtner.log4shell.scanner;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Collectors.toUnmodifiableSet;
import static java.util.stream.IntStream.range;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
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

	private static final Charset utf8 = Charset.forName("UTF-8");
	private static final Pattern log4jPattern = Pattern.compile("log4j-core-(.+)\\.jar");
	private static final Map<String, Set<Class<? extends AbstractDetector>>> mapping = mapping();

	private static Map<String, Set<Class<? extends AbstractDetector>>> mapping() {
		Map<String, Set<Class<? extends AbstractDetector>>> map = new HashMap<>();
		Class<AbstractDetector>[] classes = null;
		for (String csvLine : readCsv()) {
			String[] columns = csvLine.split("\\,");
			if (classes == null) {
				classes = createClassesFromHeader(columns);
			} else {
				map.put(cutLog4Jcore(columns[0]), column(columns, classes));
			}
		}
		return map;
	}

	private static Set<Class<? extends AbstractDetector>> column(String[] columns,
			Class<AbstractDetector>[] detectors) {
		return range(1, columns.length).filter(i -> "X".equals(columns[i])).mapToObj(i -> detectors[i])
				.collect(toSet());
	}

	@SuppressWarnings("unchecked")
	private static Class<AbstractDetector>[] createClassesFromHeader(String[] string) {
		Class<AbstractDetector>[] header = new Class[string.length];
		for (int i = 1; i < string.length; i++) {
			header[i] = loadClass(string[i]);
		}
		return header;
	}

	private static List<String> readCsv() {
		return new BufferedReader(new InputStreamReader(fingerprints(), utf8)).lines().collect(toList());
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
