package com.github.pfichtner.log4shell.scanner.util;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.github.pfichtner.log4shell.scanner.CVEDetector;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public final class Util {

	private Util() {
		super();
	}

	public static <T> List<T> ignore(T[] elements, List<T> ignore) {
		return ignore(ignore, Arrays.stream(elements));
	}

	public static <T> List<T> ignore(List<T> elements, List<T> ignore) {
		return ignore(ignore, elements.stream());
	}

	public static <T> List<T> ignore(List<T> ignore, Stream<T> stream) {
		return stream.filter(contains(ignore).negate()).collect(toList());
	}

	private static <T> Predicate<T> contains(List<T> elements) {
		return elements::contains;
	}

	public static Map<File, Detections> withDetections(Map<File, Detections> results) {
		return results.entrySet().stream().filter(e -> !e.getValue().getDetections().isEmpty())
				.collect(toMap(Entry::getKey, Entry::getValue));
	}

	public static Map<File, Detections> analyse(Log4jJars log4jJars, Visitor<Detections> sut) throws IOException {
		CVEDetector detector = new CVEDetector(sut);
		Map<File, Detections> results = new HashMap<>();
		for (File log4j : log4jJars) {
			results.put(log4j, detector.analyze(log4j.getAbsolutePath()));
		}
		return results;
	}

}
