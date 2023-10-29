package com.github.pfichtner.log4shell.scanner.util;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.useTypeComparator;
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

import com.github.pfichtner.log4shell.scanner.DetectionCollector;
import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.stefanbirkner.systemlambda.Statement;

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

	public static Map<File, List<Detection>> withDetections(Map<File, List<Detection>> results) {
		return results.entrySet().stream().filter(e -> !e.getValue().isEmpty())
				.collect(toMap(Entry::getKey, Entry::getValue));
	}

	public static Map<File, List<Detection>> analyse(Log4jJars log4jJars, AbstractDetector sut) throws IOException {
		DetectionCollector detector = new DetectionCollector(sut);
		Map<File, List<Detection>> results = new HashMap<>();
		for (File log4j : log4jJars) {
			results.put(log4j, detector.analyze(log4j.getAbsolutePath()));
		}
		return results;
	}

	public static void captureAndRestoreAsmTypeComparator(Statement statement) throws Exception {
		AsmTypeComparator oldComparator = typeComparator();
		try {
			statement.execute();
		} finally {
			useTypeComparator(oldComparator);
		}
	}

}
