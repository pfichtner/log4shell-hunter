package com.github.pfichtner.log4shell.scanner.util;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.useTypeComparator;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static java.util.stream.Collectors.toMap;
import static org.junit.jupiter.api.parallel.ResourceAccessMode.READ;
import static org.junit.jupiter.api.parallel.ResourceAccessMode.READ_WRITE;

import java.io.File;
import java.io.IOException;
import java.lang.annotation.Retention;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.jupiter.api.parallel.ResourceLock;

import com.github.pfichtner.log4shell.scanner.DetectionCollector;
import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.stefanbirkner.systemlambda.Statement;

public final class Util {

	private static final String THREAD_LOCAL_ASM_TYPE_COMPARATOR = "ThreadLocal:AsmTypeComparator";

	@ResourceLock(value = THREAD_LOCAL_ASM_TYPE_COMPARATOR, mode = READ_WRITE)
	@Retention(RUNTIME)
	public static @interface AltersComparatorMode {

	}

	private Util() {
		super();
	}

	public static Map<File, List<Detection>> withDetections(Map<File, List<Detection>> results) {
		return results.entrySet().stream().filter(e -> !e.getValue().isEmpty())
				.collect(toMap(Entry::getKey, Entry::getValue));
	}

	public static Map<File, List<Detection>> analyse(Iterable<File> log4jJars, AbstractDetector sut)
			throws IOException {
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
