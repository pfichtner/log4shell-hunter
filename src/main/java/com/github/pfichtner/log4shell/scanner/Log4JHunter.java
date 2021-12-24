package com.github.pfichtner.log4shell.scanner;

import java.io.File;
import java.io.IOException;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;

public class Log4JHunter {

	private final DetectionCollector detectionCollector;

	public static void main(String... args) throws IOException {
		if (args.length == 0) {
			System.err.println("No filename given");
			System.exit(1);
		} else {
			new Log4JHunter().check(args[0]);
		}
	}

	public Log4JHunter() {
		this(new DetectionCollector(new Log4JDetector()));
	}

	public Log4JHunter(DetectionCollector detectionCollector) {
		this.detectionCollector = detectionCollector;
	}

	public void check(String jar) throws IOException {
		check(new File(jar));
	}

	public void check(File file) throws IOException {
		for (Detection detection : detectionCollector.analyze(file)) {
			System.out.println(file + ": " + detection.format());
		}
	}

}
