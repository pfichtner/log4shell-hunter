package com.github.pfichtner.log4shell.scanner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.github.pfichtner.log4shell.scanner.io.JarScanner;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CVEDetector {

	public static class Detections {

		private final List<String> detections = new ArrayList<>();

		public void add(String detection) {
			this.detections.add(detection);
		}

		public List<String> getDetections() {
			return detections;
		}

		@Override
		public String toString() {
			return "Detections [detections=" + detections + "]";
		}

	}

	private final JarScanner<Detections> jarScanner;

	@SafeVarargs
	public CVEDetector(Visitor<Detections>... visitors) {
		this(Arrays.asList(visitors));
	}

	public CVEDetector(List<Visitor<Detections>> visitors) {
		this.jarScanner = new JarScanner<Detections>(visitors);
	}

	public void check(String jar) throws IOException {
		for (String string : analyze(jar).getDetections()) {
			System.out.println(string);
		}
	}

	public Detections analyze(String jar) throws IOException {
		Detections detections = new Detections();
		this.jarScanner.visitArchive(jar, detections);
		return detections;
	}

}
