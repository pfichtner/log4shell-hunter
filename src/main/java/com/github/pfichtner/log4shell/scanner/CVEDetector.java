package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.isClass;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.readClass;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.github.pfichtner.log4shell.scanner.io.JarReader;
import com.github.pfichtner.log4shell.scanner.io.JarReader.JarReaderVisitor;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CVEDetector {

	private List<Visitor<Detections>> visitors;

	public static class Detections {

		private final List<String> detections = new ArrayList<>();

		public void add(Visitor<?> detector, Path filename, String detection) {
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

	@SafeVarargs
	public CVEDetector(Visitor<Detections>... visitors) {
		this(Arrays.asList(visitors));
	}

	public CVEDetector(List<Visitor<Detections>> visitors) {
		this.visitors = visitors;
	}

	public void check(String jar) throws IOException {
		for (String string : analyze(jar).getDetections()) {
			System.out.println(string);
		}
	}

	public Detections analyze(String jar) throws IOException {
		Detections detections = new Detections();
		new JarReader(jar).accept(new JarReaderVisitor() {
			@Override
			public void visitFile(Path file, byte[] bytes) {
				for (Visitor<Detections> visitor : visitors) {
					if (isClass(file)) {
						visitor.visitClass(detections, file, readClass(bytes, 0));
					} else {
						visitor.visitFile(detections, file, bytes);
					}
				}
			}
		});
		return detections;
	}

}
