package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.isClass;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.readClass;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.JarReader;
import com.github.pfichtner.log4shell.scanner.io.JarReader.JarReaderVisitor;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CVEDetector {

	private List<Visitor<Detections>> visitors;

	public static class Detections {

		public static class Detection {

			private final Visitor<?> detector;
			private final Path filename;
			private final Object object;

			public Detection(Visitor<?> detector, Path filename, Object object) {
				this.detector = detector;
				this.filename = filename;
				this.object = object;
			}

			public String format() {
				return detector.format(filename, object);
			}

		}

		private final List<Detection> detections = new ArrayList<>();

		public void add(Visitor<?> detector, Path filename) {
			add(detector, filename, null);
		}

		public void add(Visitor<?> detector, Path filename, Object object) {
			this.detections.add(new Detection(detector, filename, object));
		}

		public List<Detection> getDetections() {
			return detections;
		}

		public List<String> getFormatted() {
			return detections.stream().map(Detection::format).collect(toList());
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
		for (Detection detection : analyze(jar).getDetections()) {
			System.out.println(detection.format());
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
