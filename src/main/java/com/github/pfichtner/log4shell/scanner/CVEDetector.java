package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static com.github.pfichtner.log4shell.scanner.io.Files.isClass;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.readClass;
import static java.util.Collections.unmodifiableList;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.io.JarReader;
import com.github.pfichtner.log4shell.scanner.io.JarReader.JarReaderVisitor;

public class CVEDetector {

	private List<Detector<Detections>> detectors;

	public static class Detections {

		public static class Detection {

			private final Detector<?> detector;
			private final Path filename;
			private final Object object;

			public Detection(Detector<?> detector, Path filename, Object object) {
				this.detector = detector;
				this.filename = filename;
				this.object = object;
			}

			public String format() {
				return detector.format(this) + " found in class " + filename;
			}

			public Detector<?> getDetector() {
				return detector;
			}

			public Object getObject() {
				return object;
			}

		}

		private final List<Detection> detections = new ArrayList<>();

		public void add(Detector<?> detector, Path filename) {
			add(detector, filename, null);
		}

		public void add(Detector<?> detector, Path filename, Object object) {
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
	public CVEDetector(Detector<Detections>... detectors) {
		this(Arrays.asList(detectors));
	}

	public CVEDetector(List<Detector<Detections>> detectors) {
		this.detectors = unmodifiableList(new ArrayList<>(detectors));
	}

	public List<Detector<Detections>> getDetectors() {
		return detectors;
	}

	public void check(String jar) throws IOException {
		check(new File(jar));
	}

	public void check(File file) throws IOException {
		for (Detection detection : analyze(file).getDetections()) {
			System.out.println(file + ": " + detection.format());
		}
	}

	public Detections analyze(String jar) throws IOException {
		return analyze(new File(jar));
	}

	public Detections analyze(File jar) throws IOException {
		return analyze(jar.toURI());
	}

	private Detections analyze(URI uri) throws IOException {
		return analyze(new JarReader(uri), new Detections());
	}

	private Detections analyze(JarReader jarReader, Detections detections) throws IOException {
		jarReader.accept(visitor(detections, jarReader.getFileSystem()));
		return detections;
	}

	private JarReaderVisitor visitor(Detections detections, FileSystem fileSystem) {
		return new JarReaderVisitor() {
			@Override
			public void visitFile(Path file, byte[] bytes) {
				if (isClass(file)) {
					try {
						ClassNode classNode = readClass(bytes, 0);
						for (Detector<Detections> detector : detectors) {
							detector.visitClass(detections, file, classNode);
						}
					} catch (Exception e) {
						System.err.println("Error while reading class " + file + ": " + e.getMessage());
					}

				} else {
					for (Detector<Detections> detector : detectors) {
						detector.visitFile(detections, file, bytes);
					}
					if (isArchive(file.toString())) {
						try {
							analyze(new JarReader(file), detections);
						} catch (IOException e) {
							throw new RuntimeException(e);
						}
					}
				}
			}
		};
	}

}
