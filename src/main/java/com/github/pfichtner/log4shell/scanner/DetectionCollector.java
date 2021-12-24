package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static com.github.pfichtner.log4shell.scanner.io.Files.isClass;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.readClass;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.io.JarReader;
import com.github.pfichtner.log4shell.scanner.io.JarReader.JarReaderVisitor;

public class DetectionCollector {

	private AbstractDetector detector;

	public static class Detection {

		private final Detector detector;
		private final Object resource; // e.g. the JAR
		private final Path filename;
		private final ClassNode classNode;
		private final String description;

		public Detection(Detector detector, Object resource, Path filename, ClassNode in, String description) {
			this.detector = detector;
			this.resource = resource;
			this.filename = filename;
			this.classNode = in;
			this.description = description;
		}

		public Detector getDetector() {
			return detector;
		}

		public Object getResource() {
			return resource;
		}

		public Path getFilename() {
			return filename;
		}

		public ClassNode getIn() {
			return classNode;
		}

		public String getDescription() {
			return description;
		}

		public String format() {
			return description + " found in class " + Type.getObjectType(classNode.name).getClassName()
					+ " in resource " + resource;
		}

		public static List<String> getFormatted(List<Detection> entries) {
			return entries.stream().map(Detection::format).collect(toList());
		}

	}

	public DetectionCollector(AbstractDetector detector) {
		this.detector = detector;
	}

	public List<Detection> analyze(String jar) throws IOException {
		return analyze(new File(jar));
	}

	public List<Detection> analyze(File jar) throws IOException {
		if (!jar.isFile() || !jar.canRead()) {
			throw new IllegalStateException("File " + jar + " not readable");
		}
		return analyze(jar.toURI());
	}

	private List<Detection> analyze(URI uri) throws IOException {
		return analyze(new JarReader(uri));
	}

	private List<Detection> analyze(JarReader jarReader) throws IOException {
		List<Detection> detections = new ArrayList<>();
		jarReader.accept(visitor(jarReader.getFileSystem(), detections));
		return detections;
	}

	private JarReaderVisitor visitor(FileSystem fileSystem, List<Detection> detections) {
		return new JarReaderVisitor() {

			@Override
			public void visit(String resource) {
				detector.visit(resource);
			}

			@Override
			public void visitFile(Path file, byte[] bytes) {
				if (isClass(file)) {
					try {
						ClassNode classNode = readClass(bytes, 0);
						detector.visitClass(file, classNode);
					} catch (Exception e) {
						System.err.println("Error while reading class " + file + ": " + e.getMessage());
					}
				} else {
					detector.visitFile(file, bytes);
					if (isArchive(file.toString())) {
						try {
							new JarReader(file).accept(this);
						} catch (IOException e) {
							throw new RuntimeException(e);
						}
					}
				}
			}

			@Override
			public void end() {
				detector.visitEnd();
				detections.addAll(detector.getDetections());
			}

		};
	}

}
