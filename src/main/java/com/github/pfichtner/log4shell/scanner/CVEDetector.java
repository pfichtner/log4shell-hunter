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
import java.util.List;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.io.JarReader;
import com.github.pfichtner.log4shell.scanner.io.JarReader.JarReaderVisitor;

public class CVEDetector {

	private AbstractDetector detector;

	public static class Detection {

		private final Detector detector;
		private final Path filename;
		private final Object object;

		public Detection(Detector detector, Path filename, Object object) {
			this.detector = detector;
			this.filename = filename;
			this.object = object;
		}

		public String format() {
			return object + " found in class " + filename;
		}

		public Detector getDetector() {
			return detector;
		}

		public Path getFilename() {
			return filename;
		}

		public Object getObject() {
			return object;
		}

		public static List<String> getFormatted(List<Detection> entries) {
			return entries.stream().map(CVEDetector.Detection::format).collect(toList());
		}

	}

	public CVEDetector(AbstractDetector detector) {
		this.detector = detector;
	}

	public Detector getDetector() {
		return detector;
	}

	public void check(String jar) throws IOException {
		check(new File(jar));
	}

	public void check(File file) throws IOException {
		for (CVEDetector.Detection detection : analyze(file)) {
			System.out.println(file + ": " + detection.format());
		}
	}

	public List<Detection> analyze(String jar) throws IOException {
		return analyze(new File(jar));
	}

	public List<Detection> analyze(File jar) throws IOException {
		return analyze(jar.toURI());
	}

	private List<Detection> analyze(URI uri) throws IOException {
		return analyze(new JarReader(uri));
	}

	private List<Detection> analyze(JarReader jarReader) throws IOException {
		jarReader.accept(visitor(jarReader.getFileSystem()));
		return detector.getDetections();
	}

	private JarReaderVisitor visitor(FileSystem fileSystem) {
		return new JarReaderVisitor() {

			@Override
			public void visit(URI jar) {
				detector.visit(jar);
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
							analyze(new JarReader(file));
						} catch (IOException e) {
							throw new RuntimeException(e);
						}
					}
				}
			}

			@Override
			public void end() {
				detector.visitEnd();
			}

		};
	}

}
