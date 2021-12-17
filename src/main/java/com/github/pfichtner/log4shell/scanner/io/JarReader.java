package com.github.pfichtner.log4shell.scanner.io;

import static java.nio.file.FileSystems.newFileSystem;
import static java.nio.file.FileVisitResult.CONTINUE;
import static java.nio.file.Files.copy;
import static java.nio.file.Files.walkFileTree;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;

public class JarReader {

	public static class JarReaderVisitor {

		public void visitDirectory(Path dir) {
			// noop
		}

		public void visitFile(Path file, byte[] bytes) {
			// noop
		}

	}

	private final File jar;

	public JarReader(File jar) {
		this.jar = jar;
	}

	public void accept(JarReaderVisitor visitor) throws IOException {
		try (FileSystem zipfs = newFileSystem(URI.create("jar:file:" + jar.toURI().getPath()), zipProperties())) {
			walkFileTree(zipfs.getPath("/"), new SimpleFileVisitor<Path>() {

				@Override
				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
					visitor.visitDirectory(dir);
					return CONTINUE;
				}

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					ByteArrayOutputStream content = new ByteArrayOutputStream();
					copy(file, content);
					visitor.visitFile(file, content.toByteArray());
					return CONTINUE;
				}

			});
		}
	}

	private static Map<String, String> zipProperties() {
		Map<String, String> zipProperties = new HashMap<>();
		zipProperties.put("create", "false");
		zipProperties.put("encoding", "UTF-8");
		return zipProperties;
	}

}