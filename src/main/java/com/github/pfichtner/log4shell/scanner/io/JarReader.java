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
import java.nio.file.FileVisitor;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;

public class JarReader {

	private final String resource;
	private FileSystem fileSystem;

	public static interface JarReaderVisitor {
		
		default void visit(String resource) {
			// noop
		}

		default void visitDirectory(Path dir) {
			// noop
		}

		default void visitFile(Path file, byte[] bytes) {
			// noop
		}

		default void end() {
			// noop
		}

	}

	public JarReader(File jar) throws IOException {
		this(jar.toURI());
	}

	public JarReader(URI jar) throws IOException {
		this.resource = jar.toString();
		this.fileSystem = newFileSystem(URI.create("jar:file:" + jar.getPath()), zipProperties());
	}

	public JarReader(Path path) throws IOException {
		this.resource = path.toString();
		this.fileSystem = newFileSystem(path, null);
	}

	public FileSystem getFileSystem() {
		return fileSystem;
	}

	public void accept(JarReaderVisitor visitor) throws IOException {
		visitor.visit(this.resource);
		try {
			walkFileTree(fileSystem.getPath("/"), adapter(visitor));
		} finally {
			fileSystem.close();
			visitor.end();
		}
	}

	private FileVisitor<Path> adapter(JarReaderVisitor visitor) {
		return new SimpleFileVisitor<Path>() {

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

		};
	}

	private static Map<String, String> zipProperties() {
		Map<String, String> zipProperties = new HashMap<>();
		zipProperties.put("create", "false");
		zipProperties.put("encoding", "UTF-8");
		return zipProperties;
	}

}