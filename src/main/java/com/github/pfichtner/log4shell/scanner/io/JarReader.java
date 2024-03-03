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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class JarReader {

	static class SharedFilesytem {

		private final URI uri;
		private final FileSystem fileSystem;
		private final AtomicInteger referenceCount = new AtomicInteger(1);

		public SharedFilesytem(URI uri, Supplier<FileSystem> supplier) {
			this.uri = uri;
			this.fileSystem = supplier.get();
		}

		private SharedFilesytem increment() {
			referenceCount.incrementAndGet();
			return this;
		}

		private SharedFilesytem decrement() {
			if (referenceCount.decrementAndGet() > 0) {
				return this;
			}
			try {
				fileSystem.close();
				return null;
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

	}

	private final String resource;
	private final SharedFilesytem sharedFilesytem;

	private static final Map<URI, SharedFilesytem> sharedFilesystems = new ConcurrentHashMap<>();

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

	public JarReader(File jar) {
		this(jar.toURI());
	}

	public JarReader(URI jar) {
		this(jar.toString(), managedResource(() -> {
			try {
				return newFileSystem(URI.create("jar:file:" + jar.getPath()), zipProperties());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}, jar));
	}

	public JarReader(Path file) {
		this(file.toString(), managedResource(() -> {
			try {
				return newFileSystem(file, null);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}, file.toUri()));
	}

	private static SharedFilesytem managedResource(Supplier<FileSystem> fileSystemSupplier, URI uri) {
		return sharedFilesystems.compute(uri,
				(__, s) -> s == null ? new SharedFilesytem(uri, fileSystemSupplier) : s.increment());
	}

	private JarReader(String resource, SharedFilesytem sharedFilesytem) {
		this.resource = resource;
		this.sharedFilesytem = sharedFilesytem;
	}

	public FileSystem getFileSystem() {
		return sharedFilesytem.fileSystem;
	}

	public void accept(JarReaderVisitor visitor) throws IOException {
		visitor.visit(this.resource);
		try {
			walkFileTree(sharedFilesytem.fileSystem.getPath("/"), adapter(visitor));
		} finally {
			// We cannot use computeIfPresent here because we need to ensure that both the
			// decrement operation and the subsequent resource closing operation are
			// performed atomically. Using computeIfPresent would not guarantee atomicity
			// across these two operations.
			sharedFilesystems.compute(sharedFilesytem.uri, (__, s) -> s == null ? null : s.decrement());
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
				visitor.visitFile(file, readBytes(file));
				return CONTINUE;
			}

			private byte[] readBytes(Path file) throws IOException {
				ByteArrayOutputStream content = new ByteArrayOutputStream();
				copy(file, content);
				return content.toByteArray();
			}

		};
	}

	private static Map<String, String> zipProperties() {
		return Map.of( //
				"create", "false", //
				"encoding", "UTF-8" //
		);
	}

}