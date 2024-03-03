package com.github.pfichtner.log4shell.scanner.io;

import static java.nio.file.FileSystems.newFileSystem;
import static java.nio.file.FileVisitResult.CONTINUE;
import static java.nio.file.Files.copy;
import static java.nio.file.Files.walkFileTree;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
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

	private static class SharedCloseable<T extends Closeable> {

		private final T closeable;
		private final AtomicInteger referenceCount = new AtomicInteger(1);

		public SharedCloseable(T closeable) {
			this.closeable = closeable;
		}

		public SharedCloseable<T> increment() {
			referenceCount.incrementAndGet();
			return this;
		}

		public SharedCloseable<T> decrement() {
			if (referenceCount.decrementAndGet() > 0) {
				return this;
			}
			try {
				closeable.close();
				return null;
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

	}

	private static final Map<URI, SharedCloseable<FileSystem>> sharedCloseables = new ConcurrentHashMap<>();

	private final URI uri;
	private final String resource;
	private final Supplier<FileSystem> filesystemSupplier;

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
		this(jar.toString(), jar, () -> {
			try {
				return newFileSystem(URI.create("jar:file:" + jar.getPath()), zipProperties());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		});
	}

	public JarReader(Path file) {
		this(file.toString(), file.toUri(), () -> {
			try {
				return newFileSystem(file, null);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		});
	}

	private JarReader(String resource, URI uri, Supplier<FileSystem> filesystemSupplier) {
		this.resource = resource;
		this.uri = uri;
		this.filesystemSupplier = filesystemSupplier;
	}

	public void accept(JarReaderVisitor visitor) throws IOException {
		visitor.visit(resource);
		SharedCloseable<FileSystem> sharedCloseable = sharedCloseables.compute(uri,
				(__, c) -> c == null ? new SharedCloseable<>(filesystemSupplier.get()) : c.increment());
		try {
			walkFileTree(sharedCloseable.closeable.getPath("/"), adapter(visitor));
		} finally {
			sharedCloseables.computeIfPresent(uri, (__, c) -> c.decrement());
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