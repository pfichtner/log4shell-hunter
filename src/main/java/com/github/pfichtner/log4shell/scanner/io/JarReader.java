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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class JarReader {

	static class ManagedResource {

		private static class CloseableProxy implements Closeable {

			private final Closeable closeable;
			private final AtomicBoolean closed = new AtomicBoolean();

			public CloseableProxy(Closeable closeable) {
				this.closeable = closeable;
			}

			@Override
			public void close() throws IOException {
				if (closed.compareAndSet(false, true)) {
					closeable.close();
				}
			}

			private boolean isClosed() {
				return closed.get();
			}

		}

		private final FileSystem fileSystem;
		private final AtomicInteger referenceCount = new AtomicInteger(1);
		private final CloseableProxy closeable;

		public ManagedResource(Supplier<FileSystem> supplier) {
			this.fileSystem = supplier.get();
			this.closeable = new CloseableProxy(fileSystem);
		}

		private ManagedResource retain() {
			referenceCount.getAndIncrement();
			return this;
		}

		private void release() throws IOException {
			if (referenceCount.decrementAndGet() == 0) {
				closeable.close();
			}
		}

		private boolean isClosed() {
			return closeable.isClosed();
		}

	}

	private final String resource;
	private final ManagedResource managedResource;

	private static final Map<URI, ManagedResource> managedResources = new ConcurrentHashMap<>();

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

	private static ManagedResource managedResource(Supplier<FileSystem> fileSystemSupplier, URI uri) {
		return managedResources.compute(uri, (__, existing) -> {
			synchronized (managedResources) {
				return existing == null || existing.isClosed() ? new ManagedResource(fileSystemSupplier)
						: existing.retain();
			}
		});
	}

	private JarReader(String resource, ManagedResource managedResource) {
		this.resource = resource;
		this.managedResource = managedResource;
	}

	public FileSystem getFileSystem() {
		return managedResource.fileSystem;
	}

	public void accept(JarReaderVisitor visitor) throws IOException {
		visitor.visit(this.resource);
		try {
			walkFileTree(managedResource.fileSystem.getPath("/"), adapter(visitor));
		} finally {
			synchronized (managedResources) {
				managedResource.release();
			}
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