package com.github.pfichtner.log4shell.scanner.io;

import java.net.URI;
import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

public interface Detector {

	default String getName() {
		return getClass().getSimpleName();
	}

	default void visit(URI jar) {
	}

	default void visitClass(Path filename, ClassNode classNode) {
	}

	default void visitFile(Path file, byte[] bytes) {
	}

	default void visitEnd() {
	}

}