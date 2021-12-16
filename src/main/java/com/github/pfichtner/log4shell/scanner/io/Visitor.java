package com.github.pfichtner.log4shell.scanner.io;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;

public interface Visitor<T> {

	default String getName() {
		return getClass().getSimpleName();
	}

	default void visitClass(T detections, Path filename, ClassNode classNode) {
	}

	default void visitFile(Detections detections, Path file, byte[] bytes) {
	}

	String format(Detection detection);

}