package com.github.pfichtner.log4shell.scanner.io;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodName;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

public interface Detector<T> {

	default String getName() {
		return getClass().getSimpleName();
	}

	default void visitClass(T detections, Path filename, ClassNode classNode) {
	}

	default void visitFile(T detections, Path file, byte[] bytes) {
	}

	default void visitEnd(T detections) {
	}

	static class Reference {

		private final MethodInsnNode node;

		public Reference(MethodInsnNode node) {
			this.node = node;
		}

		@Override
		public String toString() {
			return "Reference to " + methodName(node);
		}

	}

	static Reference referenceTo(MethodInsnNode node) {
		return new Reference(node);
	}

}