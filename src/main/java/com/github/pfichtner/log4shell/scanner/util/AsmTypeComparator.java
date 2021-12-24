package com.github.pfichtner.log4shell.scanner.util;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.toMap;

import java.util.Map;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.MethodNode;

public enum AsmTypeComparator {

	defaultComparator() {
		public boolean isClass(Type type1, Type type2) {
			return type1.equals(type2);
		}

		@Override
		public boolean methodNameIs(MethodNode node, String name) {
			return node.name.equals(name);
		}

		@Override
		public boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected) {
			return expected.equals(toMap(annotationNode));
		}
	},

	repackageComparator() {

		public boolean isClass(Type type1, Type type2) {
			return classname(type1).equals(classname(type2));
		}

		@Override
		public boolean methodNameIs(MethodNode node, String name) {
			return node.name.equals(name);
		}

		private String classname(Type type) {
			String internalName = type.getInternalName();
			int lastIndexOf = internalName.lastIndexOf('/');
			return lastIndexOf > 0 ? internalName.substring(lastIndexOf + 1) : internalName;
		}

		@Override
		public boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected) {
			// TODO values are of type classes we should ignore package names
			return expected.equals(toMap(annotationNode));
		}

	},

	obfuscatorComparator {

		public boolean isClass(Type type1, Type type2) {
			return true;
		}

		@Override
		public boolean methodNameIs(MethodNode node, String name) {
			return true;
		}

		@Override
		public boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected) {
			// keys could be renamed (obfuscated) so we just check the values
			// TODO when values' types are classes we should ignore package names
			return toMap(annotationNode).values().containsAll(expected.values());
		}

	};

	private static final ThreadLocal<AsmTypeComparator> tl = new ThreadLocal<AsmTypeComparator>() {
		@Override
		protected AsmTypeComparator initialValue() {
			return defaultComparator;
		}
	};

	public static AsmTypeComparator typeComparator() {
		return tl.get();
	}

	public static void useTypeComparator(AsmTypeComparator typeComparator) {
		tl.set(typeComparator);
	}

	public abstract boolean isClass(Type type1, Type type2);

	public abstract boolean methodNameIs(MethodNode node, String name);

	public abstract boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected);

}
