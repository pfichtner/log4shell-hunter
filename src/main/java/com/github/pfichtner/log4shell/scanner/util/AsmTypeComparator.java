package com.github.pfichtner.log4shell.scanner.util;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.classType;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.extractValues;

import java.util.Map;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public enum AsmTypeComparator {

	/**
	 * Class names must match exactly.<br>
	 * foo.Name == bar.Name -> false <br>
	 * foo.Name == foo.OtherName -> false <br>
	 */
	defaultComparator() {

		public boolean isClass(Type type1, Type type2) {
			return type1.equals(type2);
		}

		@Override
		public boolean methodNameIs(String name1, String name2) {
			return name1.equals(name2);
		}

		@Override
		public boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected) {
			return expected.equals(extractValues(annotationNode));
		}
	},

	/**
	 * Simple class names must match exactly but packages not.<br>
	 * foo.Name == bar.Name -> true <br>
	 * foo.Name == foo.OtherName -> false <br>
	 */
	repackageComparator() {

		public boolean isClass(Type type1, Type type2) {
			return simpleName(type1).equals(simpleName(type2));
		}

		@Override
		public boolean methodNameIs(String name1, String name2) {
			return name1.equals(name2);
		}

		private String simpleName(Type type) {
			return simpleName(type.getInternalName());
		}

		private String simpleName(String internalName) {
			// TODO if package is java/javax: do NOT ignore package names but then classes
			// could be hidden (a class foo/Bar.class could have been renamed to
			// java/Something.class)
			int lastIndexOf = internalName.lastIndexOf('/');
			return lastIndexOf > 0 ? internalName.substring(lastIndexOf + 1) : internalName;
		}

		@Override
		public boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected) {
			// TODO values are of type classes we should ignore package names
			return expected.equals(extractValues(annotationNode));
		}

	},

	/**
	 * Nothing has to match, ever time true.<br>
	 * foo.Name == bar.Name -> true <br>
	 * foo.Name == foo.OtherName -> true <br>
	 */
	obfuscatorComparator {

		// TODO if type is java/javax: do NOT ignore package names but then classes
		// could be hidden (a class foo/Bar.class could have been renamed to
		// java/Something.class)
		public boolean isClass(Type type1, Type type2) {
			return true;
		}

		@Override
		public boolean methodNameIs(String name1, String name2) {
			return true;
		}

		@Override
		public boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected) {
			// keys could be renamed (obfuscated) so we just check the values
			// TODO when values' types are classes we should ignore package names
			return extractValues(annotationNode).values().containsAll(expected.values());
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

	public boolean isClass(ClassNode classNode, Type type2) {
		return isClass(classType(classNode), type2);
	}

	public abstract boolean isClass(Type type1, Type type2);

	public boolean methodNameIs(MethodNode node, String name) {
		return methodNameIs(node.name, name);
	}

	public abstract boolean methodNameIs(String name1, String name2);

	public abstract boolean annotationIs(AnnotationNode annotationNode, Map<Object, Object> expected);

}
