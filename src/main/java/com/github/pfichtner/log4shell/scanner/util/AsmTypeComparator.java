package com.github.pfichtner.log4shell.scanner.util;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.MethodNode;

/**
 * Preparation for comparing types on different levels: default, repackaged,
 * obuscated. Instances of this class can be retrieved via ThreadLocal.
 */
public interface AsmTypeComparator {

	AsmTypeComparator defaultComparator = new AsmTypeComparator() {
		public boolean isClass(Type type1, Type type2) {
			return type1.equals(type2);
		}

		@Override
		public boolean methodNameIs(MethodNode node, String name) {
			return node.name.equals(name);
		}
	};

	AsmTypeComparator repackageComparator = new AsmTypeComparator() {

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

	};

	AsmTypeComparator obfuscatorComparator = new AsmTypeComparator() {

		public boolean isClass(Type type1, Type type2) {
			return true;
		}

		@Override
		public boolean methodNameIs(MethodNode node, String name) {
			return true;
		}

	};

	boolean isClass(Type type1, Type type2);

	boolean methodNameIs(MethodNode node, String name);

}
