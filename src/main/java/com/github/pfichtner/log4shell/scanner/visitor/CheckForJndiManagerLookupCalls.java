package com.github.pfichtner.log4shell.scanner.visitor;

import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;

import java.nio.file.Path;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

/**
 * Detects calls in classes that are named <code>JndiLookup</code> to
 * org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String)
 */
public class CheckForJndiManagerLookupCalls implements Visitor<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (filename.toString().endsWith("JndiLookup.class") && hasJndiManagerLookupCall(classNode)) {
			detections.add(this, filename);
		}
	}

	private boolean hasJndiManagerLookupCall(ClassNode classNode) {
		for (MethodNode methodNode : classNode.methods) {
			for (AbstractInsnNode insnNode : methodNode.instructions) {
				if (methodNode.name.equals("lookup"))
					if (insnNode instanceof MethodInsnNode) {
						MethodInsnNode methodInsnNode = (MethodInsnNode) insnNode;

						// TODO JndiManager could be renamed and obfuscated too, how could we detect if
						// this is a reference to
						// https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java
						// TODO lookup throws javax.naming.NamingException;

						// visitMethodInsn(INVOKEVIRTUAL,
						// "org/apache/logging/log4j/core/net/JndiManager", "lookup",
						// "(Ljava/lang/String;)Ljava/lang/Object;", false);
						if ("(Ljava/lang/String;)Ljava/lang/Object;".equals(methodInsnNode.desc)
								&& "org/apache/logging/log4j/core/net/JndiManager".equals(methodInsnNode.owner)
								&& "lookup".equals(methodInsnNode.name)
								&& INVOKEVIRTUAL == methodInsnNode.getOpcode()) {
							return true;
						}
					}
			}
		}
		return false;
	}

	@Override
	public String format(Path filename, Object data) {
		return "Reference to " + "org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String)"
				+ " found in class " + filename;
	}

}
