package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.isClass;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.readClass;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForJndiManagerLookupCalls implements Visitor<Detections> {

	@Override
	public void visit(Detections detections, String filename, byte[] bytes) {
		// TODO do not depend on filename (classname)
		if (isClass(filename) && filename.contains("JndiLookup") && hasJndiManagerLookupCall(bytes)) {
			detections.add(
					"Reference to " + "org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String)" + " found in class " + filename);
		}
	}

	private boolean hasJndiManagerLookupCall(byte[] bytes) {
		return hasJndiManagerLookupCall(readClass(bytes, 0));
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

}
