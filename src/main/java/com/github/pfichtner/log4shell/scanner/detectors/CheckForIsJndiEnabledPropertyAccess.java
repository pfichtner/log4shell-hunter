package com.github.pfichtner.log4shell.scanner.detectors;

import java.nio.file.Path;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class CheckForIsJndiEnabledPropertyAccess implements Detector<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		for (MethodNode methodNode : classNode.methods) {
			// LdcInsn("log4j2.enableJndi");
			// Insn(ICONST_0);
			if (hasAccessToProperty(methodNode.instructions)) {
				detections.add(this, filename);
			}
		}
	}

	private boolean hasAccessToProperty(InsnList instructions) {
		AbstractInsnNode insnNode = instructions.getFirst();
		while (insnNode != null) {
			if (insnNode instanceof LdcInsnNode && "log4j2.enableJndi".equals(((LdcInsnNode) insnNode).cst)) {
				if (insnNode.getNext() instanceof InsnNode) {
					InsnNode next = (InsnNode) insnNode.getNext();
					if (next.getOpcode() == Opcodes.ICONST_0) {
						return true;
					}
				}
			}
			insnNode = insnNode.getNext();
		}
		return false;
	}

	@Override
	public String format(Detection detection) {
		return "log4j2.enableJndi access";
	}

}
