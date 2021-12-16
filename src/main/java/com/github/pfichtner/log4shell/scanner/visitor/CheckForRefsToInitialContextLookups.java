package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.methodName;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.initialContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.nameIsLookup;

import java.nio.file.Path;
import java.util.Optional;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForRefsToInitialContextLookups implements Visitor<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		hasJndiManagerLookupImpl(classNode, nameIsLookup, initialContext).stream().filter(Optional::isPresent)
				.map(Optional::get).forEach(n -> detections.add(this, filename, n));
	}

	@Override
	public String format(Detection detection) {
		return "Reference to " + methodName((MethodInsnNode) detection.getObject());
	}

}
