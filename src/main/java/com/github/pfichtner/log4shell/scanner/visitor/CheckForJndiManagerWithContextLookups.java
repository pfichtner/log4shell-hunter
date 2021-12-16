package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.methodName;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.nameIsLookup;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.namingContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.throwsNamingException;

import java.nio.file.Path;
import java.util.Optional;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForJndiManagerWithContextLookups implements Visitor<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (filename.toString().endsWith("JndiManager.class")) {
			hasJndiManagerLookupImpl(classNode, nameIsLookup.and(throwsNamingException), namingContext).stream()
					.filter(Optional::isPresent).map(Optional::get).forEach(n -> detections.add(this, filename, n));
		}
	}

	@Override
	public String format(Detection detection) {
		return "Reference to " + methodName((MethodInsnNode) detection.getObject()) + " found in class "
				+ detection.getFilename();
	}

}
