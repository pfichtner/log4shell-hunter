package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.methodName;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.dirContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.nameIsLookup;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.throwsNamingException;

import java.nio.file.Path;
import java.util.Optional;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForJndiManagerWithDirContextLookups implements Visitor<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (filename.toString().endsWith("JndiManager.class")) {
			hasJndiManagerLookupImpl(classNode, nameIsLookup.and(throwsNamingException), dirContext).stream()
					.filter(Optional::isPresent).map(Optional::get).forEach(n -> detections.add(this, filename, n));
		}
	}

	@Override
	public String format(Path filename, Object data) {
		return "Reference to " + methodName((MethodInsnNode) data) + " found in class " + filename;
	}

}
