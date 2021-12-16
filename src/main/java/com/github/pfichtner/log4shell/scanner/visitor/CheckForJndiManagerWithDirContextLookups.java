package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.dirContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.nameIsLookup;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.throwsNamingException;

import java.nio.file.Path;
import java.util.Optional;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForJndiManagerWithDirContextLookups implements Visitor<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (filename.toString().endsWith("JndiManager.class")) {
			hasJndiManagerLookupImpl(classNode, nameIsLookup.and(throwsNamingException), dirContext).stream()
					.filter(Optional::isPresent).map(Optional::get).map(s -> s.concat(" found in class " + filename))
					.forEach(d -> detections.add(this, filename, d));
		}
	}

}
