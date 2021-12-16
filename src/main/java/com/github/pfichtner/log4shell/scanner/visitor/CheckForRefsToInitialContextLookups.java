package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.initialContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.nameIsLookup;

import java.nio.file.Path;
import java.util.Optional;
import java.util.stream.Stream;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForRefsToInitialContextLookups implements Visitor<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		refsToContext(classNode, detections, filename).forEach(d -> detections.add(this, filename, d));
	}

	private Stream<String> refsToContext(ClassNode classNode, Detections detections, Path filename) {
		return hasJndiManagerLookupImpl(classNode, nameIsLookup, initialContext).stream().filter(Optional::isPresent)
				.map(Optional::get).map(s -> s.concat(" found in class " + filename));
	}

}
