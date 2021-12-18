package com.github.pfichtner.log4shell.scanner;

import static java.util.Collections.unmodifiableList;

import java.net.URI;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupWithNamingContextLookupsWithoutThrowingException;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerWithDirContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerWithNamingContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.RefsToInitialContextLookups;

public final class Detectors {

	public static class Multiplexer extends AbstractDetector {

		private final List<AbstractDetector> detectors;

		public Multiplexer(List<AbstractDetector> detectors) {
			this.detectors = detectors;
		}
		
		public List<AbstractDetector> getMultiplexed() {
			return detectors;
		}

		@Override
		public void visit(URI jar) {
			for (AbstractDetector detector : detectors) {
				detector.visit(jar);
			}
		}

		@Override
		public void visitFile(Path file, byte[] bytes) {
			for (AbstractDetector detector : detectors) {
				detector.visitFile(file, bytes);
			}
		}

		@Override
		public void visitClass(Path filename, ClassNode classNode) {
			for (AbstractDetector detector : detectors) {
				detector.visitClass(filename, classNode);
			}
		}

		@Override
		public void visitEnd() {
			for (AbstractDetector detector : detectors) {
				detector.visitEnd();
			}
		}

		@Override
		public Detections getDetections() {
			Detections result = new Detections();
			detectors.stream().map(d -> d.getDetections()).map(Detections::getEntries).flatMap(Collection::stream)
					.forEach(c -> result.add(c.getDetector(), c.getFilename(), c.getObject()));
			return result;
		}

	}

	private static final List<AbstractDetector> detectors = unmodifiableList(Arrays.asList( //
			new JndiManagerLookupCalls(), //
			new JndiManagerWithNamingContextLookups(), //
			new JndiLookupWithNamingContextLookupsWithoutThrowingException(), //
			new JndiManagerWithDirContextLookups(), //
			new Log4jPluginAnnotation(), //
			new RefsToInitialContextLookups(), //
			new IsJndiEnabledPropertyAccess() //
	));

	private Detectors() {
		super();
	}

	public static Multiplexer allDetectors() {
		return multiplexer(detectors);
	}

	public static Multiplexer multiplexer(List<AbstractDetector> allDetectors) {
		return new Multiplexer(allDetectors);
	}

}
