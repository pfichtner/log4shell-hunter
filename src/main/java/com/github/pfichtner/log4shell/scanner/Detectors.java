package com.github.pfichtner.log4shell.scanner;

import static java.util.Collections.unmodifiableList;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupWithNamingContextLookupsWithoutThrowingException;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerWithDirContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerWithNamingContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.RefsToInitialContextLookups;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public final class Detectors {

	public static class Multiplexer implements Detector<Detections> {
		private final List<Detector<Detections>> detectors;
	
		public Multiplexer(List<Detector<Detections>> detectors) {
			this.detectors = detectors;
		}
	
		@Override
		public void visitFile(Detections detections, Path file, byte[] bytes) {
			for (Detector<Detections> detector : detectors) {
				detector.visitFile(detections, file, bytes);
			}
		}
	
		@Override
		public void visitClass(Detections detections, Path filename, ClassNode classNode) {
			for (Detector<Detections> detector : detectors) {
				detector.visitClass(detections, filename, classNode);
			}
		}
	
		@Override
		public void visitEnd(Detections detections) {
			for (Detector<Detections> detector : detectors) {
				detector.visitEnd(detections);
			}
		}
	
	}

	private static final List<Detector<Detections>> detectors = unmodifiableList(Arrays.asList( //
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

	public static List<Detector<Detections>> allDetectors() {
		return detectors;
	}

	public static Detector<Detections> multiplexer(List<Detector<Detections>> allDetectors) {
		return new Multiplexer(allDetectors);
	}

}
