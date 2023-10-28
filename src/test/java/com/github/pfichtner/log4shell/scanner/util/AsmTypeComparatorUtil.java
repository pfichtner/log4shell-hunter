package com.github.pfichtner.log4shell.scanner.util;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.useTypeComparator;

import org.junit.jupiter.api.function.Executable;

public final class AsmTypeComparatorUtil {

	private AsmTypeComparatorUtil() {
		super();
	}

	public static void restoreAsmTypeComparator(Executable executable) {
		AsmTypeComparator oldComparator = typeComparator();
		try {
			try {
				executable.execute();
			} catch (Throwable t) {
				throw new RuntimeException(t);
			}
		} finally {
			useTypeComparator(oldComparator);
		}
	}

}
