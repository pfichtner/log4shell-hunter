package com.github.pfichtner.log4shell.scanner;

import static java.util.regex.Pattern.quote;

import java.io.File;
import java.net.MalformedURLException;

import org.approvaltests.scrubbers.RegExScrubber;

public final class Scrubbers {

	private Scrubbers() {
		super();
	}

	public static RegExScrubber basedirScrubber() throws MalformedURLException {
		return new RegExScrubber(quote(baseDir()), "[BASEDIR]/");
	}

	private static String baseDir() throws MalformedURLException {
		return new File("").getAbsoluteFile().toURI().toURL().toString();
	}

}
