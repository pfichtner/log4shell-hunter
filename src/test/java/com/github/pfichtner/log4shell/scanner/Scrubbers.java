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
		File userDirectory = new File("").getAbsoluteFile();
		return new RegExScrubber(quote(userDirectory.toURI().toURL().toString()), "[BASEDIR]/");
	}

}
