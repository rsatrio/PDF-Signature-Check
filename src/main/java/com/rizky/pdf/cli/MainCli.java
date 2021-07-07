package com.rizky.pdf.cli;

import java.time.Duration;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;

public class MainCli {
    
    
    public static void main(String[] args)  {
        Logger log1=LoggerFactory.getLogger(MainCli.class);
        Instant start=Instant.now();
        new CommandLine(new RootCommandTools()).execute(args);
        log1.info("Elapsed Time: {} ms",Duration.between(start, Instant.now()).toMillis());
               
    }

}
