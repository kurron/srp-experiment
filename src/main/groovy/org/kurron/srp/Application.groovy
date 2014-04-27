package org.kurron.srp

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.context.annotation.ComponentScan

@SuppressWarnings( 'GrMethodMayBeStatic' )
@EnableAutoConfiguration
@ComponentScan( ['com.kurron.srp'] )
class Application {

    /**
     * This gets called when we are running from the command-line.
     * @param args any arguments to the program.
     */
    static void main( String[] args ) {
        SpringApplication.run( Application, args )
    }
}
