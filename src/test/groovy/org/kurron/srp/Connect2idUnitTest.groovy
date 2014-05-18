package org.kurron.srp

import com.nimbusds.srp6.Hex
import com.nimbusds.srp6.SRP6ClientSession
import com.nimbusds.srp6.SRP6CryptoParams
import com.nimbusds.srp6.SRP6ServerSession
import com.nimbusds.srp6.SRP6VerifierGenerator
import spock.lang.Specification

class Connect2idUnitTest extends Specification {

    /**
     * Simulated database.
     */
    Map<String,DatabaseRecord> database = [:]

    def 'exercise SRP6a algorithm'() {

        // these settings must be agreed upon by both server and client
        // the server may make these values available via JSON at run-time a do not have to be hard-coded into the client

        // N = the safe prime number
        def N = SRP6CryptoParams.N_256

        // g - generator
        def g = SRP6CryptoParams.g_common

        // H - the hashing function to use
        def H = 'SHA-256'

        // the length of the salt bytes
        int saltLength = 16

        // the x routine -- how initial exchange is computed
        // H(s|H(P))

        // M1 calculation -- how the evidence message for the client is calculated
        // H(A|B|S)

        // M2 calculation -- how the evidence message for the server is calculated
        // H(A|M1|S)

        given: 'a common SRP configuration'
        def configuration = new SRP6CryptoParams( N, g, H )

        and: 'a verifier generator'
        def generator = new SRP6VerifierGenerator( configuration )

        and: 'a random salt (s)'
        def salt = new BigInteger( SRP6VerifierGenerator.generateRandomSalt( saltLength ) )

        and: 'user credentials'
        def username = "alice"
        def password = "secret"

        and: 'a computed verifier (v)'
        def verifier = generator.generateVerifier( salt, username, password )

        and: 'the client sends username, salt and verifier to the server as part of initial registration'
        // pretend we are sending hex encoded values over the network as part of a JSON payload
        def hexSalt = Hex.encode( salt )
        def hexVerifier = Hex.encode( verifier )
        database[username] = new DatabaseRecord( salt: Hex.decodeToBigInteger( hexSalt ), verifier: Hex.decodeToBigInteger( hexVerifier ) )

        when: 'the client requests authentication'
        def clientSession = new SRP6ClientSession()
        clientSession.step1( username, password )
        // in a real scenario, the username is sent over the network to the server

        then: "server responds to the client with the server public value ‘B’ and password salt ‘s’"
        def serverSession = new SRP6ServerSession( configuration )
        // look up salt and verifier for the provided identity
        def databaseEntry = database[username]
        def B = serverSession.step1( username, databaseEntry.salt, databaseEntry.verifier )

        and: "the clients computes the client public value ‘A’ and evidence message ‘M1’, sending those to the server"
        def credentials = clientSession.step2( configuration, databaseEntry.salt, B )

        and: 'the service calculates its evidence message M2 and sends that to the client'
        def M2 = serverSession.step2( credentials.A, credentials.M1 )

        and: "client validates the server evidence message ‘M2’ after which user and server are mutually authenticated"
        clientSession.step3( M2 )

        and: 'both the client and server can compute a common session key and use that to encrypt traffic, if desired'
        def clientKey = clientSession.getSessionKey( true )
        def serverKey = serverSession.getSessionKey( true )
        clientKey == serverKey
    }

    class DatabaseRecord {
        BigInteger salt
        BigInteger verifier
    }
}
