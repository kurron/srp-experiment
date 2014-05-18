package org.kurron.srp

import com.nimbusds.srp6.SRP6ClientSession
import com.nimbusds.srp6.SRP6CryptoParams
import com.nimbusds.srp6.SRP6ServerSession
import com.nimbusds.srp6.SRP6VerifierGenerator
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.agreement.srp.SRP6Client
import org.bouncycastle.crypto.agreement.srp.SRP6Server
import org.bouncycastle.crypto.digests.SHA256Digest
import spock.lang.Ignore
import spock.lang.Specification

import java.security.SecureRandom

class Connect2idUnitTest extends Specification {

    static final SecureRandom random = new SecureRandom()

    /**
     * Simulated database.
     */
    Map<String,DatabaseRecord> database = [:]

    def 'exercise SRP6a algorithm'() {

        // these settings must be agreed upon by both server and client
        // the server may make these values available via JSON at run-time a do not have to be hard-coded into the client

        // N = the safe prime number
        def safePrime = SRP6CryptoParams.N_1024

        // g - generator
        def generator = SRP6CryptoParams.g_common

        // H - the hashing function to use
        def hashFunction = 'SHA-1'

        // the length of the salt bytes
        int saltLength = 16

        // the x routine -- how initial exchange is computed
        // H(s|H(P))

        // M1 calculation -- how the evidence message for the client is calculated
        // H(A|B|S)

        // M2 calculation -- how the evidence message for the server is calculated
        // H(A|M1|S)

        given: 'an SRP configuration using specified values'
        SRP6CryptoParams configuration = new SRP6CryptoParams( safePrime, generator, hashFunction )

        and: 'a verifier generator'
        SRP6VerifierGenerator gen = new SRP6VerifierGenerator( configuration )

        and: 'a random salt (s)'
        BigInteger salt = new BigInteger( SRP6VerifierGenerator.generateRandomSalt( saltLength ) )

        and: 'user credentials'
        String username = "alice"
        String password = "secret"

        and: 'a computed verifier (v)'
        BigInteger verifier = gen.generateVerifier( salt, username, password )

        and: 'the client sends username, salt and verifier to the server as part of initial registration'
        database[username] = new DatabaseRecord( salt: salt, verifier: verifier )

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

        and: 'both the client and server can compute a common session key and use that to encrypt traffic'
        def clientKey = clientSession.getSessionKey( true )
        def serverKey = serverSession.getSessionKey( true )
        clientKey == serverKey
    }

    class DatabaseRecord {
        BigInteger salt
        BigInteger verifier
    }
}
