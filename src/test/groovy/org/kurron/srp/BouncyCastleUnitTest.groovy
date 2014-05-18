package org.kurron.srp

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.agreement.srp.SRP6Client
import org.bouncycastle.crypto.agreement.srp.SRP6Server
import org.bouncycastle.crypto.digests.SHA256Digest
import spock.lang.Ignore
import spock.lang.Specification

import java.security.SecureRandom

/**
 * Created by vagrant on 4/26/14.
 */
@Ignore( 'Cannot find full examples.  Having difficulty getting verifier to work.' )
class BouncyCastleUnitTest extends Specification {
    static final SecureRandom random = new SecureRandom()

    def 'exercise simple math'() {
        // pre-shared by user and host
        def safePrime = new BigInteger( '5' )
        def generator = new BigInteger( '2' )
        def hashFunction = digest()

        given: 'a valid user'
        def user = new SRP6Client()

        user.init( safePrime, generator, hashFunction, random )

        and: 'a valid host'
        def host = new SRP6Server()
        def verifier = randomNumber() // supposed to be cryptographically computed
        host.init( safePrime, generator, verifier, hashFunction, random )

        when: 'an authentication attempt is made'
        def hostCredentials = host.generateServerCredentials()
        def userCredentials = user.generateClientCredentials( salt(), identity(), password() )
        def sharedSecret = host.calculateSecret( userCredentials )
        def verificationMessage = user.calculateSecret( hostCredentials )

        then: 'authentication is confirmed'
        sharedSecret == verificationMessage
    }

    BigInteger randomNumber() {
        def buffer = new byte[128]
        random.nextBytes( buffer )
        new BigInteger( buffer )
    }

    Digest digest() {
        new SHA256Digest()
    }

    byte[] salt() {
        def salt = new byte[128]
        random.nextBytes( salt )
        salt
    }

    byte[] identity() {
        def salt = new byte[128]
        random.nextBytes( salt )
        salt
    }

    byte[] password() {
        def password = new byte[128]
        random.nextBytes( password )
        password
    }
}
