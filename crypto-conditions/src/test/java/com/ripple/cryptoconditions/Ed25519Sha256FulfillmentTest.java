package com.ripple.cryptoconditions;

/*-
 * ========================LICENSE_START=================================
 * Crypto Conditions
 * %%
 * Copyright (C) 2016 - 2018 Ripple Labs
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */

import static com.ripple.cryptoconditions.helpers.TestFulfillmentFactory.MESSAGE;
import static com.ripple.cryptoconditions.helpers.TestFulfillmentFactory.constructEd25519Sha256Fulfillment;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.ripple.cryptoconditions.helpers.TestKeyFactory;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hamcrest.CoreMatchers;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Random;

/**
 * Unit tests for {@link Ed25519Sha256Fulfillment}.
 */
public class Ed25519Sha256FulfillmentTest extends AbstractCryptoConditionTest {

    /**
     * Need to add BouncyCastle so we have a provider that supports SHA256withED25519/PSS signatures
     */
    static {
        Provider bc = new BouncyCastleProvider();
        Security.addProvider(bc);
    }

    /**
     * Tests concurrently creating an instance of {@link Ed25519Sha256Fulfillment}. This test validates the fix for
     * Github issue #40 where construction of this class was not thread-safe.
     *
     * @see "https://github.com/interledger/java-crypto-conditions/issues/40"
     * @see "https://github.com/junit-team/junit4/wiki/multithreaded-code-and-concurrency"
     */
    @Test
    public void testConstructionUsingMultipleThreads() throws Exception {
        final Runnable runnableTest = () -> {
            final Ed25519Sha256Fulfillment ed25519Sha256Fulfillment =
                constructEd25519Sha256Fulfillment(
                    TestKeyFactory.generateRandomEd25519KeyPair()
                );

            assertThat(ed25519Sha256Fulfillment.getType(), is(CryptoConditionType.ED25519_SHA256));
            assertThat(ed25519Sha256Fulfillment
                .verify(ed25519Sha256Fulfillment.getDerivedCondition(), MESSAGE.getBytes()), is(true));
        };

        // Run single-threaded...
        this.runConcurrent(1, runnableTest);
        // Run multi-threaded...
        this.runConcurrent(runnableTest);
    }

    @Test(expected = NullPointerException.class)
    public final void testFromWithNullPublicKey() {
        Ed25519Sha256Fulfillment.from(null, "".getBytes());
    }

    @Test(expected = NullPointerException.class)
    public final void testFromWithNullSignature() {
        Ed25519Sha256Fulfillment
            .from((EdDSAPublicKey) TestKeyFactory.generateRandomEd25519KeyPair().getPublic(), null);
    }

    /**
     * Ed25519Sha256Fulfillment currently requires a 64-byte signature in order to properly interact with the eddsa
     * library. This test validates various iterations of signature length.
     */
    @Test
    public final void testFromWithEmptySignature() {

        for (int i = 0; i < 64; i++) {
            byte[] randomSignatureBytes = new byte[i];
            new Random().nextBytes(randomSignatureBytes);
            try {
                Ed25519Sha256Fulfillment
                    .from((EdDSAPublicKey) TestKeyFactory.generateRandomEd25519KeyPair().getPublic(),
                        randomSignatureBytes);
                fail("Should have thrown an IllegalArgumentException!");
            } catch (IllegalArgumentException e) {
                assertThat(e.getMessage(), is("Signature length must be 64 bytes for Ed25519Sha256Fulfillments!"));
            }
        }

        // Only Signature lengths of 64 bytes are allowed...
        {
            byte[] randomSignatureBytes = new byte[64];
            new Random().nextBytes(randomSignatureBytes);
            final Ed25519Sha256Fulfillment validFulfillment = Ed25519Sha256Fulfillment
                .from((EdDSAPublicKey) TestKeyFactory.generateRandomEd25519KeyPair().getPublic(), randomSignatureBytes);
            assertThat(validFulfillment.verify(validFulfillment.getDerivedCondition(), randomSignatureBytes),
                is(false));
        }

        for (int i = 65; i < 128; i++) {
            byte[] randomSignatureBytes = new byte[i];
            new Random().nextBytes(randomSignatureBytes);
            try {
                Ed25519Sha256Fulfillment
                    .from((EdDSAPublicKey) TestKeyFactory.generateRandomEd25519KeyPair().getPublic(),
                        randomSignatureBytes);
                fail("Should have thrown an IllegalArgumentException!");
            } catch (IllegalArgumentException e) {
                assertThat(e.getMessage(), is("Signature length must be 64 bytes for Ed25519Sha256Fulfillments!"));
            }
        }
    }

    @Test
    public final void testValidate() {
        final KeyPair ed25519KeyPair = TestKeyFactory.generateRandomEd25519KeyPair();
        final Ed25519Sha256Fulfillment actual
            = constructEd25519Sha256Fulfillment(ed25519KeyPair);
        assertTrue("Invalid condition",
            actual.verify(actual.getDerivedCondition(), MESSAGE.getBytes()));
    }

    @Test
    public final void testValidateWithEmptyMessage() {
        final KeyPair ed25519KeyPair = TestKeyFactory.generateRandomEd25519KeyPair();
        final Ed25519Sha256Fulfillment actual;
        try {
            final MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
            final Signature edDsaSigner = new EdDSAEngine(sha512Digest);
            edDsaSigner.initSign(ed25519KeyPair.getPrivate());
            // Empty message...
            byte[] edDsaSignature = edDsaSigner.sign();

            actual = constructEd25519Sha256Fulfillment(
                (EdDSAPublicKey) ed25519KeyPair.getPublic(), edDsaSignature
            );
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        assertTrue("Invalid condition", actual.verify(actual.getDerivedCondition()));
    }

    @Test
    public void equalsHashcode() {
        final Ed25519Sha256Fulfillment fulfillment1
            = constructEd25519Sha256Fulfillment(
            TestKeyFactory.generateRandomEd25519KeyPair()
        );
        final Ed25519Sha256Fulfillment fulfillment2 = fulfillment1;
        final Ed25519Sha256Fulfillment fulfillment3
            = constructEd25519Sha256Fulfillment(
            TestKeyFactory.generateRandomEd25519KeyPair()
        );

        assertThat(fulfillment1.equals(fulfillment1), CoreMatchers.is(true));
        assertThat(fulfillment2.equals(fulfillment2), CoreMatchers.is(true));
        assertThat(fulfillment3.equals(fulfillment3), CoreMatchers.is(true));

        assertThat(fulfillment1.equals(fulfillment2), CoreMatchers.is(true));
        assertThat(fulfillment1.equals(fulfillment3), CoreMatchers.is(false));

        assertThat(fulfillment2.equals(fulfillment1), CoreMatchers.is(true));
        assertThat(fulfillment2.equals(fulfillment3), CoreMatchers.is(false));

        assertThat(fulfillment3.equals(fulfillment1), CoreMatchers.is(false));
        assertThat(fulfillment3.equals(fulfillment2), CoreMatchers.is(false));

        assertThat(fulfillment1.hashCode(), CoreMatchers.is(fulfillment2.hashCode()));
        assertThat(fulfillment1.hashCode() == fulfillment3.hashCode(), CoreMatchers.is(false));
    }

    @Test
    public void testToString() {
        final Ed25519Sha256Fulfillment fulfillment =
            constructEd25519Sha256Fulfillment(
                TestKeyFactory.constructEd25519KeyPair()
            );

        assertThat(fulfillment.toString().contains("Ed25519Sha256Fulfillment"), is(true));
        assertThat(fulfillment.toString().endsWith(
            "signature=stnlHPRuMupW2hJzgaeTm06wVGz8d7QUQdIJPLJ9fczNimaNtg3e53BCgVsTT1hATPQEn64K8-"
                + "BIOWyb5faNBA==, type=ED25519-SHA-256, condition=Ed25519Sha256Condition{type=ED25519-SHA-256, "
                + "fingerprint=aJ5kk1zn2qrQQO5QhYZXoGigv0Y5rSafiV3BUM1F9hM, cost=131072}}"
        ), is(true));
    }
}
