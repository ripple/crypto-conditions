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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import com.google.common.collect.Lists;
import com.ripple.cryptoconditions.der.DerEncodingException;
import com.ripple.cryptoconditions.helpers.TestKeyFactory;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Unit tests for {@link CryptoConditionReader}.
 */
public class CryptoConditionReaderWriterTest {

  private static PreimageSha256Condition preimageCondition;
  private static PrefixSha256Condition prefixSha256Condition;
  private static RsaSha256Condition rsaCondition;
  private static Ed25519Sha256Condition ed25519Condition;
  private static ThresholdSha256Condition thresholdCondition;

  private static PreimageSha256Fulfillment preimageFulfillment;
  private static PrefixSha256Fulfillment prefixSha256Fulfillment;
  private static RsaSha256Fulfillment rsaFulfillment;
  private static Ed25519Sha256Fulfillment ed25519Fulfillment;
  private static ThresholdSha256Fulfillment thresholdFulfillment;

  /**
   * Setup the test.
   */
  @BeforeClass
  public static void setup() throws Exception {
    Provider bc = new BouncyCastleProvider();
    Security.addProvider(bc);

    final byte[] preimage = "Hello World!".getBytes(Charset.defaultCharset());
    final byte[] prefix = "Ying ".getBytes(Charset.defaultCharset());
    final byte[] message = "Yang".getBytes(Charset.defaultCharset());

    final MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");

    final KeyPair rsaKeyPair = TestKeyFactory.generateRandomRsaKeyPair();
    final KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
    rsaKpg.initialize(new RSAKeyGenParameterSpec(2048, new BigInteger("65537")));
    final Signature rsaSigner = Signature.getInstance("SHA256withRSA/PSS");
    rsaSigner.initSign(rsaKeyPair.getPrivate());
    rsaSigner.update(message);

    final KeyPair edDsaKeyPair = TestKeyFactory.generateRandomEd25519KeyPair();
    Signature edDsaSigner = new EdDSAEngine(sha512Digest);
    edDsaSigner.initSign(edDsaKeyPair.getPrivate());
    edDsaSigner.update(prefix);
    edDsaSigner.update(message);

    preimageCondition = PreimageSha256Fulfillment.from(preimage).getDerivedCondition();
    rsaCondition = RsaSha256Condition.from((RSAPublicKey) rsaKeyPair.getPublic());
    ed25519Condition = Ed25519Sha256Condition.from((EdDSAPublicKey) edDsaKeyPair.getPublic());
    prefixSha256Condition = PrefixSha256Condition.from(prefix, 1000, ed25519Condition);
    thresholdCondition = ThresholdSha256Condition.from(
        2,
        Lists.newArrayList(preimageCondition, rsaCondition, prefixSha256Condition)
    );

    byte[] rsaSignature = rsaSigner.sign();
    byte[] edDsaSignature = edDsaSigner.sign();
    preimageFulfillment = PreimageSha256Fulfillment.from(preimage);
    rsaFulfillment = RsaSha256Fulfillment.from((RSAPublicKey) rsaKeyPair.getPublic(), rsaSignature);
    ed25519Fulfillment =
        Ed25519Sha256Fulfillment.from((EdDSAPublicKey) edDsaKeyPair.getPublic(), edDsaSignature);
    prefixSha256Fulfillment =
        PrefixSha256Fulfillment.from(prefix, 1000, ed25519Fulfillment);
    thresholdFulfillment =
        ThresholdSha256Fulfillment.from(
            Lists.newArrayList(rsaCondition),
            Lists.newArrayList(preimageFulfillment, prefixSha256Fulfillment)
        );
  }

  @Test
  public void readWritePreimageCondition() throws Exception {
    final Condition readAndWrittenCondition = CryptoConditionReader
        .readCondition(CryptoConditionWriter.writeCondition(preimageCondition));
    assertThat(readAndWrittenCondition, is(preimageCondition));
  }

  @Test
  public void readWritePrefixCondition() throws Exception {
    final Condition readAndWrittenCondition = CryptoConditionReader
        .readCondition(CryptoConditionWriter.writeCondition(prefixSha256Condition));
    assertThat(readAndWrittenCondition, is(prefixSha256Condition));
  }

  @Test
  public void readWriteRsaCondition() throws Exception {
    final Condition readAndWrittenCondition = CryptoConditionReader
        .readCondition(CryptoConditionWriter.writeCondition(rsaCondition));
    assertThat(readAndWrittenCondition, is(rsaCondition));
  }

  @Test
  public void readWriteEd25519Condition() throws Exception {
    final Condition readAndWrittenCondition = CryptoConditionReader
        .readCondition(CryptoConditionWriter.writeCondition(ed25519Condition));
    assertThat(readAndWrittenCondition, is(ed25519Condition));
  }

  @Test
  public void testDeserializeLengthOverflow() throws Exception {
    String conditionHexDer = "A406800161810100";
    byte [] conditionBytes = Hex.decode(conditionHexDer);
    Condition readCondition =
        CryptoConditionReader.readCondition(conditionBytes);
    assertThat(readCondition.getFingerprintBase64Url(), is("YQ"));

    // Replace object length (fourth byte 01) with 84 7FFFFFFF
    // 84 is DER encoding for length of length
    // 7FFFFFFF is Integer.MAX_INT
    // Unchecked, this would cause OutOfMemoryError: Requested array size exceeds VM limit
    String overflowConditionHexDer =
        conditionHexDer.substring(0, 6) + "847FFFFFFF" + conditionHexDer.substring(8);

    byte [] overflowConditionBytes = Hex.decode(overflowConditionHexDer);

    try {
      CryptoConditionReader.readCondition(overflowConditionBytes);
      fail("DerEncodingException expected");
    } catch (DerEncodingException encodingException) {
      // expect
      assertThat(encodingException.getMessage(),
          containsString(Integer.MAX_VALUE + "] is larger than allowed"));
    }
  }

  @Test
  public void readWriteThresholdCondition() throws Exception {
    final Condition readAndWrittenCondition = CryptoConditionReader
        .readCondition(CryptoConditionWriter.writeCondition(thresholdCondition));
    assertThat(readAndWrittenCondition, is(thresholdCondition));
  }

  @Test
  public void readWritePreimageFulfillment() throws Exception {
    final Fulfillment readAndWrittenFulfillment = CryptoConditionReader
        .readFulfillment(CryptoConditionWriter.writeFulfillment(preimageFulfillment));
    assertThat(readAndWrittenFulfillment, is(preimageFulfillment));
  }

  @Test
  public void readWritePrefixFulfillment() throws Exception {
    final Fulfillment readAndWrittenFulfillment = CryptoConditionReader
        .readFulfillment(CryptoConditionWriter.writeFulfillment(prefixSha256Fulfillment));
    assertThat(readAndWrittenFulfillment, is(prefixSha256Fulfillment));
  }

  @Test
  public void readWriteRsaFulfillment() throws Exception {
    final Fulfillment readAndWrittenFulfillment = CryptoConditionReader
        .readFulfillment(CryptoConditionWriter.writeFulfillment(rsaFulfillment));
    assertThat(readAndWrittenFulfillment, is(rsaFulfillment));
  }

  @Test
  public void readWriteEd25519Fulfillment() throws Exception {
    final Fulfillment readAndWrittenFulfillment = CryptoConditionReader
        .readFulfillment(CryptoConditionWriter.writeFulfillment(ed25519Fulfillment));
    assertThat(readAndWrittenFulfillment, is(ed25519Fulfillment));
  }

  @Test
  public void readWriteThresholdFulfillment() throws Exception {
    final Fulfillment readAndWrittenFulfillment = CryptoConditionReader
        .readFulfillment(CryptoConditionWriter.writeFulfillment(thresholdFulfillment));
    assertThat(readAndWrittenFulfillment, is(thresholdFulfillment));
  }

}
