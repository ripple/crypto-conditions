package com.ripple.cryptoconditions.jackson;

/*-
 * ========================LICENSE_START=================================
 * Crypto-Conditions Jackson
 * %%
 * Copyright (C) 2018 Ripple Labs
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

import static com.ripple.cryptoconditions.jackson.Encoding.BASE64;
import static com.ripple.cryptoconditions.jackson.Encoding.BASE64URL;
import static com.ripple.cryptoconditions.jackson.Encoding.BASE64URL_WITHOUT_PADDING;
import static com.ripple.cryptoconditions.jackson.Encoding.BASE64_WITHOUT_PADDING;
import static com.ripple.cryptoconditions.jackson.Encoding.HEX;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.ripple.cryptoconditions.Ed25519Sha256Fulfillment;
import org.immutables.value.Value;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

/**
 * Validates the functionality of {@link CryptoConditionsModule}.
 */
@RunWith(Parameterized.class)
public class Ed25519Sha256FulfillmentCryptoConditionModuleTest extends AbstractCryptoConditionsModuleTest {

  private static final String ED25519_FULFILLMENT_DER_BYTES_HEX =
      "A464802036AE1B97C577AE6AFB0294E91839FA7B1F9332791B9F2C5D586819025F4A2F1D8140596413BDF20DC96833E9AEA3A12BA04F3579"
          + "0C249617AD5A7BB5DC404E22AD1C20DBE413C113ED45D4E2BB73AB5E48B90FA7E379C55D08423E2100CC23E2210A";

  private static final String ED25519_FULFILLMENT_DER_BYTES_BASE64
      = "pGSAIDauG5fFd65q+wKU6Rg5+nsfkzJ5G58sXVhoGQJfSi8dgUBZZBO98g3JaDPprqOhK6BPNXkMJJYXrVp7tdxATiKtHCDb5BPBE+1F1OK7c6"
      + "teSLkPp+N5xV0IQj4hAMwj4iEK";

  private static final String ED25519_FULFILLMENT_DER_BYTES_BASE64_WITHOUTPADDING
      = "pGSAIDauG5fFd65q+wKU6Rg5+nsfkzJ5G58sXVhoGQJfSi8dgUBZZBO98g3JaDPprqOhK6BPNXkMJJYXrVp7tdxATiKtHCDb5BPBE+1F1OK7c6"
      + "teSLkPp+N5xV0IQj4hAMwj4iEK";

  private static final String ED25519_FULFILLMENT_DER_BYTES_BASE64_URL
      = "pGSAIDauG5fFd65q-wKU6Rg5-nsfkzJ5G58sXVhoGQJfSi8dgUBZZBO98g3JaDPprqOhK6BPNXkMJJYXrVp7tdxATiKtHCDb5BPBE-1F1OK7c6"
      + "teSLkPp-N5xV0IQj4hAMwj4iEK";

  private static final String ED25519_FULFILLMENT_DER_BYTES_BASE64_URL_WITHOUTPADDING
      = "pGSAIDauG5fFd65q-wKU6Rg5-nsfkzJ5G58sXVhoGQJfSi8dgUBZZBO98g3JaDPprqOhK6BPNXkMJJYXrVp7tdxATiKtHCDb5BPBE-1F1OK7c6"
      + "teSLkPp-N5xV0IQj4hAMwj4iEK";

  private static Ed25519Sha256Fulfillment FULFILLMENT = constructEd25519Fulfillment();

  /**
   * Required-args Constructor (used by JUnit's parameterized test annotation).
   *
   * @param encodingToUse        A {@link Encoding} to use for each test run.
   * @param expectedEncodedValue A {@link String} encoded in the above encoding to assert against.
   */
  public Ed25519Sha256FulfillmentCryptoConditionModuleTest(
      final Encoding encodingToUse, final String expectedEncodedValue
  ) {
    super(encodingToUse, expectedEncodedValue);
  }

  /**
   * Get test parameters.
   *
   * @return the parameters for the tests
   */
  @Parameters
  public static Collection<Object[]> data() {
    // Create and return a Collection of Object arrays. Each element in each array is a parameter
    // to the CryptoConditionsModuleFulfillmentTest constructor.
    return Arrays.asList(new Object[][]{
        {HEX, ED25519_FULFILLMENT_DER_BYTES_HEX},
        {BASE64, ED25519_FULFILLMENT_DER_BYTES_BASE64},
        {BASE64_WITHOUT_PADDING, ED25519_FULFILLMENT_DER_BYTES_BASE64_WITHOUTPADDING},
        {BASE64URL, ED25519_FULFILLMENT_DER_BYTES_BASE64_URL},
        {BASE64URL_WITHOUT_PADDING, ED25519_FULFILLMENT_DER_BYTES_BASE64_URL_WITHOUTPADDING}
    });
  }

  @Test
  public void testSerializeDeserialize() throws IOException {
    final Ed25519FulfillmentContainer expectedContainer = ImmutableEd25519FulfillmentContainer
        .builder()
        .fulfillment(FULFILLMENT)
        .build();

    final String json = objectMapper.writeValueAsString(expectedContainer);
    assertThat(json, is(
        String.format("{\"fulfillment\":\"%s\"}", expectedEncodedValue)
    ));

    final Ed25519FulfillmentContainer actualAddressContainer = objectMapper
        .readValue(json, Ed25519FulfillmentContainer.class);

    assertThat(actualAddressContainer, is(expectedContainer));
    assertThat(actualAddressContainer.getFulfillment(), is(FULFILLMENT));
  }

  @Value.Immutable
  @JsonSerialize(as = ImmutableEd25519FulfillmentContainer.class)
  @JsonDeserialize(as = ImmutableEd25519FulfillmentContainer.class)
  interface Ed25519FulfillmentContainer {

    @JsonProperty("fulfillment")
    Ed25519Sha256Fulfillment getFulfillment();
  }
}
