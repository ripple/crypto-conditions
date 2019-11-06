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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.ripple.cryptoconditions.ThresholdSha256Condition;
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
public class TresholdSha256ConditionCryptoConditionModuleTest extends
    AbstractCryptoConditionsModuleTest {

  private static final String THRESHOLD_CONDITION_DER_BYTES_HEX =
      "A22A8020ECF2CD7971471204029D36833A1D548D3AB476B8957876B7494D8058A0AE4E6C81025066820204D0";
  private static final String THRESHOLD_CONDITION_DER_BYTES_BASE64
      = "oiqAIOzyzXlxRxIEAp02gzodVI06tHa4lXh2t0lNgFigrk5sgQJQZoICBNA=";
  private static final String THRESHOLD_CONDITION_DER_BYTES_BASE64_WITHOUTPADDING
      = "oiqAIOzyzXlxRxIEAp02gzodVI06tHa4lXh2t0lNgFigrk5sgQJQZoICBNA";
  private static final String THRESHOLD_CONDITION_DER_BYTES_BASE64_URL
      = "oiqAIOzyzXlxRxIEAp02gzodVI06tHa4lXh2t0lNgFigrk5sgQJQZoICBNA=";
  private static final String THRESHOLD_CONDITION_DER_BYTES_BASE64_URL_WITHOUTPADDING
      = "oiqAIOzyzXlxRxIEAp02gzodVI06tHa4lXh2t0lNgFigrk5sgQJQZoICBNA";

  private static ThresholdSha256Condition CONDITION = constructThresholdCondition();

  /**
   * Required-args Constructor (used by JUnit's parameterized test annotation).
   *
   * @param encodingToUse        A {@link Encoding} to use for each test run.
   * @param expectedEncodedValue A {@link String} encoded in the above encoding to assert against.
   */
  public TresholdSha256ConditionCryptoConditionModuleTest(
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
    // to the CryptoConditionsModuleConditionTest constructor.
    return Arrays.asList(new Object[][]{
        {Encoding.HEX, THRESHOLD_CONDITION_DER_BYTES_HEX},
        {Encoding.BASE64, THRESHOLD_CONDITION_DER_BYTES_BASE64},
        {Encoding.BASE64_WITHOUT_PADDING, THRESHOLD_CONDITION_DER_BYTES_BASE64_WITHOUTPADDING},
        {Encoding.BASE64URL, THRESHOLD_CONDITION_DER_BYTES_BASE64_URL},
        {Encoding.BASE64URL_WITHOUT_PADDING, THRESHOLD_CONDITION_DER_BYTES_BASE64_URL_WITHOUTPADDING}
    });
  }

  @Test
  public void testSerializeDeserialize() throws IOException {
    final ThresholdConditionContainer expectedContainer = ImmutableThresholdConditionContainer
        .builder()
        .condition(CONDITION)
        .build();

    final String json = objectMapper.writeValueAsString(expectedContainer);
    assertThat(json, is(
        String.format("{\"condition\":\"%s\"}", expectedEncodedValue)
    ));

    final ThresholdConditionContainer actualAddressContainer = objectMapper
        .readValue(json, ThresholdConditionContainer.class);

    assertThat(actualAddressContainer, is(expectedContainer));
    assertThat(actualAddressContainer.getCondition(), is(CONDITION));
  }

  @Value.Immutable
  @JsonSerialize(as = ImmutableThresholdConditionContainer.class)
  @JsonDeserialize(as = ImmutableThresholdConditionContainer.class)
  interface ThresholdConditionContainer {

    @JsonProperty("condition")
    ThresholdSha256Condition getCondition();
  }

}
