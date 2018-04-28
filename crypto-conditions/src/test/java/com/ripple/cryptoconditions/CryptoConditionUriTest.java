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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.common.io.BaseEncoding;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.EnumSet;

/**
 * JUnit tests to exercise the {@link CryptoConditionUri} class. Directly translated from five-bells-condition tests
 */
public class CryptoConditionUriTest {

  @Test
  public void test_parse_preimage_sha_256() throws URISyntaxException {
    URI uri = URI.create(
        "ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?cost=0&fpt=preimage-sha-256");

    Condition condition = CryptoConditionUri.parse(uri);

    assertEquals(CryptoConditionType.PREIMAGE_SHA256, condition.getType());
    assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        BaseEncoding.base16().encode(condition.getFingerprint()));
    assertEquals(0, condition.getCost());
  }

  @Test
  public void test_parse_prefix_sha_256() throws URISyntaxException {
    URI uri = URI.create(
        "ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?cost=0&fpt=prefix-sha-256"
            + "&subtypes=preimage-sha-256,prefix-sha-256");

    Condition condition = CryptoConditionUri.parse(uri);

    assertEquals(CryptoConditionType.PREFIX_SHA256, condition.getType());
    assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        BaseEncoding.base16().encode(condition.getFingerprint()));
    assertEquals(0, condition.getCost());

    assertTrue(condition instanceof CompoundCondition);
    CompoundCondition compoundCondition = (CompoundCondition) condition;
    assertEquals(EnumSet.of(CryptoConditionType.PREIMAGE_SHA256, CryptoConditionType.PREFIX_SHA256),
        compoundCondition.getSubtypes());
  }
}
