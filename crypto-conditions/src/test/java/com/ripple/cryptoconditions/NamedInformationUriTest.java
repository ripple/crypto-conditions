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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import com.google.common.collect.ImmutableMap;
import com.ripple.cryptoconditions.CryptoConditionUri.QueryParams;
import com.ripple.cryptoconditions.NamedInformationUri.HashFunction;
import org.junit.Test;

import java.util.Map;
import java.util.StringJoiner;

/**
 * Unit tests for {@link NamedInformationUri}.
 */
public class NamedInformationUriTest {

  private static final HashFunction HASH_FUNCTION = HashFunction.SHA_256;
  private static final byte[] EMPTY_HASH = new byte[0];
  private static final byte[] HASH = "test".getBytes();
  private static final Map<String, String> EMPTY_QUERY_PARAMS = ImmutableMap.of();

  @Test(expected = NullPointerException.class)
  public void getUri_NullHashFunction() throws Exception {
    try {
      NamedInformationUri.getUri(null, EMPTY_HASH, EMPTY_QUERY_PARAMS);
    } catch (NullPointerException e) {
      throw e;
    }
  }

  @Test(expected = NullPointerException.class)
  public void getUri_NullHash() throws Exception {
    try {
      NamedInformationUri.getUri(HASH_FUNCTION, null, EMPTY_QUERY_PARAMS);
    } catch (NullPointerException e) {
      throw e;
    }
  }

  @Test(expected = NullPointerException.class)
  public void getUri_NullQueryParams() throws Exception {
    try {
      NamedInformationUri.getUri(HASH_FUNCTION, EMPTY_HASH, null);
    } catch (NullPointerException e) {
      throw e;
    }
  }

  @Test
  public void getUri_EmptyQueryParams() throws Exception {
    final String actual = NamedInformationUri.getUri(HASH_FUNCTION, EMPTY_HASH, EMPTY_QUERY_PARAMS)
        .toString();
    assertThat(actual, is("ni:///sha-256;"));
  }

  @Test
  public void getUri_EmptyQueryParamValue() throws Exception {
    final Map<String, String> queryParams = ImmutableMap.of(QueryParams.SUBTYPES, "");
    final String actual = NamedInformationUri.getUri(HASH_FUNCTION, HASH, queryParams)
        .toString();
    assertThat(actual, is("ni:///sha-256;dGVzdA"));
  }

  @Test
  public void getUri_QueryParamOneEmptyValueOneNotEmptyValue() throws Exception {
    final Map<String, String> queryParams = ImmutableMap.of(
        QueryParams.SUBTYPES, "",
        QueryParams.COST, "3"
    );
    final String actual = NamedInformationUri.getUri(HASH_FUNCTION, HASH, queryParams)
        .toString();
    assertThat(actual, is("ni:///sha-256;dGVzdA?cost=3"));
  }

  @Test
  public void getUri_SingleSubtype() throws Exception {
    final String value = new StringJoiner(",")
        .add(CryptoConditionType.PREFIX_SHA256.toString().toLowerCase())
        .toString();
    final Map<String, String> queryParams = ImmutableMap.of(QueryParams.SUBTYPES, value);
    final String actual = NamedInformationUri.getUri(HASH_FUNCTION, HASH, queryParams)
        .toString();
    assertThat(actual, is("ni:///sha-256;dGVzdA?subtypes=prefix-sha-256"));
  }

  @Test
  public void getUri_TwoSubtypes() throws Exception {
    final String value = new StringJoiner(",")
        .add(CryptoConditionType.PREFIX_SHA256.toString().toLowerCase())
        .add(CryptoConditionType.ED25519_SHA256.toString().toLowerCase())
        .toString();
    final Map<String, String> queryParams = ImmutableMap.of(QueryParams.SUBTYPES, value);

    final String actual = NamedInformationUri.getUri(HASH_FUNCTION, HASH, queryParams)
        .toString();
    assertThat(actual, is("ni:///sha-256;dGVzdA?subtypes=prefix-sha-256,ed25519-sha-256"));
  }

  @Test
  public void getUri_ThreeSubtypes() throws Exception {
    final String value = new StringJoiner(",")
        .add(CryptoConditionType.PREFIX_SHA256.toString().toLowerCase())
        .add(CryptoConditionType.ED25519_SHA256.toString().toLowerCase())
        .add(CryptoConditionType.PREIMAGE_SHA256.toString().toLowerCase())
        .toString();
    final Map<String, String> queryParams = ImmutableMap.of(QueryParams.SUBTYPES, value);

    final String actual = NamedInformationUri.getUri(HASH_FUNCTION, HASH, queryParams)
        .toString();
    assertThat(actual,
        is("ni:///sha-256;dGVzdA?subtypes=prefix-sha-256,ed25519-sha-256,preimage-sha-256"));
  }

  @Test
  public void getUri_SpecialCharsInQueryParams() throws Exception {
    final String value = new StringJoiner(",")
        .add(CryptoConditionType.PREFIX_SHA256.toString().toLowerCase())
        .add(CryptoConditionType.ED25519_SHA256.toString().toLowerCase())
        .add(CryptoConditionType.PREIMAGE_SHA256.toString().toLowerCase())
        .add("spa ce")
        .add("!@#$%^&*")
        .toString();
    final Map<String, String> queryParams = ImmutableMap.of(QueryParams.SUBTYPES, value);

    final String actual = NamedInformationUri.getUri(HASH_FUNCTION, HASH, queryParams)
        .toString();
    assertThat(actual,
        is(
            "ni:///sha-256;dGVzdA?subtypes=prefix-sha-256,ed25519-sha-256,preimage-sha-256,spa+ce,"
                + "%21%40%23%24%25%5E%26*"
        ));
  }
}
