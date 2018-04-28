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

import java.util.EnumSet;
import java.util.List;

/**
 * A helper class for asserting crypto conditions.
 */
public class CryptoConditionAssert {

  /**
   * Asserts the the set of rsa given are equal.
   *
   * @param message  A detail message to record if the assertion fails.
   * @param expected A list of expected condition rsa.
   * @param actual   A set of condition rsa to compare against the ones expected.
   */
  public static void assertSetOfTypesIsEqual(
      final String message, final List<String> expected, final EnumSet<CryptoConditionType> actual
  ) {
    final EnumSet<CryptoConditionType> expectedSet = CryptoConditionType
        .getEnumOfTypesFromString(String.join(",", expected.toArray(new String[expected.size()])));

    if (!expectedSet.containsAll(actual)) {
      throw new AssertionError(message + " - expected does not contain all values from actual.");
    }
    expectedSet.removeAll(actual);
    if (!expectedSet.isEmpty()) {
      throw new AssertionError(message + " - expected contains values not in actual.");
    }
  }

}
