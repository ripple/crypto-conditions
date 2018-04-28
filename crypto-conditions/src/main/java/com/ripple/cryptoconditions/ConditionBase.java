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

import com.ripple.cryptoconditions.der.DerEncodingException;

/**
 * This class provides shared, concrete logic for all conditions.
 */
public abstract class ConditionBase<C extends Condition> implements Condition {

  /**
   * <p>An implementation of {@link Comparable#compareTo(Object)} to conform to the {@link
   * Comparable} interface.</p>
   *
   * <p>This implementation merely loops through the bytes of each encoded condition and returns the
   * result of that comparison.</p>
   *
   * @param that A {@link Condition} to compare against this condition.
   *
   * @return a negative integer, zero, or a positive integer as this object is less than, equal to,
   *     or greater than the specified object.
   */
  @Override
  public final int compareTo(Condition that) {
    try {
      byte[] c1encoded = CryptoConditionWriter.writeCondition(this);
      byte[] c2encoded = CryptoConditionWriter.writeCondition(that);

      int minLength = Math.min(c1encoded.length, c2encoded.length);
      for (int i = 0; i < minLength; i++) {
        int result = Integer.compareUnsigned(c1encoded[i], c2encoded[i]);
        if (result != 0) {
          return result;
        }
      }
      return c1encoded.length - c2encoded.length;

    } catch (DerEncodingException e) {
      throw new RuntimeException(e);
    }
  }
}
