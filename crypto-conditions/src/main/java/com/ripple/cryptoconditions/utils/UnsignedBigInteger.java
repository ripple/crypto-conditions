package com.ripple.cryptoconditions.utils;

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

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Utility class for encoding and decoding a {@link BigInteger} as a byte array without sign
 * prefix.
 *
 * @author adrianhopebailie
 */
public class UnsignedBigInteger {

  /**
   * Get a positive {@link BigInteger} encoded as a byte array with no sign-prefix.
   *
   * @param value a positive BigInteger value
   * @return input value encoded as a byte[] with leading 0x00 prefix trimmed.
   * @throws IllegalArgumentException if the input value is &lt; 0
   */
  public static byte[] toUnsignedByteArray(BigInteger value) {

    if (value.compareTo(BigInteger.ZERO) < 0) {
      throw new IllegalArgumentException("Value must be >= 0.");
    }

    byte[] signedValue = value.toByteArray();
    if (signedValue[0] == 0x00) {
      return Arrays.copyOfRange(signedValue, 1, signedValue.length);
    }

    return signedValue;
  }

  /**
   * Get {@link BigInteger} from byte encoding that assumes the value is  &gt; 0.
   *
   * @param value a byte encoded integer
   * @return a positive {@link BigInteger}
   */
  public static BigInteger fromUnsignedByteArray(byte[] value) {
    return new BigInteger(1, value);
  }

}
