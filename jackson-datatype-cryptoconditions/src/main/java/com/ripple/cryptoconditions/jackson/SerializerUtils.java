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

import com.ripple.cryptoconditions.Condition;
import com.ripple.cryptoconditions.CryptoConditionWriter;
import com.ripple.cryptoconditions.Fulfillment;
import com.ripple.cryptoconditions.der.DerEncodingException;

import java.util.Base64;
import java.util.Objects;

/**
 * Utility helpers used by various portions of this library.
 */
public class SerializerUtils {

  /**
   * Helper method to encode a {@link Condition} using the supplied Base64 encoder, which might be Base64 or Base64Url,
   * with or without padding.
   *
   * @param encoder   A {@link Base64.Encoder} to encode with.
   * @param condition A {@link Condition} to encode into Base64 using the supplied encoder.
   *
   * @return The base64-encoded version of {@code condition}.
   *
   * @throws RuntimeException if a {@link DerEncodingException} is encountered.
   */
  public static String encodeBase64(final Base64.Encoder encoder, final Condition condition) {
    Objects.requireNonNull(encoder);
    Objects.requireNonNull(condition);

    try {
      return encoder.encodeToString(CryptoConditionWriter.writeCondition(condition));
    } catch (DerEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Helper method to encode a {@link Fulfillment} using the supplied Base64 encoder, which might be Base64 or
   * Base64Url, with or without padding.
   *
   * @param encoder     A {@link Base64.Encoder} to encode with.
   * @param fulfillment A {@link Fulfillment} to encode into Base64 using the supplied encoder.
   *
   * @return The base64-encoded version of {@code fulfillment}.
   *
   * @throws RuntimeException if a {@link DerEncodingException} is encountered.
   */
  public static String encodeBase64(final Base64.Encoder encoder, final Fulfillment fulfillment) {
    Objects.requireNonNull(encoder);
    Objects.requireNonNull(fulfillment);

    try {
      return encoder.encodeToString(CryptoConditionWriter.writeFulfillment(fulfillment));
    } catch (DerEncodingException e) {
      throw new RuntimeException(e);
    }
  }
}
