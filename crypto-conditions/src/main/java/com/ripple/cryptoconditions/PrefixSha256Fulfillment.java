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

import org.immutables.value.Value.Immutable;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Implementation of a fulfillment based on a prefix, a sub fulfillment, and the SHA-256 function.
 */
public interface PrefixSha256Fulfillment extends Fulfillment<PrefixSha256Condition> {

  /**
   * Constructs an instance of the fulfillment using the supplied data.
   *
   * @param prefix           The prefix associated with the fulfillment.
   * @param maxMessageLength The maximum length of the message allowed by this fulfillment.
   * @param subfulfillment   The subfulfillments that this fulfillment depends on.
   *
   * @return A newly created, immutable instance of {@link PrefixSha256Fulfillment}.
   */
  static PrefixSha256Fulfillment from(
      final byte[] prefix, final long maxMessageLength, final Fulfillment subfulfillment
  ) {
    if (maxMessageLength < 0) {
      throw new IllegalArgumentException("Maximum message length must not be negative!");
    }
    final byte[] prefixInternal = Arrays.copyOf(prefix, prefix.length);
    final String prefixBase64Url = Base64.getUrlEncoder().encodeToString(prefix);
    final PrefixSha256Condition condition = PrefixSha256Condition.from(
        prefix, maxMessageLength, subfulfillment.getDerivedCondition()
    );

    return ImmutablePrefixSha256Fulfillment.builder()
        .type(CryptoConditionType.PREFIX_SHA256)
        .prefix(prefixInternal)
        .prefixBase64Url(prefixBase64Url)
        .maxMessageLength(maxMessageLength)
        .subfulfillment(subfulfillment)
        .derivedCondition(condition)
        .build();
  }

  /**
   * Accessor for the prefix as an array from bytes.
   *
   * @return A byte array containing the prefix for this fulfillment.
   *
   * @deprecated Java 8 does not have the concept from an immutable byte array, so this method allows external callers
   *     to accidentally or intentionally mutate the prefix. As such, this method may be removed in a future version.
   *     Prefer {@link #getPrefixBase64Url()} instead.
   */
  @Deprecated
  byte[] getPrefix();

  /**
   * Accessor for the prefix as a Base64Url-encoded String.
   *
   * @return A {@link String} containing Base64Url characters.
   */
  String getPrefixBase64Url();

  /**
   * <p>Accessor for the maximum message length, which per the spec is the maximum size that a given prefix
   * fulfillment will allow in order validate a given condition against this fulfillment.</p>
   *
   * <p>More specifically, the spec says that a A PREFIX-SHA-256 fulfillment is valid iff, "The size of M (the
   * message), in bytes, is less than or equal to F.maxMessageLength...".</p>
   *
   * @return The maximum message length supported by a prefix fulfillment.
   */
  long getMaxMessageLength();

  Fulfillment getSubfulfillment();

  /**
   * An abstract implementation of {@link PrefixSha256Fulfillment} for use by the
   * <tt>immutables</tt> library.
   *
   * @see "https://immutables.github.org"
   */
  @Immutable
  abstract class AbstractPrefixSha256Fulfillment implements PrefixSha256Fulfillment {

    @Override
    public boolean verify(final Condition condition, final byte[] message) {
      Objects.requireNonNull(condition, "Can't verify a PrefixSha256Fulfillment against a null condition!");
      Objects.requireNonNull(message, "Message must not be null!");

      if (message.length > getMaxMessageLength()) {
        throw new IllegalArgumentException(
            String
                .format("Message length (%s) exceeds maximum message length from (%s).",
                    message.length,
                    getMaxMessageLength()));
      }

      if (!getDerivedCondition().equals(condition)) {
        return false;
      }

      final byte[] decodedPrefix = Base64.getUrlDecoder().decode(getPrefixBase64Url());
      final byte[] prefixedMessage = Arrays.copyOf(
          decodedPrefix, decodedPrefix.length + message.length
      );
      System.arraycopy(message, 0, prefixedMessage, decodedPrefix.length, message.length);

      final Condition subcondition = getSubfulfillment().getDerivedCondition();
      return getSubfulfillment().verify(subcondition, prefixedMessage);
    }

    /**
     * Prints the immutable value {@code PrefixSha256Fulfillment} with attribute values.
     *
     * @return A string representation of the value
     */
    @Override
    public String toString() {
      return "PrefixSha256Fulfillment{"
          + "prefix=" + getPrefixBase64Url()
          + ", maxMessageLength=" + getMaxMessageLength()
          + ", subfulfillment=" + getSubfulfillment()
          + ", type=" + getType()
          + ", derivedCondition=" + getDerivedCondition()
          + "}";
    }
  }
}
