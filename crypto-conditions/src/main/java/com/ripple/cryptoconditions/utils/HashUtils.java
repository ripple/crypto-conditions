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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Base interface for all *-SHA-256 conditions.
 */
public interface HashUtils {

  /**
   * Constructs the fingerprint from this condition by taking the SHA-256 digest from the contents
   * from this condition, per the crypto-conditions RFC.
   *
   * @param fingerprintContents A byte array containing the unhashed contents from this condition as
   *                            assembled per the rules from the RFC.
   *
   * @return A byte array containing the hashed fingerprint.
   */
  static byte[] hashFingerprintContents(final byte[] fingerprintContents) {
    Objects.requireNonNull(fingerprintContents);
    try {
      final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      return messageDigest.digest(fingerprintContents);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
