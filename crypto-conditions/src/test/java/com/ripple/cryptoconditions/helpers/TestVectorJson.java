package com.ripple.cryptoconditions.helpers;

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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A class that models the "json" field in the testVectorData file.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TestVectorJson {

  private int maxMessageLength;
  private String modulus;
  private String prefix;
  private String preimage;
  private String publicKey;
  private String signature;
  private TestVectorJson subfulfillment;
  private TestVectorJson[] subfulfillments;
  private int threshold;
  private String type;

  // Debug info
  private String fingerprintContents;
  private String conditionBinary;

  @JsonProperty
  public String getFingerprintContents() {
    return fingerprintContents;
  }

  public void setFingerprintContents(String fingerprintContents) {
    this.fingerprintContents = fingerprintContents;
  }

  @JsonProperty
  public String getConditionBinary() {
    return conditionBinary;
  }

  public void setConditionBinary(String conditionBinary) {
    this.conditionBinary = conditionBinary;
  }

  @JsonProperty
  public int getMaxMessageLength() {
    return maxMessageLength;
  }

  public void setMaxMessageLength(int maxMessageLength) {
    this.maxMessageLength = maxMessageLength;
  }

  @JsonProperty
  public String getModulus() {
    return modulus;
  }

  public void setModulus(String modulus) {
    this.modulus = modulus;
  }

  @JsonProperty
  public String getPrefix() {
    return prefix;
  }

  public void setPrefix(String prefix) {
    this.prefix = prefix;
  }

  @JsonProperty
  public String getPreimage() {
    return preimage;
  }

  public void setPreimage(String preimage) {
    this.preimage = preimage;
  }

  @JsonProperty
  public String getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(String publicKey) {
    this.publicKey = publicKey;
  }

  @JsonProperty
  public String getSignature() {
    return signature;
  }

  public void setSignature(String signature) {
    this.signature = signature;
  }

  @JsonProperty
  public TestVectorJson getSubfulfillment() {
    return subfulfillment;
  }

  public void setSubfulfillment(TestVectorJson subfulfillment) {
    this.subfulfillment = subfulfillment;
  }

  @JsonProperty
  public TestVectorJson[] getSubfulfillments() {
    return subfulfillments;
  }

  public void setSubfulfillments(TestVectorJson[] subfulfillments) {
    this.subfulfillments = subfulfillments;
  }

  @JsonProperty
  public int getThreshold() {
    return threshold;
  }

  public void setThreshold(int threshold) {
    this.threshold = threshold;
  }

  @JsonProperty
  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }
}
