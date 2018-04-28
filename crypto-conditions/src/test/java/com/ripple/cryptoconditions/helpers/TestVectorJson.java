package com.ripple.cryptoconditions.helpers;

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
