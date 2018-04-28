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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * POJO class that defines a test vector containing pre-calculated and verified test data used to test the various
 * crypto-condition implementations.
 */
public class TestVector {

  private String name;
  private TestVectorJson json;
  private long cost;
  private List<String> subtypes;
  private String fingerprintContents;
  private String fulfillment;
  private String conditionBinary;
  private String conditionUri;
  private String message;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @JsonProperty
  public TestVectorJson getJson() {
    return json;
  }

  public void setJson(TestVectorJson json) {
    this.json = json;
  }

  @JsonProperty
  public long getCost() {
    return cost;
  }

  public void setCost(long cost) {
    this.cost = cost;
  }

  @JsonProperty
  public List<String> getSubtypes() {
    return subtypes;
  }

  public void setSubtypes(List<String> subtypes) {
    this.subtypes = subtypes;
  }


  @JsonProperty
  public String getFingerprintContents() {
    return fingerprintContents;
  }

  public void setFingerprintContents(String fingerprintContents) {
    this.fingerprintContents = fingerprintContents;
  }

  @JsonProperty
  public String getFulfillment() {
    return fulfillment;
  }

  public void setFulfillment(String fulfillment) {
    this.fulfillment = fulfillment;
  }

  @JsonProperty
  public String getConditionBinary() {
    return conditionBinary;
  }

  public void setConditionBinary(String conditionBinary) {
    this.conditionBinary = conditionBinary;
  }

  @JsonProperty
  public String getConditionUri() {
    return conditionUri;
  }

  public void setConditionUri(String conditionUri) {
    this.conditionUri = conditionUri;
  }

  @JsonProperty
  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  @Override
  public String toString() {
    return getName();
  }
}
