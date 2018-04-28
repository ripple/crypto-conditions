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

/**
 * A helper class used in the RSA tests to hold JSON data for testing purposes.
 */
public class CaseJson {

  private String message;
  private String salt;
  private String signature;

  @JsonProperty
  public String getMessage() {
    return message;
  }

  public CaseJson setMessage(String message) {
    this.message = message;
    return this;
  }

  @JsonProperty
  public String getSalt() {
    return salt;
  }

  public CaseJson setSalt(String salt) {
    this.salt = salt;
    return this;
  }

  @JsonProperty
  public String getSignature() {
    return signature;
  }

  public CaseJson setSignature(String signature) {
    this.signature = signature;
    return this;
  }
}
