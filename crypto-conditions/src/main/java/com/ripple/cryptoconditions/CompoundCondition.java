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

/**
 * Compound conditions extend regular conditions by defining the subtypes any sub-conditions.
 */
public interface CompoundCondition extends Condition {

  /**
   * <p>Accessor for the sub-types of a compound condition.</p>
   *
   * <p>Note that this set MUST exclude the type of this condition. </p>
   *
   * @return An instance of {@link EnumSet} of type {@link CryptoConditionType}.
   */
  EnumSet<CryptoConditionType> getSubtypes();

}
