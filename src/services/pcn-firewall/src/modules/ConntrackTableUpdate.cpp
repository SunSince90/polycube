/*
 * Copyright 2017 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../Firewall.h"
#include "datapaths/Firewall_ConntrackTableUpdate_dp.h"

Firewall::ConntrackTableUpdate::ConntrackTableUpdate(const int &index,
    const ChainNameEnum &direction, Firewall &outer)
    : Firewall::Program(firewall_code_conntracktableupdate, index,
                        direction, outer) {
  load();
}

Firewall::ConntrackTableUpdate::~ConntrackTableUpdate() {}

std::string Firewall::ConntrackTableUpdate::getCode() {
  std::string noMacroCode = code;

  /*Replacing the maximum number of rules*/
  replaceAll(noMacroCode, "_MAXRULES", std::to_string(firewall.maxRules / 64));

  /*Replacing hops*/
  replaceAll(noMacroCode, "_NEXT_HOP_1", std::to_string(index + 1));

  replaceAll(noMacroCode, "_CONNTRACK_MODE",
             std::to_string(firewall.conntrackMode));

  return noMacroCode;
}
