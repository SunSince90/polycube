/**
* bridge API generated from bridge.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */



#include "PortsJsonObject.h"
#include <regex>

namespace polycube {
namespace service {
namespace model {

PortsJsonObject::PortsJsonObject() {
  m_nameIsSet = false;
  m_macIsSet = false;
  m_mode = PortsModeEnum::ACCESS;
  m_modeIsSet = true;
  m_accessIsSet = false;
  m_trunkIsSet = false;
  m_stpIsSet = false;
}

PortsJsonObject::PortsJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_nameIsSet = false;
  m_macIsSet = false;
  m_modeIsSet = false;
  m_accessIsSet = false;
  m_trunkIsSet = false;
  m_stpIsSet = false;


  if (val.count("name")) {
    setName(val.at("name").get<std::string>());
  }

  if (val.count("mac")) {
    setMac(val.at("mac").get<std::string>());
  }

  if (val.count("mode")) {
    setMode(string_to_PortsModeEnum(val.at("mode").get<std::string>()));
  }

  if (val.count("access")) {
    if (!val["access"].is_null()) {
      PortsAccessJsonObject newItem { val["access"] };
      setAccess(newItem);
    }
  }

  if (val.count("trunk")) {
    if (!val["trunk"].is_null()) {
      PortsTrunkJsonObject newItem { val["trunk"] };
      setTrunk(newItem);
    }
  }

  if (val.count("stp")) {
    for (auto& item : val["stp"]) {
      PortsStpJsonObject newItem{ item };
      m_stp.push_back(newItem);
    }

    m_stpIsSet = true;
  }
}

nlohmann::json PortsJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_nameIsSet) {
    val["name"] = m_name;
  }

  if (m_macIsSet) {
    val["mac"] = m_mac;
  }

  if (m_modeIsSet) {
    val["mode"] = PortsModeEnum_to_string(m_mode);
  }

  if (m_accessIsSet) {
    val["access"] = JsonObjectBase::toJson(m_access);
  }

  if (m_trunkIsSet) {
    val["trunk"] = JsonObjectBase::toJson(m_trunk);
  }

  {
    nlohmann::json jsonArray;
    for (auto& item : m_stp) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["stp"] = jsonArray;
    }
  }

  return val;
}

std::string PortsJsonObject::getName() const {
  return m_name;
}

void PortsJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool PortsJsonObject::nameIsSet() const {
  return m_nameIsSet;
}



std::string PortsJsonObject::getMac() const {
  return m_mac;
}

void PortsJsonObject::setMac(std::string value) {
  m_mac = value;
  m_macIsSet = true;
}

bool PortsJsonObject::macIsSet() const {
  return m_macIsSet;
}

void PortsJsonObject::unsetMac() {
  m_macIsSet = false;
}

PortsModeEnum PortsJsonObject::getMode() const {
  return m_mode;
}

void PortsJsonObject::setMode(PortsModeEnum value) {
  m_mode = value;
  m_modeIsSet = true;
}

bool PortsJsonObject::modeIsSet() const {
  return m_modeIsSet;
}

void PortsJsonObject::unsetMode() {
  m_modeIsSet = false;
}

std::string PortsJsonObject::PortsModeEnum_to_string(const PortsModeEnum &value){
  switch(value) {
    case PortsModeEnum::ACCESS:
      return std::string("access");
    case PortsModeEnum::TRUNK:
      return std::string("trunk");
    default:
      throw std::runtime_error("Bad Ports mode");
  }
}

PortsModeEnum PortsJsonObject::string_to_PortsModeEnum(const std::string &str){
  if (JsonObjectBase::iequals("access", str))
    return PortsModeEnum::ACCESS;
  if (JsonObjectBase::iequals("trunk", str))
    return PortsModeEnum::TRUNK;
  throw std::runtime_error("Ports mode is invalid");
}
PortsAccessJsonObject PortsJsonObject::getAccess() const {
  return m_access;
}

void PortsJsonObject::setAccess(PortsAccessJsonObject value) {
  m_access = value;
  m_accessIsSet = true;
}

bool PortsJsonObject::accessIsSet() const {
  return m_accessIsSet;
}

void PortsJsonObject::unsetAccess() {
  m_accessIsSet = false;
}

PortsTrunkJsonObject PortsJsonObject::getTrunk() const {
  return m_trunk;
}

void PortsJsonObject::setTrunk(PortsTrunkJsonObject value) {
  m_trunk = value;
  m_trunkIsSet = true;
}

bool PortsJsonObject::trunkIsSet() const {
  return m_trunkIsSet;
}

void PortsJsonObject::unsetTrunk() {
  m_trunkIsSet = false;
}

const std::vector<PortsStpJsonObject>& PortsJsonObject::getStp() const{
  return m_stp;
}

void PortsJsonObject::addPortsStp(PortsStpJsonObject value) {
  m_stp.push_back(value);
  m_stpIsSet = true;
}


bool PortsJsonObject::stpIsSet() const {
  return m_stpIsSet;
}

void PortsJsonObject::unsetStp() {
  m_stpIsSet = false;
}


}
}
}

