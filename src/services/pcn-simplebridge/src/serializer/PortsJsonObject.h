/**
* simplebridge API generated from simplebridge.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* PortsJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace polycube {
namespace service {
namespace model {


/// <summary>
///
/// </summary>
class  PortsJsonObject : public JsonObjectBase {
public:
  PortsJsonObject();
  PortsJsonObject(const nlohmann::json &json);
  ~PortsJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Port Name
  /// </summary>
  std::string getName() const;
  void setName(std::string value);
  bool nameIsSet() const;

  /// <summary>
  /// MAC address of the port
  /// </summary>
  std::string getMac() const;
  void setMac(std::string value);
  bool macIsSet() const;
  void unsetMac();

private:
  std::string m_name;
  bool m_nameIsSet;
  std::string m_mac;
  bool m_macIsSet;
};

}
}
}

