/**
* simplebridge API generated from simplebridge.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* SimplebridgeBase.h
*
*
*/

#pragma once

#include "../serializer/SimplebridgeJsonObject.h"

#include "../Fdb.h"
#include "../Ports.h"

#include "polycube/services/cube.h"
#include "polycube/services/port.h"
#include "polycube/services/utils.h"
#include "polycube/services/fifo_map.hpp"

#include <spdlog/spdlog.h>

using namespace polycube::service::model;


class SimplebridgeBase: public virtual polycube::service::Cube<Ports> {
 public:
  SimplebridgeBase(const std::string name);
  
  virtual ~SimplebridgeBase();
  virtual void update(const SimplebridgeJsonObject &conf);
  virtual SimplebridgeJsonObject toJsonObject();

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  virtual std::shared_ptr<Ports> getPorts(const std::string &name);
  virtual std::vector<std::shared_ptr<Ports>> getPortsList();
  virtual void addPorts(const std::string &name, const PortsJsonObject &conf);
  virtual void addPortsList(const std::vector<PortsJsonObject> &conf);
  virtual void replacePorts(const std::string &name, const PortsJsonObject &conf);
  virtual void delPorts(const std::string &name);
  virtual void delPortsList();

  /// <summary>
  ///
  /// </summary>
  virtual std::shared_ptr<Fdb> getFdb() = 0;
  virtual void addFdb(const FdbJsonObject &value) = 0;
  virtual void replaceFdb(const FdbJsonObject &conf);
  virtual void delFdb() = 0;
};
