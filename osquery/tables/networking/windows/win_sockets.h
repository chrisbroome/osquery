/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

// clang-format off
#include <osquery/utils/system/system.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
// clang-format on

#include <boost/noncopyable.hpp>

namespace osquery {
namespace tables {

enum class WinSockTableType { tcp, tcp6, udp, udp6 };

typedef void *(socketTableAllocator)(unsigned long family);

void* allocateTcpTable(unsigned long family);
void* allocateUdpTable(unsigned long family);

template<typename TTable, typename TRow, socketTableAllocator allocator, unsigned int family>
class WinSocketTable {
 public:
  WinSocketTable() : table(static_cast<TTable*>(allocator(family))) {}
  virtual ~WinSocketTable() {
    if (table != nullptr) {
      free(table);
      table = nullptr;
    }
  }
  virtual const size_t size() const {
    return table->dwNumEntries;
  };
  virtual const TRow& operator[](const size_t index) const {
    return table->table[index];
  }
 protected:
  TTable* table;
};

/**
 * Wrapper for the Windows MIB_TCPTABLE_OWNER_PID struct
 */
class WinTcpTableOwnerPid : public WinSocketTable<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, allocateTcpTable, AF_INET> {};

/**
 * Wrapper for the Windows MIB_TCP6TABLE_OWNER_PID struct
 */
class WinTcp6TableOwnerPid : public WinSocketTable<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID, allocateTcpTable, AF_INET6> {};

/**
 * Wrapper for the Windows MIB_UDPTABLE_OWNER_PID struct
 */
class WinUdpTableOwnerPid : public WinSocketTable<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, allocateUdpTable, AF_INET> {};

/**
 * Wrapper for the Windows MIB_UDP6TABLE_OWNER_PID struct
 */
class WinUdp6TableOwnerPid : public WinSocketTable<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, allocateUdpTable, AF_INET6> {};

class WinSockets : private boost::noncopyable {
 public:
  /// Parses all of the socket entries and populates the results QueryData
  void parseSocketTable(WinSockTableType sockType, QueryData& results);

 private:
  WinTcpTableOwnerPid tcpTable_;
  WinTcp6TableOwnerPid tcp6Table_;
  WinUdpTableOwnerPid udpTable_;
  WinUdp6TableOwnerPid udp6Table_;
};
}
}
