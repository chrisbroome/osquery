/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */
#include <string>
#include <utility>
#include <vector>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "win_sockets.h"

namespace {
const std::vector<std::string> winTcpStates = {
    "UNKNOWN",
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB",
};

std::string tcpStateString(const DWORD state) {
  return state < winTcpStates.size() ? winTcpStates[state] : "UNKNOWN";
}

std::string portString(const DWORD dwPort) {
  return std::to_string(ntohs(static_cast<u_short>(dwPort)));
}

std::string inet4AddressString(const DWORD dwAddr) {
  std::vector<char> addr(128, 0x0);
  auto retVal = InetNtopA(AF_INET, &dwAddr, addr.data(), addr.size());
  if (retVal == nullptr) {
    TLOG << "Error converting network local address to string: "
         << WSAGetLastError();
  }
  return addr.data();
}

std::string inet6AddressString(const UCHAR* ucAddr) {
  std::vector<char> addr(128, 0x0);
  auto retVal = InetNtopA(AF_INET6, ucAddr, addr.data(), addr.size());
  if (retVal == nullptr) {
    TLOG << "Error converting network local address to string: "
         << WSAGetLastError();
  }
  return addr.data();
}

DWORD _winGetTcpOnwerPidTable(void *pSockTable, unsigned long* buffsize, unsigned long family) {
  return GetExtendedTcpTable(pSockTable,
                             reinterpret_cast<PULONG>(buffsize),
                             true,
                             family,
                             TCP_TABLE_OWNER_PID_ALL,
                             0);
}

DWORD _winGetUdpOnwerPidTable(void* pSockTable, unsigned long* buffsize, unsigned long family) {
  return GetExtendedUdpTable(pSockTable,
                             reinterpret_cast<PULONG>(buffsize),
                             true,
                             family,
                             UDP_TABLE_OWNER_PID,
                             0);
}

}

namespace osquery {
namespace tables {

void* allocateTcpTable(unsigned long family) {
  unsigned long buffsize = 0;
  void* pSockTable = nullptr;

  // in order to know how big of a buffer to allocate, you first try to get a table with a buffer of size 0
  const auto bufferSizeRet = _winGetTcpOnwerPidTable(pSockTable, &buffsize, family);
  if (bufferSizeRet == ERROR_INSUFFICIENT_BUFFER) {
    // when the buffer isn't big enough, GetExtendedTcpTable returns the correct buffer size through the buffsize parameter
    // so use that to allocate a new buffer
    pSockTable = static_cast<void*>(malloc(buffsize));
    if (pSockTable == nullptr) {
      return nullptr;
    }
  }
  const auto tableRet = _winGetTcpOnwerPidTable(pSockTable, &buffsize, family);
  if (tableRet != NO_ERROR) {
    return nullptr;
  }

  return pSockTable;
}

void* allocateUdpTable(unsigned long family) {
  unsigned long buffsize = 0;
  void* pSockTable = nullptr;
  const auto bufferSizeRet = _winGetUdpOnwerPidTable(pSockTable, &buffsize, family);
  if (bufferSizeRet == ERROR_INSUFFICIENT_BUFFER) {
    pSockTable = static_cast<void*>(malloc(buffsize));
    if (pSockTable == nullptr) {
      return nullptr;
    }
  }
  const auto tableRet = _winGetUdpOnwerPidTable(pSockTable, &buffsize, family);
  if (tableRet != NO_ERROR) {
    return nullptr;
  }
  return pSockTable;
}

Row parseTcpSocketTableRow(const MIB_TCPROW_OWNER_PID& entry) {
  Row r;
  r["protocol"] = INTEGER(IPPROTO_TCP);
  r["local_address"] = inet4AddressString(entry.dwLocalAddr);
  r["local_port"] = portString(entry.dwLocalPort);
  r["remote_address"] = inet4AddressString(entry.dwRemoteAddr);
  r["remote_port"] = portString(entry.dwRemotePort);
  r["pid"] = INTEGER(entry.dwOwningPid);
  r["family"] = INTEGER(AF_INET);
  r["state"] = tcpStateString(entry.dwState);
  r["fd"] = "0";
  r["socket"] = "0";
  return r;
}

Row parseTcp6SocketTableRow(const MIB_TCP6ROW_OWNER_PID& entry) {
  Row r;
  r["protocol"] = INTEGER(IPPROTO_TCP);
  r["local_address"] = inet6AddressString(entry.ucLocalAddr);
  r["local_port"] = portString(entry.dwLocalPort);
  r["remote_address"] = inet6AddressString(entry.ucRemoteAddr);
  r["remote_port"] = portString(entry.dwRemotePort);
  r["pid"] = INTEGER(entry.dwOwningPid);
  r["family"] = INTEGER(AF_INET6);
  r["state"] = tcpStateString(entry.dwState);
  r["fd"] = "0";
  r["socket"] = "0";
  return r;
}

Row parseUdpSocketTableRow(const MIB_UDPROW_OWNER_PID& entry) {
  Row r;
  r["protocol"] = INTEGER(IPPROTO_UDP);
  r["local_address"] = inet4AddressString(entry.dwLocalAddr);
  r["local_port"] = portString(entry.dwLocalPort);
  r["remote_address"] = "0";
  r["remote_port"] = INTEGER(0);
  r["pid"] = INTEGER(entry.dwOwningPid);
  r["family"] = INTEGER(AF_INET);
  r["state"] = "";
  r["fd"] = "0";
  r["socket"] = "0";
  return r;
}

Row parseUdp6SocketTableRow(const MIB_UDP6ROW_OWNER_PID& entry) {
  Row r;
  r["protocol"] = INTEGER(IPPROTO_UDP);
  r["local_address"] = inet6AddressString(entry.ucLocalAddr);
  r["local_port"] = portString(entry.dwLocalPort);
  r["remote_address"] = "0";
  r["remote_port"] = INTEGER(0);
  r["pid"] = INTEGER(entry.dwOwningPid);
  r["family"] = INTEGER(AF_INET6);
  r["state"] = "";
  r["fd"] = "0";
  r["socket"] = "0";
  return r;
}

template<typename TTable, typename TRow>
QueryData parseSocketTable(const TTable& table, Row (parseFunc)(const TRow &)) {
  QueryData results;
  const auto size = table.size();
  for (size_t i = 0; i < size; ++i) {
    results.push_back(std::move(parseFunc(table[i])));
  }
  return results;
}

void WinSockets::parseSocketTable(WinSockTableType sockType,
                                  QueryData& results) {
  QueryData res;
  switch (sockType) {
  case WinSockTableType::tcp:
    res = tables::parseSocketTable(tcpTable_, parseTcpSocketTableRow);
    break;
  case WinSockTableType::tcp6:
    res = tables::parseSocketTable(tcp6Table_, parseTcp6SocketTableRow);
    break;
  case WinSockTableType::udp:
    res = tables::parseSocketTable(udpTable_, parseUdpSocketTableRow);
    break;
  case WinSockTableType::udp6:
    res = tables::parseSocketTable(udp6Table_, parseUdp6SocketTableRow);
    break;
  }
  results.insert(results.end(), res.begin(), res.end());
}

QueryData genOpenSockets(QueryContext& context) {
  QueryData results;
  WinSockets sockTable;

  sockTable.parseSocketTable(WinSockTableType::tcp, results);
  sockTable.parseSocketTable(WinSockTableType::tcp6, results);
  sockTable.parseSocketTable(WinSockTableType::udp, results);
  sockTable.parseSocketTable(WinSockTableType::udp6, results);

  return results;
}
}
}
