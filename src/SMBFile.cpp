/*
 *  Copyright (C) 2005-2020 Team Kodi
 *  https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include "SMBFile.h"

#include <algorithm>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>

#include "SMBSession.h"
#include "netbios/netbios_ns.h"

static void netbios_on_entry_added(void *p_opaque, netbios_ns_entry *entry)
{
  CSMBFile* smb = reinterpret_cast<CSMBFile*>(p_opaque);
  std::lock_guard<std::recursive_mutex> lock(*smb);

  smb->NetbiosOnEntryAdded(entry);
}

static void netbios_on_entry_removed(void *p_opaque, netbios_ns_entry *entry)
{
  CSMBFile* smb = reinterpret_cast<CSMBFile*>(p_opaque);
  std::lock_guard<std::recursive_mutex> lock(*smb);

  smb->NetbiosOnEntryRemoved(entry);
}

CSMBFile::CSMBFile(KODI_HANDLE instance, const std::string& version) : CInstanceVFS(instance, version)
{
  netbios_ns_discover_callbacks callbacks;
  m_ns = netbios_ns_new();

  callbacks.p_opaque = (void*)this;
  callbacks.pf_on_entry_added = netbios_on_entry_added;
  callbacks.pf_on_entry_removed = netbios_on_entry_removed;

  if (netbios_ns_discover_start(m_ns, 5, // broadcast every 5 seconds
                                &callbacks))
  {
    netbios_ns_destroy(m_ns);
    m_ns = nullptr;
  }
}

kodi::addon::VFSFileHandle CSMBFile::Open(const kodi::addon::VFSUrl& url)
{
  void *context = CSMBSessionManager::OpenFile(url);
  return context;
}

kodi::addon::VFSFileHandle CSMBFile::OpenForWrite(const kodi::addon::VFSUrl& url, bool overWrite)
{
  int mode = O_RDWR | O_WRONLY;
  if (!Exists(url))
    mode |= O_CREAT;

  kodi::addon::VFSFileHandle context = CSMBSessionManager::OpenFile(url, mode);
  return context;
}

ssize_t CSMBFile::Read(kodi::addon::VFSFileHandle context, uint8_t* lpBuf, size_t uiBufSize)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->Read(context, lpBuf, uiBufSize);
}

ssize_t CSMBFile::Write(kodi::addon::VFSFileHandle context, const uint8_t* buffer, size_t uiBufSize)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->Write(context, buffer, uiBufSize);
}

int64_t CSMBFile::Seek(kodi::addon::VFSFileHandle context, int64_t iFilePosition, int iWhence)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  // Not SEEK_END is not implemented, work around for now.
  if (iWhence == SEEK_END)
  {
    struct file_open* file = reinterpret_cast<struct file_open*>(context);
    int64_t pos = conn->GetLength(file);
    return conn->Seek(context, pos + iFilePosition, SEEK_SET);
  }

  return conn->Seek(context, iFilePosition, iWhence);
}

int CSMBFile::Truncate(kodi::addon::VFSFileHandle context, int64_t size)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->Truncate(context, size);
}

int64_t CSMBFile::GetLength(kodi::addon::VFSFileHandle context)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(file);
  if (!conn)
    return -1;

  return conn->GetLength(file);
}

int64_t CSMBFile::GetPosition(kodi::addon::VFSFileHandle context)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->GetPosition(context);
}

int CSMBFile::GetChunkSize(kodi::addon::VFSFileHandle context)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->GetChunkSize(context);
}

bool CSMBFile::IoControlGetSeekPossible(kodi::addon::VFSFileHandle context)
{
  return true;
}

bool CSMBFile::Close(void *context)
{
  if (!context)
    return false;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return false;

  return conn->CloseFile(context);
}

int CSMBFile::Stat(const kodi::addon::VFSUrl& url, kodi::vfs::FileStatus& buffer)
{
  if (url.GetSharename().empty())
    return -1;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return -1;

  struct __stat64 st;
  int res = conn->Stat(url, &st);

  buffer.SetFileSerialNumber(static_cast<uint64_t>(st.st_ino));
  buffer.SetIsDirectory(st.st_mode & S_IFDIR);
  buffer.SetIsSymLink(st.st_nlink);
  buffer.SetSize(st.st_size);
  buffer.SetAccessTime(st.st_atime);
  buffer.SetModificationTime(st.st_mtime);
  buffer.SetStatusTime(st.st_ctime);

  return res;
}

bool CSMBFile::Exists(const kodi::addon::VFSUrl& url)
{
  if (url.GetSharename().empty())
    return false;

  kodi::vfs::FileStatus st;
  return Stat(url, st) == 0 && !st.GetIsDirectory();
}

bool CSMBFile::Delete(const kodi::addon::VFSUrl& url)
{
  if (url.GetSharename().empty())
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return false;

  auto res = conn->Delete(url);

  return res;
}

bool CSMBFile::Rename(const kodi::addon::VFSUrl& url, const kodi::addon::VFSUrl& url2)
{
  if (url.GetSharename().empty() || url2.GetSharename().empty())
    return false;
  // rename is possible only inside a tree
  if (url.GetSharename() == url2.GetSharename())
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return false;

  auto res = conn->Rename(url, url2);
  return res;
}

void CSMBFile::ClearOutIdle()
{
  CSMBSessionManager::CheckIfIdle();
}

void CSMBFile::DisconnectAll()
{
  CSMBSessionManager::DisconnectAll();
  if (m_ns)
  {
    netbios_ns_discover_stop(m_ns);
    netbios_ns_destroy(m_ns);
    m_ns = nullptr;
  }
}

void CSMBFile::NetbiosOnEntryAdded(netbios_ns_entry * entry)
{
  uint32_t ip = netbios_ns_entry_ip(entry);
  struct in_addr addr;
  addr.s_addr = ip;

  auto it = std::find_if(m_discovered.begin(), m_discovered.end(), [ip](const netbios_host& host) {
    return ip == host.ip;
  });

  if (it == m_discovered.end())
  {
    netbios_host host;
    host.ip = ip;
    host.type = netbios_ns_entry_type(entry);
    host.domain = std::string(netbios_ns_entry_group(entry));
    host.name = std::string(netbios_ns_entry_name(entry));

    m_discovered.push_back(host);

    kodi::Log(ADDON_LOG_DEBUG, "NetbiosOnEntryAdded: Ip:%s name: %s/%s",
              inet_ntoa(addr), host.domain.c_str(), host.name.c_str());
  }
  else
  {
    // need update?
    it->type = netbios_ns_entry_type(entry);
    it->domain = std::string(netbios_ns_entry_group(entry));
    it->name = std::string(netbios_ns_entry_name(entry));
  }
}

void CSMBFile::NetbiosOnEntryRemoved(netbios_ns_entry * entry)
{
  uint32_t ip = netbios_ns_entry_ip(entry);

  auto it = std::find_if(m_discovered.begin(), m_discovered.end(), [ip](const netbios_host& host) {
    return ip == host.ip;
  });

  if (it != m_discovered.end())
  {
    struct in_addr addr;
    addr.s_addr = it->ip;

    kodi::Log(ADDON_LOG_DEBUG, "NetbiosOnEntryRemoved: Ip:%s name: %s/%s",
              inet_ntoa(addr), it->domain.c_str(), it->name.c_str());

    m_discovered.erase(it);
  }
}

bool CSMBFile::GetDirectory(const kodi::addon::VFSUrl& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks)
{
  bool res = false;
  CSMBSessionPtr conn = nullptr;

  // browse entire network
  if (url.GetHostname().empty())
  {
    std::lock_guard<std::recursive_mutex> lock(*this);
    for (netbios_host& host : m_discovered)
    {
      std::string path(url.GetURL() + std::string(host.name));
      if (path[path.size() - 1] != '/')
        path += '/';

      kodi::vfs::CDirEntry pItem;
      if (host.name[0] == '.')
      {
        pItem.AddProperty("file:hidden", "true");
      }
      else
      {
        pItem.ClearProperties();
      }

      pItem.SetLabel(host.name);
      pItem.SetFolder(true);
      pItem.SetPath(path);
      items.push_back(pItem);
    }

    return true;
  }

  conn = CSMBSessionManager::Open(url);
  if (!conn)
  {
    int err = CSMBSessionManager::GetLastError();
    if ( err == -EACCES       // SMB2_STATUS_ACCESS_DENIED
      || err == -ECONNREFUSED // SMB2_STATUS_LOGON_FAILURE
      )
    {
      callbacks.RequireAuthentication(url.GetURL());
    }
    return false;
  }

  if (url.GetSharename().empty())
  {
    res = conn->GetShares(url, items);
  }
  else
  {
    res = conn->GetDirectory(url, items);
  }
  return res;
}

bool CSMBFile::DirectoryExists(const kodi::addon::VFSUrl& url)
{
  if (url.GetHostname().empty())
    return true;

  // checking if server exists by trying to connect to it's IPC$ share
  if (url.GetSharename().empty())
  {
    CSMBSessionPtr conn = CSMBSessionManager::Open(url);
    return conn != nullptr;
  }

  kodi::vfs::FileStatus st;
  return Stat(url, st) == 0 && st.GetIsDirectory();
}

bool CSMBFile::RemoveDirectory(const kodi::addon::VFSUrl& url)
{
  if (url.GetSharename().empty())
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return false;

  auto res = conn->RemoveDirectory(url);

  return res;
}

bool CSMBFile::CreateDirectory(const kodi::addon::VFSUrl& url)
{
  if (url.GetSharename().empty())
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return false;

  auto res = conn->CreateDirectory(url);

  return res;
}
