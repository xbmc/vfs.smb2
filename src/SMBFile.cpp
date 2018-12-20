/*
 *      Copyright (C) 2005-2018 Team Kodi
 *      http://kodi.tv
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
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
  P8PLATFORM::CLockObject lock(*smb);

  smb->NetbiosOnEntryAdded(entry);
}

static void netbios_on_entry_removed(void *p_opaque, netbios_ns_entry *entry)
{
  CSMBFile* smb = reinterpret_cast<CSMBFile*>(p_opaque);
  P8PLATFORM::CLockObject lock(*smb);

  smb->NetbiosOnEntryRemoved(entry);
}

CSMBFile::CSMBFile(KODI_HANDLE instance) : CInstanceVFS(instance)
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

void* CSMBFile::Open(const VFSURL& url)
{
  void *context = CSMBSessionManager::OpenFile(url);
  return context;
}

void* CSMBFile::OpenForWrite(const VFSURL& url, bool overWrite)
{
  int mode = O_RDWR | O_WRONLY;
  if (!Exists(url))
    mode |= O_CREAT;

  void* context = CSMBSessionManager::OpenFile(url, mode);
  return context;
}

ssize_t CSMBFile::Read(void* context, void* lpBuf, size_t uiBufSize)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->Read(context, lpBuf, uiBufSize);
}

ssize_t CSMBFile::Write(void* context, const void* buffer, size_t uiBufSize)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->Write(context, buffer, uiBufSize);
}

int64_t CSMBFile::Seek(void* context, int64_t iFilePosition, int iWhence)
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

int CSMBFile::Truncate(void* context, int64_t size)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->Truncate(context, size);
}

int64_t CSMBFile::GetLength(void* context)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(file);
  if (!conn)
    return -1;

  return conn->GetLength(file);
}

int64_t CSMBFile::GetPosition(void* context)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->GetPosition(context);
}

int CSMBFile::GetChunkSize(void* context)
{
  if (!context)
    return -1;

  CSMBSessionPtr conn = CSMBSession::GetForContext(context);
  if (!conn)
    return -1;

  return conn->GetChunkSize(context);
}

int CSMBFile::IoControl(void* context, XFILE::EIoControl request, void* param)
{
  if(request == XFILE::IOCTRL_SEEK_POSSIBLE)
    return 1;

  return -1;
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

int CSMBFile::Stat(const VFSURL& url, struct __stat64* buffer)
{
  if (!strlen(url.sharename))
    return -1;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return -1;

  auto res = conn->Stat(url, buffer);

  return res;
}

bool CSMBFile::Exists(const VFSURL& url)
{
  if (!strlen(url.sharename))
    return false;

  struct __stat64 st;
  return Stat(url, &st) == 0 && !S_ISDIR(st.st_mode);
}

bool CSMBFile::Delete(const VFSURL& url)
{
  if (!strlen(url.sharename))
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return false;

  auto res = conn->Delete(url);

  return res;
}

bool CSMBFile::Rename(const VFSURL& url, const VFSURL& url2)
{
  if (!strlen(url.sharename) || !strlen(url2.sharename))
    return false;
  // rename is possible only inside a tree
  if (stricmp(url.sharename, url2.sharename))
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

bool CSMBFile::GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks)
{
  bool res = false;
  CSMBSessionPtr conn = nullptr;

  // browse entire network
  if (!strlen(url.hostname))
  {
    P8PLATFORM::CLockObject lock(*this);
    for (netbios_host& host : m_discovered)
    {
      std::string path(std::string(url.url) + std::string(host.name));
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

  // for shares enumeration share name must be "IPC$"
  if (!strlen(url.sharename))
  {
    VFSURL url2 = 
    { 
      url.url, 
      url.domain, 
      url.hostname, 
      url.filename, 
      url.port, 
      url.options, 
      url.username, 
      url.password, 
      url.redacted, 
      "IPC$" 
    };

    conn = CSMBSessionManager::Open(url2);
  }
  else
  {
    conn = CSMBSessionManager::Open(url);
  }

  if (!conn)
  {
    int err = CSMBSessionManager::GetLastError();
    if ( err == -EACCES       // SMB2_STATUS_ACCESS_DENIED
      || err == -ECONNREFUSED // SMB2_STATUS_LOGON_FAILURE
      )
    {
      callbacks.RequireAuthentication(url.url);
    }
    return false;
  }

  if (!strlen(url.sharename))
  {
    res = conn->GetShares(url, items);
  }
  else
  {
    res = conn->GetDirectory(url, items);
  }
  return res;
}

bool CSMBFile::DirectoryExists(const VFSURL& url)
{
  if (!strlen(url.hostname))
    return true;

  // checking if server exists by trying to connect to it's IPC$ share
  if (!strlen(url.sharename))
  {
    VFSURL url2 =
    {
      url.url,
      url.domain,
      url.hostname,
      url.filename,
      url.port,
      url.options,
      url.username,
      url.password,
      url.redacted,
      "IPC$"
    };

    CSMBSessionPtr conn = CSMBSessionManager::Open(url2);
    return conn != nullptr;
  }

  struct __stat64 st;
  return Stat(url, &st) == 0 && S_ISDIR(st.st_mode);
}

bool CSMBFile::RemoveDirectory(const VFSURL& url)
{
  if (!strlen(url.sharename))
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return false;

  auto res = conn->RemoveDirectory(url);

  return res;
}

bool CSMBFile::CreateDirectory(const VFSURL& url)
{
  if (!strlen(url.sharename))
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
  if (!conn)
    return false;

  auto res = conn->CreateDirectory(url);

  return res;
}
