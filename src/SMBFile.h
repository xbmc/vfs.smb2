/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include <kodi/addon-instance/VFS.h>
#include <kodi/Filesystem.h>
#include <kodi/General.h>
#include <mutex>

#ifndef S_ISDIR
#define S_ISDIR(mode) ((((mode)) & 0170000) == (0040000))
#endif
#ifndef S_ISLNK
#define S_ISLNK(mode) ((((mode)) & 0170000) == (0120000))
#endif

struct netbios_ns;
struct netbios_ns_entry;

class CSMBFile : public kodi::addon::CInstanceVFS, public std::recursive_mutex
{
public:
  CSMBFile(KODI_HANDLE instance, const std::string& version);

  kodi::addon::VFSFileHandle Open(const kodi::addon::VFSUrl& url) override;
  kodi::addon::VFSFileHandle OpenForWrite(const kodi::addon::VFSUrl& url, bool overWrite) override;
  int Stat(const kodi::addon::VFSUrl& url, kodi::vfs::FileStatus& buffer) override;
  bool Exists(const kodi::addon::VFSUrl& url) override;
  bool Delete(const kodi::addon::VFSUrl& url) override;
  bool Rename(const kodi::addon::VFSUrl& url, const kodi::addon::VFSUrl& url2) override;

  ssize_t Read(kodi::addon::VFSFileHandle context, uint8_t* lpBuf, size_t uiBufSize) override;
  ssize_t Write(kodi::addon::VFSFileHandle context, const uint8_t* buffer, size_t uiBufSize) override;
  int64_t Seek(kodi::addon::VFSFileHandle context, int64_t iFilePosition, int iWhence) override;
  int Truncate(kodi::addon::VFSFileHandle context, int64_t size) override;
  int64_t GetLength(kodi::addon::VFSFileHandle context) override;
  int64_t GetPosition(kodi::addon::VFSFileHandle context) override;
  int GetChunkSize(kodi::addon::VFSFileHandle context) override;
  bool IoControlGetSeekPossible(kodi::addon::VFSFileHandle context) override;
  bool Close(kodi::addon::VFSFileHandle context) override;

  bool GetDirectory(const kodi::addon::VFSUrl& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks) override;
  bool DirectoryExists(const kodi::addon::VFSUrl& url) override;
  bool RemoveDirectory(const kodi::addon::VFSUrl& url) override;
  bool CreateDirectory(const kodi::addon::VFSUrl& url) override;

  void ClearOutIdle();
  void DisconnectAll();

  void NetbiosOnEntryAdded(netbios_ns_entry *entry);
  void NetbiosOnEntryRemoved(netbios_ns_entry *entry);

private:
  struct netbios_host
  {
    char type;
    uint32_t ip;
    std::string name;
    std::string domain;
  };

  netbios_ns* m_ns;
  std::vector<netbios_host> m_discovered;
};

class ATTRIBUTE_HIDDEN CMyAddon : public kodi::addon::CAddonBase
{
public:
  CMyAddon() = default;
  ADDON_STATUS CreateInstance(int instanceType, const std::string& instanceID, KODI_HANDLE instance, const std::string& version, KODI_HANDLE& addonInstance) override
  {
    addonInstance = new CSMBFile(instance, version);
    return ADDON_STATUS_OK;
  }
};

ADDONCREATOR(CMyAddon);
