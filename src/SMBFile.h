/*
 *  Copyright (C) 2005-2020 Team Kodi
 *  https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include <kodi/addon-instance/VFS.h>
#include <kodi/Filesystem.h>
#include <kodi/General.h>
#include <p8-platform/threads/mutex.h>

#ifdef RemoveDirectory
#undef RemoveDirectory
#endif // RemoveDirectory
#ifdef CreateDirectory
#undef CreateDirectory
#endif // RemoveDirectory

struct netbios_ns;
struct netbios_ns_entry;

class CSMBFile : public kodi::addon::CInstanceVFS, public P8PLATFORM::CMutex
{
public:
  CSMBFile(KODI_HANDLE instance);

  void* Open(const VFSURL& url) override;
  void* OpenForWrite(const VFSURL& url, bool overWrite) override;
  int Stat(const VFSURL& url, struct __stat64* buffer) override;
  bool Exists(const VFSURL& url) override;
  bool Delete(const VFSURL& url) override;
  bool Rename(const VFSURL& url, const VFSURL& url2) override;

  ssize_t Read(void* context, void* lpBuf, size_t uiBufSize) override;
  ssize_t Write(void* context, const void* buffer, size_t uiBufSize) override;
  int64_t Seek(void* context, int64_t iFilePosition, int iWhence) override;
  int Truncate(void* context, int64_t size) override;
  int64_t GetLength(void* context) override;
  int64_t GetPosition(void* context) override;
  int GetChunkSize(void* context) override;
  int IoControl(void* context, VFS_IOCTRL request, void* param) override;
  bool Close(void* context) override;

  bool GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks) override;
  bool DirectoryExists(const VFSURL& url) override;
  bool RemoveDirectory(const VFSURL& url) override;
  bool CreateDirectory(const VFSURL& url) override;

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
  ADDON_STATUS CreateInstance(int instanceType, std::string instanceID, KODI_HANDLE instance, KODI_HANDLE& addonInstance) override
  {
    addonInstance = new CSMBFile(instance);
    return ADDON_STATUS_OK;
  }
};

ADDONCREATOR(CMyAddon);
