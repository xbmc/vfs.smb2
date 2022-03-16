/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include <kodi/addon-instance/VFS.h>
#include <kodi/Filesystem.h>
#include <kodi/General.h>

#include <inttypes.h>
extern "C"
{
#include <smb2/libsmb2.h>
}

#include <chrono>
#include <fcntl.h>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>

#ifdef RemoveDirectory
#undef RemoveDirectory
#endif
#ifdef CreateDirectory
#undef CreateDirectory
#endif

class CSMBSession;

// mutex implementation
typedef std::recursive_mutex mutex_t;
// locker implementation
typedef std::lock_guard<mutex_t> locker_t;
// pointer type
typedef std::shared_ptr<CSMBSession> CSMBSessionPtr;
// connections for a domain;user@host/share
typedef std::map<std::string, CSMBSessionPtr> session_map_t;
// oppened files on session
typedef std::vector<struct file_open*> files_vec_t;

class CSMBSessionManager
{
public:
  static CSMBSessionPtr Open(const kodi::addon::VFSUrl& url);
  static void* OpenFile(const kodi::addon::VFSUrl& url, int mode = O_RDONLY);

  static void DisconnectAll();
  static void CheckIfIdle();
  static int GetLastError() { return m_lastError; }

private:
  static mutex_t m_sess_mutex;
  static session_map_t m_sessions;
  static int m_lastError;
};

class CSMBSession
{
public:
  virtual ~CSMBSession();

  static CSMBSessionPtr GetForContext(void* context);

  // static operations
  bool GetDirectory(const kodi::addon::VFSUrl& url, std::vector<kodi::vfs::CDirEntry>& items);
  bool GetShares(const kodi::addon::VFSUrl& url, std::vector<kodi::vfs::CDirEntry>& items);
  int Stat(const kodi::addon::VFSUrl& url, struct __stat64* buffer);
  bool Delete(const kodi::addon::VFSUrl& url);
  bool Rename(const kodi::addon::VFSUrl& url, const kodi::addon::VFSUrl& url2);
  bool RemoveDirectory(const kodi::addon::VFSUrl& url);
  bool CreateDirectory(const kodi::addon::VFSUrl& url);

  // file operations
  bool CloseFile(void* context);
  ssize_t Read(void* context, void* lpBuf, size_t uiBufSize);
  ssize_t Write(void* context, const void* lpBuf, size_t uiBufSize);
  int64_t Seek(void* context, int64_t iFilePosition, int iWhence);
  int Truncate(void* context, int64_t size);
  int64_t GetLength(void* context);
  int64_t GetPosition(void* context) const;
  int GetChunkSize(void* context) const;

  // session operations
  void Close();
  bool Echo();
  bool IsIdle() const;
  int GetLastError() { return lastError; }
  bool IsValid() const { return smb_context != nullptr && !reconnect; }
  bool HasOpens() const { return !m_files.empty(); }

private:
  friend CSMBSessionManager;

  using smb_ctx = struct smb2_context*;
  using smb_cb = smb2_command_cb;
  using smb_data = struct sync_cb_data&;
  typedef std::function<int(smb_ctx, smb_cb, smb_data)> async_func;

  CSMBSession(std::string& hostname, std::string& domain, std::string& username
            , std::string& password, std::string& sharename);
  bool Connect(std::string& hostname, std::string& domain, std::string& username
             , std::string& password, std::string& sharename);
  struct file_open* OpenFile(const kodi::addon::VFSUrl& url, int mode = O_RDONLY);
  void CloseHandle(struct smb2fh* file);
  int Stat(struct smb2fh* file, struct __stat64* buffer);
  int ProcessAsync(const std::string& cmd, struct sync_cb_data& cb_data, async_func func);

  mutex_t ctx_mutex;                // mutex to smb2_context
  struct smb2_context *smb_context; // smb2 context

  mutex_t m_open_mutex;             // mutex to m_files
  files_vec_t m_files;              // files opened with session

  std::chrono::system_clock::time_point lastAccess; // the last access time
  int lastError;                    // the last error
  bool reconnect;                   // session requires reconnect
};
