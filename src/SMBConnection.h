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

#include <kodi/addon-instance/VFS.h>
#include <kodi/Filesystem.h>
#include <kodi/General.h>

#include <fcntl.h>
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

class CConnection;

// connection open by file handle
typedef std::map<struct file_open*, CConnection*> t_opens_map;
// vector of connections
typedef std::vector<CConnection*> t_connection_vec;
// connections for a share
typedef std::map<std::string, t_connection_vec> t_connection_map;
// mutex implementation
typedef std::recursive_mutex t_mutex;
// locker implementation
typedef std::lock_guard<t_mutex> t_locker;

class CConnectionFactory
{
public:
  static CConnection* Acquire(const VFSURL& url);
  static void Release(CConnection* conn);

  static struct file_open* OpenFile(const VFSURL& url, int mode = O_RDONLY);
  static CConnection* GetForFile(struct file_open* fh);
  static bool CloseFile(struct file_open* fh);

  static void Remove(CConnection *conn);
  static void DisconnectAll();
  static void CheckIfIdle() { /* TODO */ };

private:
  static t_mutex m_conn_mutex;
  static t_connection_map m_connections;
  static t_mutex m_open_mutex;
  static t_opens_map m_opens;
};

class CConnection
{
public:
  // static operations
  bool GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, kodi::addon::CInstanceVFS::CVFSCallbacks callbacks);
  int Stat(const VFSURL& url, struct __stat64* buffer);
  bool Delete(const VFSURL& url);
  bool RemoveDirectory(const VFSURL& url);
  bool CreateDirectory(const VFSURL& url);

  // file operations
  int Stat(struct smb2fh *file, struct __stat64* buffer);
  ssize_t Read(struct file_open *file, void* lpBuf, size_t uiBufSize);
  ssize_t Write(struct file_open *file, const void* lpBuf, size_t uiBufSize);
  int64_t Seek(struct file_open *file, int64_t iFilePosition, int iWhence);
  int Truncate(struct file_open *file, int64_t size);
  int64_t GetLength(struct file_open *file);
  int64_t GetPosition(struct file_open *file);

  // connection operation
  int GetChunkSize();
  void Close();
  bool Echo();

private:
  friend CConnectionFactory;

  CConnection();
  void CloseFile(struct smb2fh *file);
  struct smb2fh* OpenFile(const VFSURL& url, int mode = O_RDONLY);

  t_mutex ctx_mutex;                // mutex to smb2_context
  struct smb2_context *smb_context; // smb2 context
  std::string sharename;            // <server>/<share>
  uint64_t lastAccess;              // last access time to the connectio
  int refs;                         // ref count
  bool reconnect;                   // requires reconnect
};
