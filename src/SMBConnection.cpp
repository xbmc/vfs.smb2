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

#include <inttypes.h>
extern "C"
{
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
}

#include "SMBConnection.h"
#include <kodi/Network.h>
#include <p8-platform/util/timeutils.h>
#include <algorithm>
#include <fcntl.h>

//6 mins (360s) cached context timeout
#define CONTEXT_TIMEOUT 360000

struct file_open
{
  struct smb2fh* handle;
  int mode;
  std::string path;
  uint64_t size;
  uint64_t offset;
};

struct sync_cb_data
{
  bool completed;
  bool reconnect;
  int status;
  void *data;
};

t_mutex CConnectionFactory::m_conn_mutex;
t_mutex CConnectionFactory::m_open_mutex;
t_connection_map CConnectionFactory::m_connections;
t_opens_map CConnectionFactory::m_opens;

static std::string to_smb_path(const char* path)
{
  std::string strPath(path);
  std::replace(strPath.begin(), strPath.end(), '/', '\\');

  if (strPath.back() == '\\')
    strPath = strPath.substr(0, strPath.size() - 1);

  return strPath;
}

static void cmd_cb(struct smb2_context* smb2, int status, void* command_data, void* private_data)
{
  struct sync_cb_data *cb_data = (struct sync_cb_data *) private_data;
  cb_data->data = command_data;
  cb_data->completed = true;
  cb_data->status = status;
}

static int wait_for_reply(struct smb2_context* smb2, sync_cb_data &cb_data)
{
  WSAPOLLFD pfd;
  while (!cb_data.completed)
  {
    pfd.fd = smb2_get_fd(smb2);
    pfd.events = smb2_which_events(smb2);

    if (WSAPoll(&pfd, 1, 500) < 0)
    {
      int wsa_err = WSAGetLastError();
      kodi::Log(ADDON_LOG_ERROR, "SMB2: poll failed with: %d", wsa_err);
      cb_data.reconnect = true;
      return -1;
    }

    // TODO add timeout
    if (pfd.revents == 0)
    {
      continue;
    }

    if (smb2_service(smb2, pfd.revents) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_service failed with: %s", smb2_get_error(smb2));
      cb_data.reconnect = true;
      return -1;
    }
  }
  return 0;
}

CConnection* CConnectionFactory::Acquire(const VFSURL &url)
{
  t_locker lock(m_conn_mutex);

  CConnection* conn = nullptr;
  std::string sharename = url.hostname + std::string("/") + url.sharename;
  std::list<struct file_open*> renews;
  bool opens_locked = false;

  auto it = m_connections.find(sharename);
  if (it != m_connections.end())
  {
    auto connections = it->second;
    auto itc = std::find_if(connections.begin(), connections.end(), [](const CConnection* con) {
      return true; // !con->bLocked;
    });

    if (itc != connections.end())
    {
      conn = *itc;
      if (conn->reconnect)
      {
        m_open_mutex.lock();
        opens_locked = true;

        auto it = m_opens.begin();
        while (it != m_opens.end());
        {
          if (it->second == conn)
          {
            free(it->first->handle); // dangerous

            it->second->refs--;
            it = m_opens.erase(it);
            renews.push_back(it->first);
          }
          else
            it++;
        }

        delete conn;
        connections.erase(itc);
      }
      /*if ((!conn->refs && conn->lastAccess < P8PLATFORM::GetTimeMs() - CONTEXT_TIMEOUT) || !conn->smb_context)
      {
        delete conn;
        connections.erase(itc);
      }*/
      else
      {
        conn->lastAccess = P8PLATFORM::GetTimeMs();
        conn->refs++;

        return conn;
      }
    }
  }

  // open new connection
  struct smb2_context *smb_context = smb2_init_context();
  struct smb2_url *smburl = smb2_parse_url(smb_context, url.url);
  if (!smburl || !smburl->server)
  {
    kodi::Log(ADDON_LOG_ERROR, "failed to parse url: %s", smb2_get_error(smb_context));
    smb2_destroy_context(smb_context);

    if (opens_locked)
      m_open_mutex.unlock();

    return nullptr;
  }

  if (!smburl->domain)
    smburl->domain = strdup(smburl->server);

  if (!smburl->user && !smburl->password)
  {
    smburl->user = strdup("Guest");
    smburl->password = strdup("");
  }

  smb2_set_workstation(smb_context, smburl->server);
  if (smburl->user)
    smb2_set_user(smb_context, smburl->user);
  if (smburl->password)
    smb2_set_password(smb_context, smburl->password);
  if (smburl->domain)
    smb2_set_domain(smb_context, smburl->domain);

  smb2_set_security_mode(smb_context, SMB2_NEGOTIATE_SIGNING_ENABLED);

  auto ret = smb2_connect_share(smb_context, smburl->server, smburl->share, smburl->user);
  if (ret < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: connect to share '%s' at server '%s' failed. %s", smburl->share, smburl->server, smb2_get_error(smb_context));
    smb2_destroy_context(smb_context);
    smb2_destroy_url(smburl);

    if (opens_locked)
      m_open_mutex.unlock();

    return nullptr;
  }

  kodi::Log(ADDON_LOG_DEBUG, "SMB2: connected to server '%s' and share '%s'", url.hostname, smburl->share);
  smb2_destroy_url(smburl);

  conn = new CConnection();
  conn->sharename = sharename;
  conn->smb_context = smb_context;
  conn->lastAccess = P8PLATFORM::GetTimeMs();

  if (!renews.empty())
  {
    for (auto open : renews)
    {
      open->handle = smb2_open(smb_context, open->path.c_str(), open->mode);
      smb2_lseek(smb_context, open->handle, open->offset, SEEK_SET, nullptr);
      m_opens[open] = conn;
    }
  }
  if (opens_locked)
    m_open_mutex.unlock();

  m_connections[sharename].push_back(conn);

  return conn;
}

struct file_open* CConnectionFactory::OpenFile(const VFSURL &url, int mode /* = O_RDONLY */)
{
  struct file_open *file = nullptr;

  CConnection* conn = Acquire(url);
  if (!conn)
    return nullptr;

  t_locker lock(m_open_mutex);

  struct smb2fh* fh = conn->OpenFile(url, mode);
  if (fh)
  {
    struct __stat64 st;
    if (!conn->Stat(fh, &st))
    {
      file = new file_open;
      file->handle = fh;
      file->path = url.filename;
      file->size = st.st_size;
      file->offset = 0;
      file->mode = mode;

      m_opens[file] = conn;
      conn->refs++;
    }
    else
      conn->CloseFile(fh);
  }

  Release(conn);
  return file;
}

CConnection* CConnectionFactory::GetForFile(struct file_open* fh)
{
  if (!fh)
    return nullptr;

  t_locker lock(m_open_mutex);

  auto it = m_opens.find(fh);
  if (it != m_opens.end())
    return it->second;

  return nullptr;
}

bool CConnectionFactory::CloseFile(struct file_open* fh)
{
  if (!fh)
    return false;

  t_locker lock(m_open_mutex);

  auto it = m_opens.find(fh);
  if (it != m_opens.end())
  {
    it->second->CloseFile(fh->handle);

    delete fh;
    m_opens.erase(it);
    it->second->refs--;
  }

  return true;
}

void CConnectionFactory::Release(CConnection* conn)
{
  t_locker lock(m_conn_mutex);
  conn->refs--;
}

void CConnectionFactory::Remove(CConnection *conn)
{
  t_locker lock(m_conn_mutex);

  auto it = m_connections.find(conn->sharename);
  if (it != m_connections.end())
  {
    auto connections = it->second;
    auto itc = std::find_if(connections.begin(), connections.end(), [conn](const CConnection* con) {
      return con == conn;
    });
    if (itc != connections.end())
    {
      delete (*itc);
      connections.erase(itc);
    }
  }
}

void CConnectionFactory::DisconnectAll()
{
  t_locker lock1(m_conn_mutex);
  t_locker lock2(m_open_mutex);

  auto it = m_opens.begin();
  while (it != m_opens.end())
  {
    if (it->second)
    {
      it->second->CloseFile(it->first->handle);
    }

    delete it->first;
    it = m_opens.erase(it);
  }

  auto itc = m_connections.begin();
  while (itc != m_connections.end())
  {
    CConnection* conn = itc->second.front();
    conn->Close();

    delete conn;
    itc->second.clear();

    itc = m_connections.erase(itc);
  }
}

CConnection::CConnection()
  : smb_context(nullptr)
  , lastAccess(0)
  , refs(1)
  , reconnect(false)
{
}

bool CConnection::GetDirectory(const VFSURL & url, std::vector<kodi::vfs::CDirEntry>& items, kodi::addon::CInstanceVFS::CVFSCallbacks callbacks)
{
  struct smb2_url *smburl = smb2_parse_url(smb_context, url.url);
  if (!smburl)
  {
    kodi::Log(ADDON_LOG_ERROR, "failed to parse url: %s", smb2_get_error(smb_context));
    return false;
  }

  struct smb2dir* smbdir = nullptr;
  struct sync_cb_data cb_data = { 0 };
  std::string path = to_smb_path(smburl->path);

  {
    t_locker lock(ctx_mutex);
    if (smb2_opendir_async(smb_context, path.c_str(), cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_opendir_async failed : %s", smb2_get_error(smb_context));
      return false;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: open dir error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return false;
    }
  }

  if (cb_data.status)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: opendir failed: %s", smb2_get_error(smb_context));
    return false;
  }

  smbdir = (struct smb2dir*) cb_data.data;
  smb2dirent *smbdirent = nullptr;
  while ((smbdirent = smb2_readdir(smb_context, smbdir)) != nullptr)
  {
    int64_t iSize = 0;
    bool bIsDir = false;
    int64_t lTimeDate = 0;
    std::string path(std::string(url.url) + std::string(smbdirent->name));

    iSize = smbdirent->st.smb2_size;
    bIsDir = smbdirent->st.smb2_type == SMB2_TYPE_DIRECTORY;
    lTimeDate = smbdirent->st.smb2_mtime;

    if (lTimeDate == 0)
    {
      lTimeDate = smbdirent->st.smb2_ctime;
    }

    kodi::vfs::CDirEntry pItem;
    pItem.SetLabel(smbdirent->name);
    pItem.SetSize(iSize);

    if (bIsDir)
    {
      if (path[path.size() - 1] != '/')
        path += '/';
      pItem.SetFolder(true);
    }
    else
    {
      pItem.SetFolder(false);
    }

    if (smbdirent->name[0] == '.')
    {
      pItem.AddProperty("file:hidden", "true");
    }
    else
    {
      pItem.ClearProperties();
    }
    pItem.SetPath(path);
    items.push_back(pItem);
  }

  smb2_closedir(smb_context, smbdir);
  return true;
}

int CConnection::Stat(const VFSURL &url, struct __stat64* buffer)
{
  struct smb2_url* smburl = smb2_parse_url(smb_context, url.url);
  if (!smburl)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: failed to parse url: %s", smb2_get_error(smb_context));
    return -1;
  }

  std::string path = to_smb_path(smburl->path);

  struct sync_cb_data cb_data = { 0 };
  struct smb2_stat_64 st;

  {
    t_locker lock(ctx_mutex);
    if (smb2_stat_async(smb_context, path.c_str(), &st, cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_stat_async failed : %s", smb2_get_error(smb_context));
      return -1;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: stat error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return -1;
    }
  }

  //if buffer == nullptr we where called from Exists - in that case don't spam the log with errors
  if (cb_data.status != 0 && buffer != nullptr)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: failed to stat(%s) %s", url.filename, smb2_get_error(smb_context));
  }
  else if (buffer)
  {
    memset(buffer, 0, sizeof(struct __stat64));
    buffer->st_ino = st.smb2_ino;
    buffer->st_nlink = st.smb2_nlink;
    buffer->st_size = st.smb2_size;
    buffer->st_atime = st.smb2_atime;
    buffer->st_mtime = st.smb2_mtime;
    buffer->st_ctime = st.smb2_ctime;
  }
  return cb_data.status;
}

bool CConnection::Delete(const VFSURL & url)
{
  struct sync_cb_data cb_data = { 0 };
  struct smb2_url* smburl = smb2_parse_url(smb_context, url.url);
  if (!smburl)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: failed to parse url: %s", smb2_get_error(smb_context));
    return false;
  }

  std::string path = to_smb_path(smburl->path);

  {
    t_locker lock(ctx_mutex);
    if (smb2_unlink_async(smb_context, path.c_str(), cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_unlink_async failed : %s", smb2_get_error(smb_context));
      return false;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: unlink error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return false;
    }
  }

  return true;
}

bool CConnection::RemoveDirectory(const VFSURL & url)
{
  struct sync_cb_data cb_data = { 0 };
  struct smb2_url* smburl = smb2_parse_url(smb_context, url.url);
  if (!smburl)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: failed to parse url: %s", smb2_get_error(smb_context));
    return false;
  }

  std::string path = to_smb_path(smburl->path);
  if (path.empty())
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: cannot delete tree root");
    return false;
  }

  {
    t_locker lock(ctx_mutex);
    if (smb2_rmdir_async(smb_context, path.c_str(), cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_rmdir_async failed : %s", smb2_get_error(smb_context));
      return false;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: rmdir error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return false;
    }
  }

  return true;
}

bool CConnection::CreateDirectory(const VFSURL & url)
{
  struct sync_cb_data cb_data = { 0 };
  struct smb2_url* smburl = smb2_parse_url(smb_context, url.url);
  if (!smburl)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: failed to parse url: %s", smb2_get_error(smb_context));
    return false;
  }

  std::string path = to_smb_path(smburl->path);
  if (path.empty())
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: path must be in a tree");
    return false;
  }

  {
    t_locker lock(ctx_mutex);
    if (smb2_mkdir_async(smb_context, path.c_str(), cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_mkdir_async failed : %s", smb2_get_error(smb_context));
      return false;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: mkdir error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return false;
    }
  }

  return true;
}

int CConnection::Stat(smb2fh* file, struct __stat64* buffer)
{
  struct sync_cb_data cb_data = { 0 };
  struct smb2_stat_64 st;
  
  {
    t_locker lock(ctx_mutex);
    if (smb2_fstat_async(smb_context, file, &st, cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_fstat_async failed : %s", smb2_get_error(smb_context));
      return -1;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: stat error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return -1;
    }
  }
  
  if (!cb_data.status && buffer)
  {
    memset(buffer, 0, sizeof(struct __stat64));
    buffer->st_ino = st.smb2_ino;
    buffer->st_nlink = st.smb2_nlink;
    buffer->st_size = st.smb2_size;
    buffer->st_atime = st.smb2_atime;
    buffer->st_mtime = st.smb2_mtime;
    buffer->st_ctime = st.smb2_ctime;
  }
  return cb_data.status;
}

struct smb2fh* CConnection::OpenFile(const VFSURL &url, int mode /*= O_RDONLY*/)
{
  struct smb2_url* smburl = smb2_parse_url(smb_context, url.url);
  if (!smburl)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: failed to parse url: %s", smb2_get_error(smb_context));
    return nullptr;
  }

  std::string path = to_smb_path(smburl->path);
  struct smb2fh *file = nullptr;
  struct sync_cb_data cb_data = { 0 };
  
  {
    t_locker lock(ctx_mutex);
    if (smb2_open_async(smb_context, path.c_str(), mode, cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_open_async failed : %s", smb2_get_error(smb_context));
      return nullptr;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: open error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return nullptr;
    }
  }
  
  if (cb_data.status) 
  {
    kodi::Log(ADDON_LOG_INFO, "SMB2: unable to open file: '%s' error: '%s'", smburl->path, smb2_get_error(smb_context));
    return nullptr;
  }

  kodi::Log(ADDON_LOG_DEBUG, "SMB2: opened %s", smburl->path);

  return (struct smb2fh*)cb_data.data;
}

ssize_t CConnection::Read(struct file_open *file, void* lpBuf, size_t uiBufSize)
{
  struct sync_cb_data cb_data = { 0 };

  // don't read more than file has
  if ((file->offset + uiBufSize) > file->size)
    uiBufSize = file->size - file->offset;

  if (!uiBufSize)
    return 0;

  // it's possible
  int max_size = GetChunkSize();
  if (uiBufSize > max_size)
    uiBufSize = max_size;

  {
    t_locker lock(ctx_mutex);
    if (smb2_read_async(smb_context, file->handle, static_cast<uint8_t*>(lpBuf), static_cast<uint32_t>(uiBufSize), cmd_cb, &cb_data))
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_read_async failed : %s", smb2_get_error(smb_context));
      return -1;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: read error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return -1;
    }
  }

  // set offset from handle
  smb2_lseek(smb_context, file->handle, 0, SEEK_CUR, &file->offset);

  return (ssize_t)cb_data.status;
}

ssize_t CConnection::Write(file_open* file, const void* lpBuf, size_t uiBufSize)
{
  struct sync_cb_data cb_data = { 0 };

  if (!uiBufSize)
    return 0;

  // it's possible
  int max_size = GetChunkSize();
  if (uiBufSize > max_size)
    uiBufSize = max_size;

  {
    t_locker lock(ctx_mutex);
    if (smb2_write_async(smb_context, file->handle, (uint8_t*)lpBuf, static_cast<uint32_t>(uiBufSize), cmd_cb, &cb_data))
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_write_async failed : %s", smb2_get_error(smb_context));
      return -1;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: write error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return -1;
    }
  }

  // set offset from handle
  smb2_lseek(smb_context, file->handle, 0, SEEK_CUR, &file->offset);

  return (ssize_t)cb_data.status;
}

int64_t CConnection::Seek(struct file_open *file, int64_t iFilePosition, int iWhence)
{
  int ret = 0;

  // no need to lock lseek (it does nothing on connection)
  ret = smb2_lseek(smb_context, file->handle, iFilePosition, iWhence, &file->offset);
  if (ret < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: seek failed. error( seekpos: %" PRId64 ", whence: %i, %s)",
                               iFilePosition, iWhence, smb2_get_error(smb_context));
    return -1;
  }

  return static_cast<int64_t>(file->offset);
}

int CConnection::Truncate(file_open *file, int64_t size)
{
  struct sync_cb_data cb_data = { 0 };

  {
    t_locker lock(ctx_mutex);
    if (smb2_ftruncate_async(smb_context, file->handle, size, cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_ftruncate_async failed : %s", smb2_get_error(smb_context));
      return -1;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: ftruncate error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return -1;
    }
  }

  return cb_data.status;
}

int64_t CConnection::GetLength(struct file_open *file)
{
  struct sync_cb_data cb_data = { 0 };
  struct smb2_stat_64 tmp;

  {
    t_locker lock(ctx_mutex);
    if (smb2_fstat_async(smb_context, file->handle, &tmp, cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_fstat_async failed : %s", smb2_get_error(smb_context));
      return -1;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: stat error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return -1;
    }
  }

  // it may change
  file->size = tmp.smb2_size;

  return tmp.smb2_size;
}

int64_t CConnection::GetPosition(struct file_open *file)
{
  return static_cast<int64_t>(file->offset);
}

void CConnection::Close()
{
  {
    t_locker lock(ctx_mutex);
    smb2_disconnect_share(smb_context);

    if (smb_context)
      smb2_destroy_context(smb_context);

    smb_context = nullptr;
  }
}

void CConnection::CloseFile(struct smb2fh* file)
{
  if (!file)
    return;

  struct sync_cb_data cb_data = { 0 };

  t_locker lock(ctx_mutex);
  if (smb2_close_async(smb_context, file, cmd_cb, &cb_data) != 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_close_async failed : %s", smb2_get_error(smb_context));
    return;
  }
  if (wait_for_reply(smb_context, cb_data) < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: close error : %s", smb2_get_error(smb_context));
    if (cb_data.reconnect)
      reconnect = true;
  }
}

int CConnection::GetChunkSize()
{
  return std::min(65536u * 4, smb2_get_max_read_size(smb_context));
}

bool CConnection::Echo()
{
  struct sync_cb_data cb_data = { 0 };
  {
    t_locker lock(ctx_mutex);
    if (smb2_echo_async(smb_context, cmd_cb, &cb_data) != 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_echo_async failed : %s", smb2_get_error(smb_context));
      return false;
    }
    if (wait_for_reply(smb_context, cb_data) < 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "SMB2: echo error : %s", smb2_get_error(smb_context));
      if (cb_data.reconnect)
        reconnect = true;
      return false;
    }
  }
  return cb_data.status == 0;
}
