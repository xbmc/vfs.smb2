/*
 *  Copyright (C) 2005-2020 Team Kodi
 *  https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include <inttypes.h>
extern "C"
{
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
}

#include "SMBSession.h"
#include <kodi/Network.h>
#include <algorithm>
#include <locale>

//6 mins (360s) cached context timeout
#define CONTEXT_TIMEOUT 360000
// max size of smb credit
#define SMB2_MAX_CREDIT_SIZE 65536

struct file_open
{
  CSMBSessionPtr session;
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

mutex_t CSMBSessionManager::m_sess_mutex;
session_map_t CSMBSessionManager::m_sessions;
int CSMBSessionManager::m_lastError = 0;

static std::string to_tree_path(const VFSURL &url)
{
  if (strlen(url.filename) <= strlen(url.sharename) + 1)
    return "";

  std::string strPath(url.filename + strlen(url.sharename) + 1);
  std::replace(strPath.begin(), strPath.end(), '/', '\\');

  if (strPath.back() == '\\')
    strPath = strPath.substr(0, strPath.size() - 1);

  return strPath;
}

static void cmd_cb(struct smb2_context* smb2, int status, void* command_data, void* private_data)
{
  struct sync_cb_data *cb_data = static_cast<struct sync_cb_data *>(private_data);
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
      cb_data.status = wsa_err;
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
      cb_data.status = -1;
      return -1;
    }
  }
  return 0;
}

std::string get_host_name()
{
  std::string result;
  char* buf = new char[256];
  if (!gethostname(buf, 256))
  {
    result = buf;
  }
  delete[] buf;
  return result;
}

void smb2_stat_to_system(struct smb2_stat_64& smb2_st, struct __stat64& sys_st)
{
  sys_st.st_ino = static_cast<_ino_t>(smb2_st.smb2_ino);
  sys_st.st_mode = smb2_st.smb2_type == SMB2_TYPE_DIRECTORY ? S_IFDIR : 0;
  sys_st.st_nlink = smb2_st.smb2_nlink;
  sys_st.st_size = smb2_st.smb2_size;
  sys_st.st_atime = smb2_st.smb2_atime;
  sys_st.st_mtime = smb2_st.smb2_mtime;
  sys_st.st_ctime = smb2_st.smb2_ctime;
}

CSMBSessionPtr CSMBSessionManager::Open(const VFSURL &url)
{
  std::string hostname = url.hostname;
  std::string sharename = url.sharename;
  std::string domain = !strlen(url.domain) ? "MicrosoftAccount" : url.domain;
  std::string username = !strlen(url.username) ? "Guest" : url.username;
  std::string password = url.password;
  std::string key = domain + ';' + username + '@' + hostname + '/' + sharename;
  std::transform(key.begin(), key.end(), key.begin(), ::tolower);

  locker_t lock(m_sess_mutex);

  CSMBSessionPtr session = m_sessions[key];
  if (session && session->IsValid())
  {
    return session;
  }

  // open new session
  CSMBSessionPtr new_sess = CSMBSessionPtr(new CSMBSession(hostname, domain, username, password, sharename));
  m_lastError = new_sess->GetLastError();

  if (!new_sess->IsValid())
    return nullptr;

  m_sessions[key] = new_sess;

  return new_sess;
}

void* CSMBSessionManager::OpenFile(const VFSURL& url, int mode /*= O_RDONLY*/)
{
  CSMBSessionPtr session = Open(url);
  if (!session)
    return nullptr;

  struct file_open* file = session->OpenFile(url, mode);
  if (file)
  {
    file->session = session;
  }
  return file;
}

void CSMBSessionManager::DisconnectAll()
{
  locker_t lock(m_sess_mutex);
  m_sessions.clear();
}

void CSMBSessionManager::CheckIfIdle()
{
  for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it)
  {
    if (it->second && it->second->IsIdle())
    {
      if (it->second->HasOpens())
      {
        // send ping to keep session alive
        it->second->Echo();
      }
      else
      {
        // close unused sessions
        it->second.reset();
      }
    }
  }
}

CSMBSession::CSMBSession(std::string& hostname, std::string& domain, std::string& username
                       , std::string& password, std::string& sharename)
  : reconnect(false)
{
  if (!Connect(hostname, domain, username, password, sharename))
    Close();

  lastAccess = std::chrono::system_clock::now();
}

CSMBSessionPtr CSMBSession::GetForContext(void* context)
{
  struct file_open* file = static_cast<struct file_open*>(context);
  return file->session;
}

bool CSMBSession::Connect(std::string& hostname, std::string& domain, std::string& username
                        , std::string& password, std::string& sharename)
{
  smb_context = smb2_init_context();

  std::string localhost = get_host_name();
  if (!localhost.empty())
    smb2_set_workstation(smb_context, localhost.c_str());
  smb2_set_domain(smb_context, domain.c_str());
  smb2_set_user(smb_context, username.c_str());
  smb2_set_password(smb_context, password.c_str());

  smb2_set_security_mode(smb_context, SMB2_NEGOTIATE_SIGNING_ENABLED);

  lastError = smb2_connect_share(smb_context, hostname.c_str(), sharename.c_str(), nullptr);

  if (lastError < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: connect to share '%s' at server '%s' failed. %s"
                             , sharename.c_str(), hostname.c_str(), smb2_get_error(smb_context));
    smb2_destroy_context(smb_context);
    smb_context = nullptr;

    return false;
  }

  kodi::Log(ADDON_LOG_DEBUG, "SMB2: connected to server '%s' and share '%s'", hostname.c_str(), sharename.c_str());

  return true;
}

CSMBSession::~CSMBSession()
{
  locker_t lock(ctx_mutex);
  Close();
}

bool CSMBSession::IsIdle() const
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - lastAccess).count() > CONTEXT_TIMEOUT;
}

bool CSMBSession::GetShares(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items)
{
  struct sync_cb_data cb_data = { 0 };

  if (!IsValid())
    return false;

  lastAccess = std::chrono::system_clock::now();
  int ret = ProcessAsync("share_enum", cb_data, [](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_share_enum_async(ctx, cb, &data);
  });

  if (cb_data.status)
  {
    lastError = ret;
    kodi::Log(ADDON_LOG_ERROR, "SMB2: share_enum failed: %s", smb2_get_error(smb_context));
    return false;
  }

  lastError = 0;
  struct srvsvc_netshareenumall_rep* reply = static_cast<struct srvsvc_netshareenumall_rep*>(cb_data.data);
  for (uint32_t i = 0; i < reply->ctr->ctr1.count; ++i)
  {
    // allow visible disk trees only
    if ((reply->ctr->ctr1.array[i].type & 3) != SHARE_TYPE_DISKTREE
      || reply->ctr->ctr1.array[i].type & SHARE_TYPE_HIDDEN)
      continue;

    std::string item_path = std::string(url.url) + std::string(reply->ctr->ctr1.array[i].name);
    if (item_path[item_path.size() - 1] != '/')
      item_path += '/';

    kodi::vfs::CDirEntry pItem;
    pItem.SetLabel(reply->ctr->ctr1.array[i].name);
    pItem.SetFolder(true);
    pItem.SetPath(item_path);
    items.push_back(pItem);
  }
  smb2_free_data(smb_context, reply);

  return true;
}

bool CSMBSession::GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items)
{
  struct sync_cb_data cb_data = { 0 };
  std::string path = to_tree_path(url);

  if (!IsValid())
    return false;

  lastAccess = std::chrono::system_clock::now();
  int ret = ProcessAsync("opendir", cb_data, [&path](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_opendir_async(ctx, path.c_str(), cb, &data);
  });

  if (cb_data.status)
  {
    lastError = ret;
    kodi::Log(ADDON_LOG_ERROR, "SMB2: opendir failed: %s", smb2_get_error(smb_context));
    return false;
  }

  lastError = 0;
  struct smb2dir* smbdir = static_cast<struct smb2dir*>(cb_data.data);
  smb2dirent *smbdirent;
  while ((smbdirent = smb2_readdir(smb_context, smbdir)) != nullptr)
  {
    // don't add parent for tree root
    if (path.empty() && smbdirent->name[0] == '.')
      continue;

    bool bIsDir = smbdirent->st.smb2_type == SMB2_TYPE_DIRECTORY;
    int64_t iSize = smbdirent->st.smb2_size;
    int64_t lTimeDate = smbdirent->st.smb2_mtime;
    std::string item_path = std::string(url.url) + std::string(smbdirent->name);

    if (lTimeDate == 0)
    {
      lTimeDate = smbdirent->st.smb2_ctime;
    }

    kodi::vfs::CDirEntry pItem;
    pItem.SetLabel(smbdirent->name);
    pItem.SetSize(iSize);
    pItem.SetDateTime(lTimeDate);

    if (bIsDir)
    {
      if (item_path[item_path.size() - 1] != '/')
        item_path += '/';
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
    pItem.SetPath(item_path);
    items.push_back(pItem);
  }

  smb2_closedir(smb_context, smbdir);
  return true;
}

int CSMBSession::Stat(const VFSURL& url, struct __stat64* buffer)
{
  std::string path = to_tree_path(url);

  struct sync_cb_data cb_data = { 0 };
  struct smb2_stat_64 st;

  if (!IsValid())
    return -1;

  lastAccess = std::chrono::system_clock::now();
  lastError = ProcessAsync("stat", cb_data, [&path, &st](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_stat_async(ctx, path.c_str(), &st, cb, &data);
  });

  if (cb_data.status == 0 && buffer)
  {
    memset(buffer, 0, sizeof(struct __stat64));
    smb2_stat_to_system(st, *buffer);
  }

  return cb_data.status;
}

bool CSMBSession::Delete(const VFSURL& url)
{
  struct sync_cb_data cb_data = { 0 };
  std::string path = to_tree_path(url);

  if (!IsValid())
    return false;

  lastAccess = std::chrono::system_clock::now();

  ProcessAsync("unlink", cb_data, [&path](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_unlink_async(ctx, path.c_str(), cb, &data);
  });

  return cb_data.status == 0;
}

bool CSMBSession::RemoveDirectory(const VFSURL& url)
{
  struct sync_cb_data cb_data = { 0 };

  std::string path = to_tree_path(url);
  if (path.empty())
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: cannot delete tree root");
    return false;
  }

  if (!IsValid())
    return false;

  lastAccess = std::chrono::system_clock::now();

  ProcessAsync("rmdir", cb_data, [&path](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_rmdir_async(ctx, path.c_str(), cb, &data);
  });

  return cb_data.status = 0;
}

bool CSMBSession::CreateDirectory(const VFSURL& url)
{
  struct sync_cb_data cb_data = { 0 };

  std::string path = to_tree_path(url);
  if (path.empty())
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: path must be in a tree");
    return false;
  }

  if (!IsValid())
    return false;

  lastAccess = std::chrono::system_clock::now();
  lastError = ProcessAsync("mkdir", cb_data, [&path](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_mkdir_async(ctx, path.c_str(), cb, &data);
  });

  return cb_data.status == 0;
}

int CSMBSession::Stat(smb2fh* file, struct __stat64* buffer)
{
  struct sync_cb_data cb_data = { 0 };
  struct smb2_stat_64 st;
  
  if (!IsValid())
    return -1;

  lastAccess = std::chrono::system_clock::now();
  ProcessAsync("fstat", cb_data, [&file, &st](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_fstat_async(ctx, file, &st, cb, &data);
  });


  if (!cb_data.status && buffer)
  {
    memset(buffer, 0, sizeof(struct __stat64));
    smb2_stat_to_system(st, *buffer);
  }
  return cb_data.status;
}

struct file_open* CSMBSession::OpenFile(const VFSURL& url, int mode /*= O_RDONLY*/)
{
  struct file_open *file = nullptr;
  struct sync_cb_data cb_data = { 0 };
  std::string path = to_tree_path(url);

  if (!IsValid())
    return nullptr;

  lastAccess = std::chrono::system_clock::now();
  int ret = ProcessAsync("open", cb_data, [&path, &mode](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_open_async(ctx, path.c_str(), mode, cb, &data);
  });

  if (cb_data.status) 
  {
    lastError = ret;
    kodi::Log(ADDON_LOG_INFO, "SMB2: unable to open file: '%s' error: '%s'", path.c_str(), smb2_get_error(smb_context));
    return nullptr;
  }

  struct smb2fh* fh = static_cast<struct smb2fh*>(cb_data.data);
  if (fh)
  {
    struct __stat64 st;
    if (!Stat(fh, &st))
    {
      file = new file_open;
      file->handle = fh;
      file->path = path;
      file->size = st.st_size;
      file->offset = 0;
      file->mode = mode;

      kodi::Log(ADDON_LOG_DEBUG, "SMB2: opened %s", path.c_str());

      locker_t lock(m_open_mutex);
      m_files.push_back(file);
    }
    else
    {
      kodi::Log(ADDON_LOG_INFO, "SMB2: unable to stat file: '%s' error: '%s'", path.c_str(), smb2_get_error(smb_context));
      CloseHandle(fh);
    }
  }

  return file;
}

bool CSMBSession::Rename(const VFSURL & url, const VFSURL & url2)
{
  struct sync_cb_data cb_data = { 0 };
  std::string oldpath = to_tree_path(url);
  std::string newpath = to_tree_path(url2);

  if (!IsValid())
    return false;

  lastAccess = std::chrono::system_clock::now();
  int ret = ProcessAsync("rename", cb_data, [&oldpath, &newpath](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_rename_async(ctx, oldpath.c_str(), newpath.c_str(), cb, &data);
  });

  if (cb_data.status)
  {
    lastError = ret;
    kodi::Log(ADDON_LOG_INFO, "SMB2: unable to rename file: '%s' error: '%s'", oldpath.c_str(), smb2_get_error(smb_context));
    return false;
  }

  return cb_data.status == 0;
}

bool CSMBSession::CloseFile(void* context)
{
  struct file_open* file = static_cast<struct file_open*>(context);
  if (!file)
    return false;

  auto it = std::find(m_files.begin(), m_files.end(), file);
  if (it != m_files.end())
  {
    locker_t lock(m_open_mutex);
    m_files.erase(it);
  }

  CloseHandle(file->handle);
  delete file;

  return true;
}

ssize_t CSMBSession::Read(void* context, void* lpBuf, size_t uiBufSize)
{
  struct file_open* file = static_cast<struct file_open*>(context);
  if (!file->handle || !IsValid())
    return -1;

  struct sync_cb_data cb_data = { 0 };
  lastAccess = std::chrono::system_clock::now();

  // don't read more than file has
  if ((file->offset + uiBufSize) > file->size)
    uiBufSize = file->size - file->offset;

  if (!uiBufSize)
    return 0;

  // it's possible
  int max_size = GetChunkSize(file);
  if (uiBufSize > max_size)
    uiBufSize = max_size;

  struct smb2fh* fh = file->handle;
  int ret = ProcessAsync("open", cb_data, [&fh, &lpBuf, &uiBufSize](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_read_async(ctx, fh, static_cast<uint8_t*>(lpBuf), static_cast<uint32_t>(uiBufSize), cb, &data);
  });

  if (ret < 0)
    return -1;

  lastError = 0;
  // set offset from handle
  smb2_lseek(smb_context, fh, 0, SEEK_CUR, &file->offset);

  return static_cast<ssize_t>(cb_data.status);
}

ssize_t CSMBSession::Write(void* context, const void* lpBuf, size_t uiBufSize)
{
  struct file_open* file = static_cast<struct file_open*>(context);
  if (!file->handle || !IsValid())
    return -1;

  struct sync_cb_data cb_data = { 0 };
  lastAccess = std::chrono::system_clock::now();

  if (!uiBufSize)
    return 0;

  // it's possible
  int max_size = GetChunkSize(file);
  if (uiBufSize > max_size)
    uiBufSize = max_size;

  struct smb2fh* fh = file->handle;
  int ret = ProcessAsync("write", cb_data, [&fh, &lpBuf, &uiBufSize](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_write_async(ctx, fh, (uint8_t*)lpBuf, static_cast<uint32_t>(uiBufSize), cb, &data);
  });

  if (ret < 0)
    return -1;

  lastError = 0;
  // set offset from handle
  smb2_lseek(smb_context, fh, 0, SEEK_CUR, &file->offset);

  return static_cast<ssize_t>(cb_data.status);
}

int64_t CSMBSession::Seek(void* context, int64_t iFilePosition, int iWhence)
{
  struct file_open* file = static_cast<struct file_open*>(context);
  if (!file->handle)
    return -1;

  lastAccess = std::chrono::system_clock::now();

  // no need to lock lseek (it does nothing on connection)
  int ret = smb2_lseek(smb_context, file->handle, iFilePosition, iWhence, &file->offset);
  if (ret == -EINVAL)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: seek failed. error( seekpos: %" PRId64 ", whence: %i, %s)"
      , iFilePosition, iWhence, smb2_get_error(smb_context));
    return -1;
  }

  return file->offset;
}

int CSMBSession::Truncate(void* context, int64_t size)
{
  struct file_open* file = static_cast<struct file_open*>(context);
  if (!file->handle || !IsValid())
    return -1;

  struct sync_cb_data cb_data = { 0 };

  lastAccess = std::chrono::system_clock::now();

  struct smb2fh* fh = file->handle;
  int ret = ProcessAsync("ftruncate", cb_data, [&fh, &size](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_ftruncate_async(ctx, fh, static_cast<uint64_t>(size), cb, &data);
  });

  lastError = ret;
  if (ret != 0)
    return -1;

  return cb_data.status;
}

int64_t CSMBSession::GetLength(void* context)
{
  struct file_open* file = static_cast<struct file_open*>(context);
  if (!file->handle || !IsValid())
    return -1;

  struct sync_cb_data cb_data = { 0 };
  struct smb2_stat_64 tmp;

  lastAccess = std::chrono::system_clock::now();

  struct smb2fh* fh = file->handle;
  int ret = ProcessAsync("fstat", cb_data, [&fh, &tmp](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_fstat_async(ctx, fh, &tmp, cb, &data);
  });
  lastError = ret;

  if (ret != 0)
    return -1;

  // it may change
  file->size = tmp.smb2_size;

  return tmp.smb2_size;
}

int64_t CSMBSession::GetPosition(void* context) const
{
  struct file_open* file = static_cast<struct file_open*>(context);
  if (!file->handle)
    return -1;

  return static_cast<int64_t>(file->offset);
}

void CSMBSession::Close()
{
  locker_t lock(ctx_mutex);

  if (!m_files.empty())
  {
    auto copy = m_files;
    for (auto it = copy.begin(); it != copy.end(); ++it)
    {
      CloseFile((*it));
    }
  }

  if (smb_context)
  {
    if (!reconnect) // means that already disconnected
      smb2_disconnect_share(smb_context);

    smb2_destroy_context(smb_context);
  }
  smb_context = nullptr;
}

void CSMBSession::CloseHandle(struct smb2fh* file)
{
  if (!file)
    return;

  if (!IsValid())
  {
    free(file);
    return;
  }

  struct sync_cb_data cb_data = { 0 };
  lastAccess = std::chrono::system_clock::now();

  lastError = ProcessAsync("close", cb_data, [&file](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_close_async(ctx, file, cb, &data);
  });
}

int CSMBSession::GetChunkSize(void* context) const
{
  struct file_open* file = static_cast<struct file_open*>(context);

  uint32_t chunk_size;
  uint32_t smb_chunks = static_cast<uint32_t>(file->size / SMB2_MAX_CREDIT_SIZE);

  if (smb_chunks <= 0x10) // 1MB
    chunk_size = SMB2_MAX_CREDIT_SIZE;
  else if (smb_chunks <= 0x100) // 16MB
    chunk_size = SMB2_MAX_CREDIT_SIZE << 1;
  else if (smb_chunks <= 0x1000) // 256MB
    chunk_size = SMB2_MAX_CREDIT_SIZE << 2;
  else
    chunk_size = SMB2_MAX_CREDIT_SIZE << 4; // 1Mb for large files

  return std::min(chunk_size, smb2_get_max_read_size(smb_context));
}

bool CSMBSession::Echo()
{
  if (!IsValid())
    return false;

  struct sync_cb_data cb_data = { 0 };
  lastAccess = std::chrono::system_clock::now();

  lastError = ProcessAsync("echo", cb_data, [](smb_ctx ctx, smb_cb cb, smb_data data) {
    return smb2_echo_async(ctx, cb, &data);
  });

  return lastError == 0;
}

int CSMBSession::ProcessAsync(const std::string& cmd, struct sync_cb_data& cb_data, async_func func)
{
  locker_t lock(ctx_mutex);

  int ret;
  if ((ret = func(smb_context, cmd_cb, cb_data)) != 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: smb2_%s_async failed : %s", cmd.c_str(), smb2_get_error(smb_context));
    return ret;
  }

  if (wait_for_reply(smb_context, cb_data) < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB2: %s error : %s", cmd.c_str(), smb2_get_error(smb_context));
    if (cb_data.reconnect)
      reconnect = true;
    return -1;
  }

  return cb_data.status;
}
