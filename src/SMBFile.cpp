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

  return Stat(url, nullptr) == 0;
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

void CSMBFile::ClearOutIdle()
{
  CSMBSessionManager::CheckIfIdle();
}

void CSMBFile::DisconnectAll()
{
  CSMBSessionManager::DisconnectAll();
}

bool CSMBFile::GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks)
{
  if (!strlen(url.sharename))
    return false;

  CSMBSessionPtr conn = CSMBSessionManager::Open(url);
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

  auto res = conn->GetDirectory(url, items);
  return res;
}

bool CSMBFile::DirectoryExists(const VFSURL& url)
{
  if (!strlen(url.sharename))
    return false;

  struct __stat64 st;
  return Stat(url, &st) == 0 && st.st_ino == 1;
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
