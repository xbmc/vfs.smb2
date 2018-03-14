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
#include <inttypes.h>

#include "SMBConnection.h"

void* CSMBFile::Open(const VFSURL& url)
{
  struct file_open *file = CConnectionFactory::OpenFile(url);
  return file;
}

void* CSMBFile::OpenForWrite(const VFSURL& url, bool overWrite)
{
  int mode = O_RDWR | O_WRONLY;
  if (!Exists(url))
    mode |= O_CREAT;

  struct file_open *file = CConnectionFactory::OpenFile(url, mode);
  return file;
}

ssize_t CSMBFile::Read(void* context, void* lpBuf, size_t uiBufSize)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CConnection* conn = CConnectionFactory::GetForFile(file);
  if (!conn)
    return -1;

  return conn->Read(file, lpBuf, uiBufSize);
}

ssize_t CSMBFile::Write(void* context, const void* buffer, size_t uiBufSize)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CConnection* conn = CConnectionFactory::GetForFile(file);
  if (!conn)
    return -1;

  return conn->Write(file, buffer, uiBufSize);
}

int64_t CSMBFile::Seek(void* context, int64_t iFilePosition, int iWhence)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CConnection* conn = CConnectionFactory::GetForFile(file);
  if (!conn)
    return -1;

  return conn->Seek(file, iFilePosition, iWhence);
}

int CSMBFile::Truncate(void* context, int64_t size)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CConnection* conn = CConnectionFactory::GetForFile(file);
  if (!conn)
    return -1;

  return conn->Truncate(file, size);
}

int64_t CSMBFile::GetLength(void* context)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CConnection* conn = CConnectionFactory::GetForFile(file);
  if (!conn)
    return -1;

  return conn->GetLength(file);
}

int64_t CSMBFile::GetPosition(void* context)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CConnection* conn = CConnectionFactory::GetForFile(file);
  if (!conn)
    return -1;

  return conn->GetPosition(file);
}

int CSMBFile::GetChunkSize(void * context)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return -1;

  CConnection* conn = CConnectionFactory::GetForFile(file);
  if (!conn)
    return -1;

  return conn->GetChunkSize();
}

int CSMBFile::IoControl(void* context, XFILE::EIoControl request, void* param)
{
  if(request == XFILE::IOCTRL_SEEK_POSSIBLE)
    return 1;

  return -1;
}

bool CSMBFile::Close(void* context)
{
  struct file_open* file = reinterpret_cast<struct file_open*>(context);
  if (!file)
    return false;

  return CConnectionFactory::CloseFile(file);
}

int CSMBFile::Stat(const VFSURL& url, struct __stat64* buffer)
{
  CConnection *conn = CConnectionFactory::Acquire(url);
  if (!conn)
    return -1;

  auto res = conn->Stat(url, buffer);

  CConnectionFactory::Release(conn);
  return res;
}

bool CSMBFile::Exists(const VFSURL& url)
{
  return Stat(url, nullptr) == 0;
}

bool CSMBFile::Delete(const VFSURL & url)
{
  CConnection *conn = CConnectionFactory::Acquire(url);
  if (!conn)
    return false;

  auto res = conn->Delete(url);

  CConnectionFactory::Release(conn);
  return res;
}

void CSMBFile::ClearOutIdle()
{
  CConnectionFactory::CheckIfIdle();
}

void CSMBFile::DisconnectAll()
{
  CConnectionFactory::DisconnectAll();
}

bool CSMBFile::GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks)
{
  CConnection *conn = CConnectionFactory::Acquire(url);
  if (!conn)
    return false;

  auto res = conn->GetDirectory(url, items, callbacks);

  CConnectionFactory::Release(conn);
  return res;
}

bool CSMBFile::DirectoryExists(const VFSURL & url)
{
  struct __stat64 st;
  return Stat(url, &st) == 0 && st.st_ino == 1;
}

bool CSMBFile::RemoveDirectory(const VFSURL & url)
{
  CConnection *conn = CConnectionFactory::Acquire(url);
  if (!conn)
    return false;

  auto res = conn->RemoveDirectory(url);

  CConnectionFactory::Release(conn);
  return res;
}

bool CSMBFile::CreateDirectory(const VFSURL & url)
{
  CConnection *conn = CConnectionFactory::Acquire(url);
  if (!conn)
    return false;

  auto res = conn->CreateDirectory(url);

  CConnectionFactory::Release(conn);
  return res;
}
