/*
 * Copyright 2018 Bitwise IO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */

//! Disk-backed persistence wrapper

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

use atomicwrites::{AllowOverwrite, AtomicFile};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{from_str, to_string};

use super::{Storage, StorageReadGuard, StorageWriteGuard};

/// A disk-based read guard
pub struct DiskStorageReadGuard<'a, T: Serialize + DeserializeOwned + 'a> {
    storage: &'a DiskStorage<T>,
}

impl<'a, T: Serialize + DeserializeOwned> DiskStorageReadGuard<'a, T> {
    fn new(storage: &'a DiskStorage<T>) -> Self {
        Self { storage }
    }
}

impl<'a, T: Serialize + DeserializeOwned + 'a> Deref for DiskStorageReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.storage.data
    }
}

impl<'a, T: 'a + Serialize + DeserializeOwned + fmt::Display> fmt::Display
    for DiskStorageReadGuard<'a, T>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl<'a, T: 'a + Serialize + DeserializeOwned> StorageReadGuard<'a, T>
    for DiskStorageReadGuard<'a, T>
{
}

/// A disk-based write guard
pub struct DiskStorageWriteGuard<'a, T: Serialize + DeserializeOwned + 'a> {
    storage: &'a mut DiskStorage<T>,
}

impl<'a, T: Serialize + DeserializeOwned> DiskStorageWriteGuard<'a, T> {
    fn new(storage: &'a mut DiskStorage<T>) -> Self {
        Self { storage }
    }
}

impl<'a, T: Serialize + DeserializeOwned> Drop for DiskStorageWriteGuard<'a, T> {
    fn drop(&mut self) {
        self.storage
            .file
            .write(|f| {
                f.write_all(
                    to_string(&self.storage.data)
                        .expect("Couldn't convert value to string!")
                        .as_bytes(),
                )
            })
            .expect("File write failed while dropping DiskStorageWriteGuard!");
    }
}

impl<'a, T: Serialize + DeserializeOwned + 'a> Deref for DiskStorageWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.storage.data
    }
}

impl<'a, T: Serialize + DeserializeOwned + 'a> DerefMut for DiskStorageWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.storage.data
    }
}

impl<'a, T: 'a + Serialize + DeserializeOwned + fmt::Display> fmt::Display
    for DiskStorageWriteGuard<'a, T>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl<'a, T: 'a + Serialize + DeserializeOwned> StorageWriteGuard<'a, T>
    for DiskStorageWriteGuard<'a, T>
{
}

/// A disk-based RAII-guarded Storage implementation
///
/// File writes are atomic
pub struct DiskStorage<T: Serialize + DeserializeOwned> {
    data: T,
    file: AtomicFile,
}

impl<T: Serialize + DeserializeOwned> DiskStorage<T> {
    pub fn from_path<P: Into<String>, F: Fn() -> T>(path: P, default: F) -> Result<Self, String> {
        let path = path.into();

        let file = AtomicFile::new(path, AllowOverwrite);

        // Read the file first, to see if there's any existing data
        let data = match File::open(file.path()) {
            Ok(mut f) => {
                let mut contents = String::new();

                f.read_to_string(&mut contents)
                    .map_err(|err| format!("Couldn't read file: {}", err))?;

                from_str(&contents).map_err(|err| format!("Couldn't read file: {}", err))?
            }
            Err(_) => {
                let data = default();
                file.write(|f| f.write_all(to_string(&data)?.as_bytes()))
                    .map_err(|err| format!("File write failed: {}", err))?;

                data
            }
        };

        // Then open the file again and truncate, preparing it to be written to
        Ok(Self { data, file })
    }
}

impl<T: fmt::Display + Serialize + DeserializeOwned> fmt::Display for DiskStorage<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (*self).data.fmt(f)
    }
}

impl<T: Serialize + DeserializeOwned> Storage for DiskStorage<T> {
    type S = T;

    fn read<'a>(&'a self) -> Box<dyn StorageReadGuard<'a, T, Target = T> + 'a> {
        Box::new(DiskStorageReadGuard::new(self))
    }

    fn write<'a>(&'a mut self) -> Box<dyn StorageWriteGuard<'a, T, Target = T> + 'a> {
        Box::new(DiskStorageWriteGuard::new(self))
    }
}
