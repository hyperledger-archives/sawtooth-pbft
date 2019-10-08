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

//! Storage trait for syncing writes to an object to a backing store
//!
//! Hands out {read, write} RAII-guarded references to an object, and ensures
//! that when the reference drops, any changes to the object are persisted to
//! the selected storage.

pub mod disk;
pub mod memory;

use std::ops::{Deref, DerefMut};

use serde::de::DeserializeOwned;
use serde::Serialize;

pub use self::disk::DiskStorage;
pub use self::memory::MemStorage;

/// RAII structure used to allow read access to state object
///
/// This guard allows avoiding unnecessary syncing if you just need read
/// access to the state object.
pub trait StorageReadGuard<'a, T: Sized>: Deref<Target = T> {}

/// RAII structure used to allow write access to state object
///
/// This guard will ensure that any changes to an object are persisted to
/// a backing store when this is Dropped.
pub trait StorageWriteGuard<'a, T: Sized>: DerefMut<Target = T> {}

/// Storage wrapper that ensures that changes to an object are persisted to a backing store
///
/// Achieves this by handing out RAII-guarded references to the underlying data, that ensure
/// persistence when they get Dropped.
pub trait Storage {
    type S;

    fn read<'a>(&'a self) -> Box<dyn StorageReadGuard<'a, Self::S, Target = Self::S> + 'a>;
    fn write<'a>(&'a mut self) -> Box<dyn StorageWriteGuard<'a, Self::S, Target = Self::S> + 'a>;
}

/// Given a location string, returns the appropriate storage
///
/// Accepts `"memory"` or `"disk+/path/to/file"` as location values
pub fn get_storage<'a, T: Sized + Serialize + DeserializeOwned + 'a, F: Fn() -> T>(
    location: &str,
    default: F,
) -> Result<Box<dyn Storage<S = T> + 'a>, String> {
    if location == "memory" {
        Ok(Box::new(MemStorage::new(default)) as Box<dyn Storage<S = T>>)
    } else if location.starts_with("disk") {
        let split = location.splitn(2, '+').collect::<Vec<_>>();

        if split.len() != 2 {
            return Err(format!("Invalid location: {}", location));
        }

        Ok(Box::new(DiskStorage::from_path(split[1], default).unwrap()))
    } else {
        Err(format!("Unknown storage location type: {}", location))
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use self::rand::distributions::Alphanumeric;
    use self::rand::{thread_rng, Rng};
    use super::*;
    use super::{DiskStorage, MemStorage};
    use std::fs::remove_file;

    // The common use case, of passing in a guarded reference
    fn add_refs(foo: &mut u32, bar: &u32) {
        *foo += bar;
    }

    // You can also pass in the storages themselves
    fn add_storages(foo: &mut dyn (Storage<S = u32>), bar: &mut dyn (Storage<S = u32>)) {
        **foo.write() += **bar.read();
    }

    #[test]
    fn test_read_guard() {
        let filename = String::from("/tmp/")
            + &thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .collect::<String>();

        let storage = DiskStorage::from_path(&filename[..], || 1).unwrap();
        let val = storage.read();
        let other = storage.read();
        assert_eq!(**val, 1);
        assert_eq!(**other, 1);

        remove_file(filename).unwrap();
    }

    #[test]
    // Ensures that data is persisted between object lifetimes
    fn test_disk_persistence() {
        let filename = String::from("/tmp/")
            + &thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .collect::<String>();

        {
            let mut storage = DiskStorage::from_path(&filename[..], || 0).unwrap();
            let mut val = storage.write();
            **val = 5;
            assert_eq!(**val, 5);
        }

        let storage = DiskStorage::from_path(&filename[..], || 0).unwrap();
        let val = storage.read();
        assert_eq!(**val, 5);

        remove_file(filename).unwrap();
    }

    #[test]
    // Ensure we don't overwrite longer data with shorter data, and get a mixture of the two
    fn test_truncation() {
        let filename = String::from("/tmp/")
            + &thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .collect::<String>();

        {
            let storage = DiskStorage::from_path(&filename[..], || 500).unwrap();
            let val = storage.read();
            assert_eq!(**val, 500);
        }

        {
            let mut storage = DiskStorage::from_path(&filename[..], || 0).unwrap();
            let mut val = storage.write();
            assert_eq!(**val, 500);
            **val = 2;
            assert_eq!(**val, 2);
        }

        let storage = DiskStorage::from_path(&filename[..], || 0).unwrap();
        let val = storage.read();
        assert_eq!(**val, 2);

        remove_file(filename).unwrap();
    }

    #[test]
    fn test_write_guard() {
        let filename = String::from("/tmp/")
            + &thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .collect::<String>();

        {
            let mut storage = DiskStorage::from_path(&filename[..], || 1).unwrap();
            let mut val = storage.write();
            assert_eq!(**val, 1);
            **val = 5;
            assert_eq!(**val, 5);
        }

        {
            let mut storage = DiskStorage::from_path(&filename[..], || 1).unwrap();
            let mut val = storage.write();
            assert_eq!(**val, 5);
            **val = 64;
            assert_eq!(**val, 64);
        }

        remove_file(filename).unwrap();
    }

    #[test]
    fn test_fn_arg() {
        let filename = String::from("/tmp/")
            + &thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .collect::<String>();

        let mut diskval = DiskStorage::from_path(&filename[..], || 1).unwrap();
        let mut memval = MemStorage::new(|| 5);

        assert_eq!(**diskval.read(), 1);
        add_refs(&mut *diskval.write(), &*memval.read());
        assert_eq!(**diskval.read(), 6);

        assert_eq!(**memval.read(), 5);
        add_storages(&mut memval, &mut diskval);
        assert_eq!(**memval.read(), 11);

        remove_file(filename).unwrap();
    }

    #[test]
    fn test_get_storage() {
        let filename = String::from("/tmp/")
            + &thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .collect::<String>();

        let memval = get_storage("memory", || 1).unwrap();
        let mut diskval = get_storage(&format!("disk+{}", filename), || 1).unwrap();

        assert_eq!(**memval.read(), 1);

        {
            let mut val = diskval.write();
            **val = 128;
        }

        assert_eq!(**diskval.read(), 128);

        remove_file(filename).unwrap();
    }
}
