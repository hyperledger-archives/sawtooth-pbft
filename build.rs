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

extern crate protoc_rust;

use protoc_rust::Customize;

use std::fs;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    fs::create_dir_all("src/protos").unwrap();

    // Run protoc
    protoc_rust::run(protoc_rust::Args {
        out_dir: "src/protos",
        input: &[
            "protos/pbft_message.proto",
        ],
        includes: &["protos"],
        customize: Customize {
            ..Default::default()
        },
    }).expect("Protoc Error");

    // Create mod.rs accordingly
    let mut mod_file = File::create("src/protos/mod.rs").unwrap();
    mod_file.write_all(b"pub mod pbft_message;\n").unwrap();
}
