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

//! Implementation of the [PBFT consensus
//! algorithm](https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html),
//! modified for use with Hyperledger Sawtooth.

#![allow(unknown_lints)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use std::process;

use clap::{clap_app, crate_version};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use sawtooth_sdk::consensus::zmq_driver::ZmqDriver;

pub mod config;
pub mod engine;
pub mod error;
pub mod hash;
pub mod message_extensions;
pub mod message_log;
pub mod message_type;
pub mod node;
mod protos;
pub mod state;
pub mod storage;
pub mod timing;

fn main() {
    let args = parse_args();

    let config = match args.log_config {
        Some(path) => {
            // Register deserializer for syslog so we can load syslog appender(s)
            let mut deserializers = log4rs::file::Deserializers::new();
            log4rs_syslog::register(&mut deserializers);

            match log4rs::load_config_file(path, deserializers) {
                Ok(mut config) => {
                    {
                        let root = config.root_mut();
                        root.set_level(args.log_level);
                    }
                    config
                }
                Err(err) => {
                    eprintln!(
                        "Error loading logging configuration file: {:?}\
                         \nFalling back to console logging.",
                        err
                    );
                    get_console_config(args.log_level)
                }
            }
        }
        None => get_console_config(args.log_level),
    };

    log4rs::init_config(config).unwrap_or_else(|err| {
        eprintln!("Error initializing logging configuration: {:?}", err);
        process::exit(1)
    });

    info!("Sawtooth PBFT Engine ({})", env!("CARGO_PKG_VERSION"));

    let pbft_engine = engine::PbftEngine::new();

    let (driver, _stop) = ZmqDriver::new();

    driver
        .start(&args.endpoint, pbft_engine)
        .unwrap_or_else(|err| {
            error!("{}", err);
            process::exit(1);
        });
}

fn get_console_config(log_level: log::LevelFilter) -> Config {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h({l:5.5})} | {({M}:{L}):20.20} | {m}{n}",
        )))
        .build();

    Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(log_level))
        .unwrap_or_else(|err| {
            eprintln!("Error building logging configuration: {:?}", err);
            process::exit(1)
        })
}

fn parse_args() -> PbftCliArgs {
    let matches = clap_app!(sawtooth_pbft =>
        (version: crate_version!())
        (about: "PBFT consensus for Sawtooth")
        (@arg connect: -C --connect +takes_value
         "connection endpoint for validator")
        (@arg verbose: -v --verbose +multiple
         "increase output verbosity")
        (@arg logconfig: -L --log_config +takes_value
         "path to logging config file"))
    .get_matches();

    let log_config = matches.value_of("logconfig").map(|s| s.into());

    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        3 | _ => log::LevelFilter::Trace,
    };

    let endpoint = String::from(
        matches
            .value_of("connect")
            .unwrap_or("tcp://localhost:5050"),
    );

    PbftCliArgs {
        log_config,
        log_level,
        endpoint,
    }
}

pub struct PbftCliArgs {
    log_config: Option<String>,
    log_level: log::LevelFilter,
    endpoint: String,
}
