# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

FROM ubuntu:bionic

RUN apt-get update \
 && apt-get install -y -q --allow-downgrades \
    build-essential \
    curl \
    libssl-dev \
    gcc \
    git \
    libzmq3-dev \
    openssl \
    pkg-config \
    unzip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN curl -OLsS https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
 && unzip protoc-3.5.1-linux-x86_64.zip -d protoc3 \
 && rm protoc-3.5.1-linux-x86_64.zip

ENV PATH=$PATH:/protoc3/bin:/root/.cargo/bin \
    CARGO_INCREMENTAL=0

RUN curl https://sh.rustup.rs -sSf > /usr/bin/rustup-init \
 && chmod +x /usr/bin/rustup-init \
 && rustup-init -y \
 && rustup component add rustfmt-preview \
 && rustup component add clippy-preview \
 && cargo install cargo-deb


WORKDIR /project/sawtooth-pbft

CMD cargo build
