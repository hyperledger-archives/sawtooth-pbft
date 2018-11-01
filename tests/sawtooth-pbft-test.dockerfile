# Copyright 2018 Intel Corporation
# Copyright 2018 Bitwise IO, Inc.
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

RUN apt update \
 && apt install gnupg -y

RUN echo "deb [arch=amd64] http://repo.sawtooth.me/ubuntu/nightly bionic universe" >> /etc/apt/sources.list \
 && (apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 44FC67F19B2466EA \
 || apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 44FC67F19B2466EA) \
 && apt-get update \
 && apt-get install -y -q --allow-downgrades \
    build-essential \
    curl \
    libssl-dev \
    gcc \
    git \
    pkg-config \
    python3 \
    python3-sawtooth-cli \
    python3-sawtooth-rest-api \
    python3-sawtooth-settings \
    python3-sawtooth-validator \
    python3-requests \
    python3-nose2 \
    sawtooth-smallbank-workload \
#    sawtooth-smallbank-tp-go \
#    sawtooth-xo-tp-go \
    unzip \
    wget \
    libzmq3-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN wget https://build.sawtooth.me/view/all/job/Sawtooth-Hyperledger/job/sawtooth-sdk-go/view/change-requests/job/PR-18/lastSuccessfulBuild/artifact/build/debs/sawtooth-smallbank-tp-go_0.1.2.dev756_amd64.deb
RUN wget https://build.sawtooth.me/view/all/job/Sawtooth-Hyperledger/job/sawtooth-sdk-go/view/change-requests/job/PR-18/lastSuccessfulBuild/artifact/build/debs/sawtooth-xo-tp-go_0.1.2.dev756_amd64.deb
RUN apt install ./*.deb

RUN curl -OLsS https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
 && unzip protoc-3.5.1-linux-x86_64.zip -d protoc3 \
 && rm protoc-3.5.1-linux-x86_64.zip

RUN curl https://sh.rustup.rs -sSf > /usr/bin/rustup-init \
 && chmod +x /usr/bin/rustup-init \
 && rustup-init -y

ENV PATH=$PATH:/protoc3/bin:/project/sawtooth-core/bin:/root/.cargo/bin \
    CARGO_INCREMENTAL=0

WORKDIR /project/sawtooth-pbft
