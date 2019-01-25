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

RUN apt-get update \
  && apt-get install gnupg -y

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb [arch=amd64] http://repo.sawtooth.me/ubuntu/ci bionic universe" >> /etc/apt/sources.list \
 && apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD \
 && apt-get update \
 && apt-get install -y -q --allow-downgrades \
    build-essential \
    git \
    libffi-dev \
    libssl-dev \
    libzmq3-dev \
    python3-pip

RUN apt-get update && apt-get install -y -q --no-install-recommends \
    curl

RUN apt-get update && apt-get install -y -q \
    dvipng \
    latexmk \
    make \
    pkg-config \
    sudo \
    texlive-fonts-recommended \
    texlive-latex-base \
    texlive-latex-extra \
    texlive-latex-recommended \
    zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install \
    sphinx \
    sphinxcontrib-httpdomain \
    sphinx_rtd_theme

RUN curl -OLsS https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
 && unzip protoc-3.5.1-linux-x86_64.zip -d protoc3 \
 && rm protoc-3.5.1-linux-x86_64.zip

RUN curl https://sh.rustup.rs -sSf > /usr/bin/rustup-init \
 && chmod +x /usr/bin/rustup-init \
 && rustup-init -y

ENV PATH=$PATH:/protoc3/bin:/root/.cargo/bin:/project/cli/target/debug \
    CARGO_INCREMENTAL=0

WORKDIR /project/sawtooth-pbft/docs
CMD make html latexpdf
