#!/bin/bash -eu
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

export ASAN_OPTIONS="detect_leaks=0"
export UBSAN_OPTIONS="detect_leaks=0"

./autogen.sh
cflags="${CFLAGS}" optflags="" ./configure
make -j $(nproc)
make install -j $(nproc)

ruby_version=$(basename `find . -name 'ruby-*.pc'` .pc)
RUBY_LIB_DIR=$(pkg-config --variable=libdir $ruby_version)
RUBY_LIBRARIES=$(pkg-config --variable=LIBRUBYARG_STATIC $ruby_version)
RUBY_INCLUDES=$(pkg-config --cflags $ruby_version)

find $RUBY_LIB_DIR -name "json*"

cd $SRC/fuzz
${CXX} ${CXXFLAGS} abstract-fuzzer.cpp ruby-fuzzer.cpp -o $OUT/fuzz_ruby \
    -std=c++20 \
    -Wall \
    -L${RUBY_LIB_DIR} \
    ${RUBY_INCLUDES} \
    ${RUBY_LIBRARIES} \
    ${LIB_FUZZING_ENGINE}

#    -g -O0 -fdeclspec -fno-omit-frame-pointer -fno-common \
#    -fsanitize=address,fuzzer \

# Copy options to out
cp $SRC/fuzz/*.options $OUT/
