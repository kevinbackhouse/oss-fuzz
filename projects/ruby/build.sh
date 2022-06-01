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
./configure --enable-shared

make -j $(nproc)

mkdir -p exe
ln -s ../ruby exe/ruby

make install -j $(nproc)

ruby_version=$(basename `find . -name 'ruby-*.pc'` .pc)
export RUBY_LIB_DIR=$(pkg-config --variable=libdir $ruby_version)
export RUBY_LIBRARIES=$(pkg-config --variable=LIBRUBYARG_SHARED $ruby_version)
export RUBY_INCLUDES=$(pkg-config --cflags $ruby_version)
export RUBY_RUBYLIBDIR=$(pkg-config --variable=rubylibdir $ruby_version)

cd $SRC/fuzz
ruby gen_fuzz_wrapper.rb > init_ruby_load_paths.h
${CC} ${CFLAGS} fuzz_ruby_gems.c -o $OUT/fuzz_ruby_gems \
    -Wall \
    -Wl,-rpath,./lib \
    -L${RUBY_LIB_DIR} \
    ${RUBY_INCLUDES} \
    ${RUBY_LIBRARIES} \
    ${LIB_FUZZING_ENGINE}

# Copy options to out
cp $SRC/fuzz/*.options $OUT/
cp -r $RUBY_LIB_DIR $OUT/lib
