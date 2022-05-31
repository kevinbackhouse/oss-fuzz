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


# Ruby gems are shared objects that need to be dynamically loaded.
# OSS-Fuzz requires all the binary files to be copied to the /out
# directory, so static linking is recommended. But static linking
# prevents the dynamic loading of gems from working. So, instead, we
# need to build ruby with the --enabled-shared flag and copy all the
# relevant shared objects to the /out directory. We also need to
# invoke the fuzzer binary with the LD_LIBRARY_PATH and RUBYLIB
# environment variables set, so that the ruby interpreter is able to
# find those files. This script generates a wrapper bash script that
# calls the fuzzer binary with those environment variables set.

old_lib_dir = ENV["RUBY_LIB_DIR"]

puts "#!/bin/sh"
puts "# LLVMFuzzerTestOneInput for fuzzer detection."
puts "export THIS_DIR=$(dirname $(realpath \"$0\"))"
puts "export THIS_LIB_DIR=\"$THIS_DIR/lib\""
puts "export LD_LIBRARY_PATH=\"$THIS_LIB_DIR:$LD_LIBRARY_PATH\""

n = $LOAD_PATH.length
i = 0
puts "export RUBYLIB=\"\\"
while i < n do
  path = $LOAD_PATH[i]
  if path.start_with?(old_lib_dir)
    puts "$THIS_LIB_DIR" + path.delete_prefix(old_lib_dir) + (i+1 < n ? ":\\" : "\"")
  else
    abort
  end
  i += 1
end
puts "./bin/run_fuzz_ruby_gems $@"
