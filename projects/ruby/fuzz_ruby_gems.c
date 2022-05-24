/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <ruby/ruby.h>
#include <unistd.h>

#define ARRAYSIZE(x) (sizeof(x)/sizeof(x[0]))

enum RubyDataType {
  RDT_CString
};

struct TargetFunction
{
  VALUE obj;
  ID method_id;
  int nargs;
  VALUE *args; // array of length `nargs`
};

VALUE eval(const char *cmd) {
  int state = 0;
  VALUE result = rb_eval_string_protect(cmd, &state);
  if (state != 0) {
    rb_set_errinfo(Qnil);
  }
  
  return result;
}

static VALUE call_protected_helper(VALUE rdata)
{
  struct TargetFunction *data = (struct TargetFunction *)(rdata);
  return rb_funcall2(data->obj, data->method_id, data->nargs, data->args);
};

VALUE call_protected(struct TargetFunction *fcn)
{
  int state = 0;
  VALUE result = rb_protect(call_protected_helper, (VALUE)(fcn), &state);
  if (state != 0) {
    rb_set_errinfo(Qnil);
  }
  return result;
}

VALUE require(const char *module) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "require '%s'\n", module);
  return eval(cmd);
}

struct ByteStream {
  const uint8_t *data_;
  size_t size_;
  size_t pos_;
};

void ByteStream_init(struct ByteStream *bs, const uint8_t *data, size_t size) {
    bs->data_ = data;
    bs->size_ = size;
    bs->pos_ = 0;
}

// Copy bytes from the ByteStream into `data`. Returns 0 on success, -1 on error.
// Error only occurs if there aren't enough bytes remaining in the ByteStream.
int ByteStream_get_bytes(struct ByteStream *bs, uint8_t *data, size_t size) {
  if (size > bs->size_ - bs->pos_) {
    return -1;
  }
  memcpy(data, bs->data_ + bs->pos_, size);
  bs->pos_ += size;
  return 0;
}

// Initialize x with bytes from the ByteStream. Returns -1 on error.
int BytesStream_get_uint32_t(struct ByteStream *bs, uint32_t *x) {
  return ByteStream_get_bytes(bs, (uint8_t*)x, sizeof(x));
}

// Initialize x with bytes from the ByteStream. Returns -1 on error.
int BytesStream_get_uint64_t(struct ByteStream *bs, uint64_t *x) {
  return ByteStream_get_bytes(bs, (uint8_t*)x, sizeof(x));
}

VALUE generate_CString(struct ByteStream *bs) {
  uint64_t size = 0;
  if (BytesStream_get_uint64_t(bs, &size) < 0) {
    return 0;
  }
  if (size > (unsigned long)LONG_MAX) {
    return 0;
  }
  if (size > bs->size_ - bs->pos_) {
    return 0;
  }
  char* data = malloc(size);
  if (!data) {
    return 0;
  }
  VALUE result = 0;
  if (ByteStream_get_bytes(bs, (uint8_t*)data, size) < 0) {
    goto out;
  }
  result = rb_str_new(data, (long)size);

out:
  free(data);
  return result;
}

VALUE generate_value(struct ByteStream *bs, const enum RubyDataType t) {
  switch (t) {
  case RDT_CString:
    return generate_CString(bs);
  default:
    return 0;
  }
}

int fuzz_function(struct ByteStream *bs, const char *module, const char *cls, const char *name, 
                  const int nargs, const enum RubyDataType *argTypes) {
  if (nargs < 0) {
    return -1;
  }
  VALUE *args = calloc(nargs, sizeof(VALUE));
  if (!args) {
    return -1;
  }
  int result = -1;
  int i;
  for (i = 0; i < nargs; i++) {
    VALUE v = generate_value(bs, argTypes[i]);
    if (!v) {
      goto out;
    }
    args[i] = v;
  }

  struct TargetFunction target;
  require(module);
  target.obj = rb_path2class(cls);
  target.method_id = rb_intern(name);
  target.nargs = nargs;
  target.args = args;
  
  result = call_protected(&target);
out:
  free(args);
  return result;
}

static int fuzz_date_strptime(struct ByteStream *bs) {
   enum RubyDataType argTypes[2] = { RDT_CString, RDT_CString };
   return fuzz_function(bs, "date", "Date", "strptime", ARRAYSIZE(argTypes), argTypes);
}

static int fuzz_date_httpdate(struct ByteStream *bs) {
   enum RubyDataType argTypes[2] = { RDT_CString };
   return fuzz_function(bs, "date", "Date", "httpdate", ARRAYSIZE(argTypes), argTypes);
}

static int fuzz_json_parse(struct ByteStream *bs) {
   enum RubyDataType argTypes[1] = { RDT_CString };
   return fuzz_function(bs, "json", "JSON", "parse", ARRAYSIZE(argTypes), argTypes);
}

static int fuzz_psych_parse(struct ByteStream *bs) {
   enum RubyDataType argTypes[1] = { RDT_CString };
   return fuzz_function(bs, "psych", "Psych", "parse", ARRAYSIZE(argTypes), argTypes);
}

typedef int (*fuzz_function_ptr)(struct ByteStream *bs);

static fuzz_function_ptr fuzz_functions[] = {
  fuzz_date_strptime, fuzz_date_httpdate, fuzz_json_parse, fuzz_psych_parse
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char rubylibdir[PATH_MAX];
    char cwd[PATH_MAX];
    struct ByteStream bs = {};

    ByteStream_init(&bs, data, size);

    getcwd(cwd, sizeof(cwd));

    const char *outpath = getenv("OUT");
    if (!outpath) {
      outpath = cwd;
    }
    snprintf(rubylibdir, sizeof(rubylibdir), "%s/rubylibdir", outpath);
    setenv("RUBYLIB", rubylibdir, 0);

    // Initialize the Ruby interpreter.
    static bool ruby_initialized = false;
    if (!ruby_initialized) {
      ruby_initialized = true;
      RUBY_INIT_STACK;
      ruby_init();
      ruby_init_loadpath();
    }

    // Choose a function from `fuzz_functions`.
    uint32_t i = 0;
    if (BytesStream_get_uint32_t(&bs, &i) < 0) {
      goto out;
    }
    fuzz_function_ptr fuzz_fcn = fuzz_functions[i % ARRAYSIZE(fuzz_functions)];

    // Run the ruby gem.
    fuzz_fcn(&bs);

out:
    return 0;
}
