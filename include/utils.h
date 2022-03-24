#pragma once
#include <event2/http.h>

char *get_file_ext(const char *filepath);

int get_file_stat(const char *filepath);

const char *get_method_str(enum evhttp_cmd_type t);

char *join_path(const char *base, const char *path);