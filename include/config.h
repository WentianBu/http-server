#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    int load_mime_types(const char *filename);
    char *get_mime_type(const char *ext);

#ifdef __cplusplus
}
#endif