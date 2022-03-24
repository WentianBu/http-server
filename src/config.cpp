#include "config.h"

#include <iostream>
#include <fstream>
#include <string>
#include <list>
#include <unordered_map>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

unordered_map<string, string> mime_types;
json cfg;

int load_mime_types(const char *filename)
{
    ifstream fin(filename);
    if (!fin.is_open())
        return -1; // cannot open file
    const int bl = 256;
    char line[bl] = {0};

    while (fin.getline(line, bl - 1))
    {
        if (!line[0])
            continue;

        vector<int> starts;
        starts.reserve(8);
        bool status = false;
        for (int i = 0; i < bl; ++i)
        {
            if (line[i] == ' ' || line[i] == '\t' || line[i] == ';')
            {
                line[i] = 0; // set all seperators to \0
                status = false;
            }
            else if (line[i] != 0 && !status)
            {
                starts.push_back(i); // record the start of a substring
                status = true;
            }
        }
        if (starts.size() < 2)
            return -1; // parse error
        string mimetype = line + starts[0];

        for (int i = 1; i < starts.size(); i++)
        {
            string ext = line + starts[i];
            mime_types[ext] = mimetype;
        }

        memset(line, 0, bl); // must empty the buf
    }
    return 0;
}

char *get_mime_type(const char *ext)
{
    char *ret = (char *)malloc(256);
    if (ext[0] == 0)
    {
        strcpy(ret, "application/octet-stream");
        return ret;
    }

    string file_ext = ext;
    unordered_map<string, string>::iterator it = mime_types.find(file_ext);

    memset(ret, 0, 256);
    if (it == mime_types.end())
        strcpy(ret, "application/octet-stream");
    else
        strcpy(ret, it->second.c_str());
    return ret; // must free by caller
}

int load_config(const char *config_fn)
{
    std::ifstream cfg_if(config_fn);
    if (!cfg_if)
        return -1;
}
