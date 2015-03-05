#include <iostream>
#include <unistd.h>
#include <sys/types.h> 
#include <string.h>
#include <string>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

// Namespace std
using namespace std;

bool check_send_permissions(string user, string group, string stored_user, 
                            string stored_group, string group_dir, bool exists);
bool check_get_permissions(string user, string stored_user,
                            string stored_group, string group_dir);
