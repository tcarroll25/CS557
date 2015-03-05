#include "refmon.hpp"
#include "helpers.hpp"

/* Check for permissions for index send
 * 
 * return true if OK
 * false otherwise
 */
bool check_send_permissions(string user, string group, string stored_user, 
                            string stored_group, string group_dir, bool exists) {

    /* If the index exists already */
    if (exists) {
        // Same author, no group, store it.
        if (user.compare(stored_user) == 0) {
            return true;
        }
        // Check if stored group
        else if (stored_group.length() == 0) {
            // No stored group and not user
            return false;
        }
        // Group Check
        else {
            // If the user exists in stored_group, store it.
            if (check_group_for_user(user, stored_group, group_dir)) {
                return true;
            }
            return false;
        }
    }
    /* New index */
    else {
        // No groups, store it.
        if ( (group.length() == 0) && (stored_group.length() == 0) ) {
            return true;
        }
        else {
            // If user exists in the group, store it.
            if (check_group_for_user(user, group, group_dir)) {
                return true;
            }
            return false;
        }
    }
}


/* 
 * Check permissions on index request
 *
 * return true if OK
 * false otherwise
 */
bool check_get_permissions(string user, string stored_user,
                            string stored_group, string group_dir) {

    /* If the user wrote it, get it */
    if (user.compare(stored_user) == 0) {
        return true;
    }

    /* If user is in group file, get it */
    if (check_group_for_user(user, stored_group, group_dir)) {
        return true;
    }

    return false;
}
