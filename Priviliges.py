#
#עמית נוטמן ועמית נברוצקי



import win32api
import win32con
import win32security


def print_token_privileges(handle):
    """
    checks which privileges the process has and if they are enabled or disabled - prints them and return them in list
    :param handle: the handle of the process token
    :return: list of the privileges and for each if it is enabled or disabled
    """
    privileges = []

    try:
        #win32security.TokenPrivileges - so we can get the privilege list of the process
        privileges = win32security.GetTokenInformation(handle, win32security.TokenPrivileges)
        print("process privileges:")
        for luid, flags in privileges:
            try:
                #translates the luid to privileges name. none - use local computer
                priv_name = win32security.LookupPrivilegeName(None, luid)
                #checks if the bit of enabled is on
                if flags & win32security.SE_PRIVILEGE_ENABLED:
                    status = "Enabled"
                else:
                    status = "Disabled"
                print(f"{priv_name}: {status}")
            except Exception:
                pass
    except Exception as e:
        print(e)

    return privileges



if __name__ == "__main__":
    success = False
    pid_input = input("enter pid: ")

    if pid_input.isdigit():
        pid = int(pid_input)

        try:
            #PROCESS_QUERY_INFORMATION asks to read information, false doesnt need to move handle
            process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            #TOKEN_QUERY allows to read information, TOKEN_ADJUST_PRIVILEGES allows to change privileges, | - ask both things
            token_handle = win32security.OpenProcessToken(process_handle,win32security.TOKEN_QUERY | win32security.TOKEN_ADJUST_PRIVILEGES)

            current_privileges = print_token_privileges(token_handle)

            target_privileges_name = input("enter the privilege to change/add: ").strip()

            # translate the name of privilege (str) to luid
            target_luid = win32security.LookupPrivilegeValue(None, target_privileges_name)

            privilege_exists = False
            new_privilege_enabled_disabled = 0

            for luid, flags in current_privileges:
                if luid == target_luid:
                    privilege_exists = True
                    # If it exists, change the enabled / disabled
                    if flags & win32security.SE_PRIVILEGE_ENABLED:
                        new_privilege_enabled_disabled = 0  # 0 = disabled
                    else:
                        new_privilege_enabled_disabled = win32security.SE_PRIVILEGE_ENABLED
                    break

            # if the loop finished and we never found it, we add it as enabled
            if not privilege_exists:
                new_privilege_enabled_disabled = win32security.SE_PRIVILEGE_ENABLED

            # change the privilege in token
            # AdjustTokenPrivileges gets a list of pairs: [(luid, enabled / disabled)]
            new_privilege = [(target_luid, new_privilege_enabled_disabled)]
            win32security.AdjustTokenPrivileges(token_handle, 0, new_privilege) # 0 - do not disable all privileges

            if win32api.GetLastError() == 1300:
                print("couldnt change privilege")
            else:
                print_token_privileges(token_handle)

        except Exception as e:
            print(e)
    else:
        print("invalid pid - enter numbers only")

