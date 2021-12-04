#pragma once

HANDLE duplicate_lsass_handle(DWORD lsass_pid);
HANDLE get_process_handle(DWORD dwPid, DWORD dwFlags, BOOL quiet);
HANDLE fork_lsass_process(DWORD dwPid);
HANDLE find_lsass(void);
