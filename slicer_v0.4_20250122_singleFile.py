## Ksign Slicer + Reveal(수집방안) + CPG 신 버전 + 하나의 파일만 처리리##
## 코드 수집은 불러온 소스코드 파일에서 라인에 따라 그대로 가져온다##
## 모든 dir 내의 파일들에 대해서 슬라이스를 수집 ##
""" 250122 - 0.4 version
    패치 예정 내역:
        Sink를 기반으로 Backward 수집 및 제어문 처리
    
    이유:
        0.3 버전의 슬라이스는 원하는대로 잘 수집은 되었지만 다음과 같은 문제가 있음
            1. 종속성만을 고려하니 코드 내의 너무 많은 라인이 수집이 되었음
            2. if - else 혹은 다른 CONTROL_STRUCTURE 노드가 제대로 수집이 안됨
            3. 해당 라인이 어느 Block에 있는지 식별이 안됨
            4. 매크로 상수, 변수 등이 수집되지 않음
    
    패치 상세:
        1. 제어문을 표현하기 위해(Block 표현) .strip을 제거하여 slice를 수집할 예정
            indent를 통해서 Block의 범위를 표현하는데, CPG 파일 상에서는 닫는 브라켓이 없기 때문: 해결
        2. 추가적인 요소 수집
            LOCAL노드, 매크로함수, 구조체 필드, else 등을 추가하기 위한 추가적인 Edge 고려: 해결
        
    수정된 노드

"""
import os
import json
import clang.cindex
import clang.enumerations
import csv
import numpy as np
import re 
import warnings
import requests
import argparse
import sys
import pandas as pd
from tqdm import tqdm

warnings.filterwarnings('ignore')
# std 함수 리스트이며, 2차 목표 슬라이스를 기반으로 제작한다면, 여기서 다른 함수들이 추가되어야 함..
l_funcs = ['StrNCat', 'getaddrinfo', '_ui64toa', 'fclose', 'pthread_mutex_lock', 'gets_s', 'sleep', 
           '_ui64tot', 'freopen_s', '_ui64tow', 'send', 'lstrcat', 'HMAC_Update', '__fxstat', 'StrCatBuff', 
           '_mbscat', '_mbstok_s', '_cprintf_s', 'ldap_search_init_page', 'memmove_s', 'ctime_s', 'vswprintf', 
           'vswprintf_s', '_snwprintf', '_gmtime_s', '_tccpy', '*RC6*', '_mbslwr_s', 'random', 
           '__wcstof_internal', '_wcslwr_s', '_ctime32_s', 'wcsncat*', 'MD5_Init', '_ultoa', 
           'snprintf', 'memset', 'syslog', '_vsnprintf_s', 'HeapAlloc', 'pthread_mutex_destroy', 
           'ChangeWindowMessageFilter', '_ultot', 'crypt_r', '_strupr_s_l', 'LoadLibraryExA', '_strerror_s', 
           'LoadLibraryExW', 'wvsprintf', 'MoveFileEx', '_strdate_s', 'SHA1', 'sprintfW', 'StrCatNW', 
           '_scanf_s_l', 'pthread_attr_init', '_wtmpnam_s', 'snscanf', '_sprintf_s_l', 'dlopen', 
           'sprintfA', 'timed_mutex', 'OemToCharA', 'ldap_delete_ext', 'sethostid', 'popen', 'OemToCharW', 
           '_gettws', 'vfork', '_wcsnset_s_l', 'sendmsg', '_mbsncat', 'wvnsprintfA', 'HeapFree', '_wcserror_s', 
           'realloc', '_snprintf*', 'wcstok', '_strncat*', 'StrNCpy', '_wasctime_s', 'push*', '_lfind_s', 
           'CC_SHA512', 'ldap_compare_ext_s', 'wcscat_s', 'strdup', '_chsize_s', 'sprintf_s', 'CC_MD4_Init', 
           'wcsncpy', '_wfreopen_s', '_wcsupr_s', '_searchenv_s', 'ldap_modify_ext_s', '_wsplitpath', 
           'CC_SHA384_Final', 'MD2', 'RtlCopyMemory', 'lstrcatW', 'MD4', 'MD5', '_wcstok_s_l', '_vsnwprintf_s', 
           'ldap_modify_s', 'strerror', '_lsearch_s', '_mbsnbcat_s', '_wsplitpath_s', 'MD4_Update', '_mbccpy_s', 
           '_strncpy_s_l', '_snprintf_s', 'CC_SHA512_Init', 'fwscanf_s', '_snwprintf_s', 'CC_SHA1', 'swprintf', 
           'fprintf', 'EVP_DigestInit_ex', 'strlen', 'SHA1_Init', 'strncat', '_getws_s', 'CC_MD4_Final', 
           'wnsprintfW', 'lcong48', 'lrand48', 'write', 'HMAC_Init', '_wfopen_s', 'wmemchr', '_tmakepath', 
           'wnsprintfA', 'lstrcpynW', 'scanf_s', '_mbsncpy_s_l', '_localtime64_s', 'fstream.open', '_wmakepath', 
           'Connection.open', '_tccat', 'valloc', 'setgroups', 'unlink', 'fstream.put', 'wsprintfA', '*SHA1*', 
           '_wsearchenv_s', 'ualstrcpyA', 'CC_MD5_Update', 'strerror_s', 'HeapCreate', 'ualstrcpyW', '__xstat', 
           '_wmktemp_s', 'StrCatChainW', 'ldap_search_st', '_mbstowcs_s_l', 'ldap_modify_ext', '_mbsset_s', 
           'strncpy_s', 'move', 'execle', 'StrCat', 'xrealloc', 'wcsncpy_s', '_tcsncpy*', 'execlp', 
           'RIPEMD160_Final', 'ldap_search_s', 'EnterCriticalSection', '_wctomb_s_l', 'fwrite', '_gmtime64_s', 
           'sscanf_s', 'wcscat', '_strupr_s', 'wcrtomb_s', 'VirtualLock', 'ldap_add_ext_s', '_mbscpy', 
           '_localtime32_s', 'lstrcpy', '_wcsncpy*', 'CC_SHA1_Init', '_getts', '_wfopen', '__xstat64', 
           'strcoll', '_fwscanf_s_l', '_mbslwr_s_l', 'RegOpenKey', 'makepath', 'seed48', 'CC_SHA256', 
           'sendto', 'execv', 'CalculateDigest', 'memchr', '_mbscpy_s', '_strtime_s', 'ldap_search_ext_s', 
           '_chmod', 'flock', '__fxstat64', '_vsntprintf', 'CC_SHA256_Init', '_itoa_s', '__wcserror_s', 
           '_gcvt_s', 'fstream.write', 'sprintf', 'recursive_mutex', 'strrchr', 'gethostbyaddr', '_wcsupr_s_l', 
           'strcspn', 'MD5_Final', 'asprintf', '_wcstombs_s_l', '_tcstok', 'free', 'MD2_Final', 'asctime_s', 
           '_alloca', '_wputenv_s', '_wcsset_s', '_wcslwr_s_l', 'SHA1_Update', 'filebuf.sputc', 'filebuf.sputn', 
           'SQLConnect', 'ldap_compare', 'mbstowcs_s', 'HMAC_Final', 'pthread_condattr_init', '_ultow_s', 'rand', 
           'ofstream.put', 'CC_SHA224_Final', 'lstrcpynA', 'bcopy', 'system', 'CreateFile*', 'wcscpy_s', 
           '_mbsnbcpy*', 'open', '_vsnwprintf', 'strncpy', 'getopt_long', 'CC_SHA512_Final', '_vsprintf_s_l', 
           'scanf', 'mkdir', '_localtime_s', '_snprintf', '_mbccpy_s_l', 'memcmp', 'final', '_ultoa_s', 
           'lstrcpyW', 'LoadModule', '_swprintf_s_l', 'MD5_Update', '_mbsnset_s_l', '_wstrtime_s', '_strnset_s', 
           'lstrcpyA', '_mbsnbcpy_s', 'mlock', 'IsBadHugeWritePtr', 'copy', '_mbsnbcpy_s_l', 'wnsprintf', 
           'wcscpy', 'ShellExecute', 'CC_MD4', '_ultow', '_vsnwprintf_s_l', 'lstrcpyn', 'CC_SHA1_Final', 
           'vsnprintf', '_mbsnbset_s', '_i64tow', 'SHA256_Init', 'wvnsprintf', 'RegCreateKey', 'strtok_s', 
           '_wctime32_s', '_i64toa', 'CC_MD5_Final', 'wmemcpy', 'WinExec', 'CreateDirectory*', 
           'CC_SHA256_Update', '_vsnprintf_s_l', 'jrand48', 'wsprintf', 'ldap_rename_ext_s', 'filebuf.open', 
           '_wsystem', 'SHA256_Update', '_cwscanf_s', 'wsprintfW', '_sntscanf', '_splitpath', 'fscanf_s', 
           'strpbrk', 'wcstombs_s', 'wscanf', '_mbsnbcat_s_l', 'strcpynA', 'pthread_cond_init', 'wcsrtombs_s', 
           '_wsopen_s', 'CharToOemBuffA', 'RIPEMD160_Update', '_tscanf', 'HMAC', 'StrCCpy', 'Connection.connect', 
           'lstrcatn', '_mbstok', '_mbsncpy', 'CC_SHA384_Update', 'create_directories', 'pthread_mutex_unlock', 
           'CFile.Open', 'connect', '_vswprintf_s_l', '_snscanf_s_l', 'fputc', '_wscanf_s', '_snprintf_s_l', 
           'strtok', '_strtok_s_l', 'lstrcatA', 'snwscanf', 'pthread_mutex_init', 'fputs', 'CC_SHA384_Init', 
           '_putenv_s', 'CharToOemBuffW', 'pthread_mutex_trylock', '__wcstoul_internal', '_memccpy', 
           '_snwprintf_s_l', '_strncpy*', 'wmemset', 'MD4_Init', '*RC4*', 'strcpyW', '_ecvt_s', 'memcpy_s', 
           'erand48', 'IsBadHugeReadPtr', 'strcpyA', 'HeapReAlloc', 'memcpy', 'ldap_rename_ext', 'fopen_s', 
           'srandom', '_cgetws_s', '_makepath', 'SHA256_Final', 'remove', '_mbsupr_s', 'pthread_mutexattr_init', 
           '__wcstold_internal', 'StrCpy', 'ldap_delete', 'wmemmove_s', '_mkdir', 'strcat', '_cscanf_s_l', 
           'StrCAdd', 'swprintf_s', '_strnset_s_l', 'close', 'ldap_delete_ext_s', 'ldap_modrdn', 'strchr', 
           '_gmtime32_s', '_ftcscat', 'lstrcatnA', '_tcsncat', 'OemToChar', 'mutex', 'CharToOem', 'strcpy_s', 
           'lstrcatnW', '_wscanf_s_l', '__lxstat64', 'memalign', 'MD2_Init', 'StrCatBuffW', 'StrCpyN', 'CC_MD5', 
           'StrCpyA', 'StrCatBuffA', 'StrCpyW', 'tmpnam_r', '_vsnprintf', 'strcatA', 'StrCpyNW', '_mbsnbset_s_l', 
           'EVP_DigestInit', '_stscanf', 'CC_MD2', '_tcscat', 'StrCpyNA', 'xmalloc', '_tcslen', '*MD4*', 
           'vasprintf', 'strxfrm', 'chmod', 'ldap_add_ext', 'alloca', '_snscanf_s', 'IsBadWritePtr', 'swscanf_s', 
           'wmemcpy_s', '_itoa', '_ui64toa_s', 'EVP_DigestUpdate', '__wcstol_internal', '_itow', 'StrNCatW', 
           'strncat_s', 'ualstrcpy', 'execvp', '_mbccat', 'EVP_MD_CTX_init', 'assert', 'ofstream.write', 
           'ldap_add', '_sscanf_s_l', 'drand48', 'CharToOemW', 'swscanf', '_itow_s', 'RIPEMD160_Init', 
           'CopyMemory', 'initstate', 'getpwuid', 'vsprintf', '_fcvt_s', 'CharToOemA', 'setuid', 'malloc', 
           'StrCatNA', 'strcat_s', 'srand', 'getwd', '_controlfp_s', 'olestrcpy', '__wcstod_internal', 
           '_mbsnbcat', 'lstrncat', 'des_*', 'CC_SHA224_Init', 'set*', 'vsprintf_s', 'SHA1_Final', '_umask_s', 
           'gets', 'setstate', 'wvsprintfW', 'LoadLibraryEx', 'ofstream.open', 'calloc', '_mbstrlen', 
           '_cgets_s', '_sopen_s', 'IsBadStringPtr', 'wcsncat_s', 'add*', 'nrand48', 'create_directory', 
           'ldap_search_ext', '_i64toa_s', '_ltoa_s', '_cwscanf_s_l', 'wmemcmp', '__lxstat', 'lstrlen', 
           'pthread_condattr_destroy', '_ftcscpy', 'wcstok_s', '__xmknod', 'pthread_attr_destroy', 'sethostname', 
           '_fscanf_s_l', 'StrCatN', 'RegEnumKey', '_tcsncpy', 'strcatW', 'AfxLoadLibrary', 'setenv', 'tmpnam', 
           '_mbsncat_s_l', '_wstrdate_s', '_wctime64_s', '_i64tow_s', 'CC_MD4_Update', 'ldap_add_s', '_umask', 
           'CC_SHA1_Update', '_wcsset_s_l', '_mbsupr_s_l', 'strstr', '_tsplitpath', 'memmove', '_tcscpy', 
           'vsnprintf_s', 'strcmp', 'wvnsprintfW', 'tmpfile', 'ldap_modify', '_mbsncat*', 'mrand48', 'sizeof', 
           'StrCatA', '_ltow_s', '*desencrypt*', 'StrCatW', '_mbccpy', 'CC_MD2_Init', 'RIPEMD160', 'ldap_search', 
           'CC_SHA224', 'mbsrtowcs_s', 'update', 'ldap_delete_s', 'getnameinfo', '*RC5*', '_wcsncat_s_l', 
           'DriverManager.getConnection', 'socket', '_cscanf_s', 'ldap_modrdn_s', '_wopen', 'CC_SHA256_Final', 
           '_snwprintf*', 'MD2_Update', 'strcpy', '_strncat_s_l', 'CC_MD5_Init', 'mbscpy', 'wmemmove', 
           'LoadLibraryW', '_mbslen', '*alloc', '_mbsncat_s', 'LoadLibraryA', 'fopen', 'StrLen', 'delete', 
           '_splitpath_s', 'CreateFileTransacted*', 'MD4_Final', '_open', 'CC_SHA384', 'wcslen', 'wcsncat', 
           '_mktemp_s', 'pthread_mutexattr_destroy', '_snwscanf_s', '_strset_s', '_wcsncpy_s_l', 'CC_MD2_Final', 
           '_mbstok_s_l', 'wctomb_s', 'MySQL_Driver.connect', '_snwscanf_s_l', '*_des_*', 'LoadLibrary', 
           '_swscanf_s_l', 'ldap_compare_s', 'ldap_compare_ext', '_strlwr_s', 'GetEnvironmentVariable', 
           'cuserid', '_mbscat_s', 'strspn', '_mbsncpy_s', 'ldap_modrdn2', 'LeaveCriticalSection', 'CopyFile', 
           'getpwd', 'sscanf', 'creat', 'RegSetValue', 'ldap_modrdn2_s', 'CFile.Close', '*SHA_1*', 
           'pthread_cond_destroy', 'CC_SHA512_Update', '*RC2*', 'StrNCatA', '_mbsnbcpy', '_mbsnset_s', 
           'crypt', 'excel', '_vstprintf', 'xstrdup', 'wvsprintfA', 'getopt', 'mkstemp', '_wcsnset_s', 
           '_stprintf', '_sntprintf', 'tmpfile_s', 'OpenDocumentFile', '_mbsset_s_l', '_strset_s_l', 
           '_strlwr_s_l', 'ifstream.open', 'xcalloc', 'StrNCpyA', '_wctime_s', 'CC_SHA224_Update', '_ctime64_s', 
           'MoveFile', 'chown', 'StrNCpyW', 'IsBadReadPtr', '_ui64tow_s', 'IsBadCodePtr', 'getc', 
           'OracleCommand.ExecuteOracleScalar', 'AccessDataSource.Insert', 'IDbDataAdapter.FillSchema', 
           'IDbDataAdapter.Update', 'GetWindowText*', 'SendMessage', 'SqlCommand.ExecuteNonQuery', 'streambuf.sgetc', 
           'streambuf.sgetn', 'OracleCommand.ExecuteScalar', 'SqlDataSource.Update', '_Read_s', 'IDataAdapter.Fill', 
           '_wgetenv', '_RecordsetPtr.Open*', 'AccessDataSource.Delete', 'Recordset.Open*', 'filebuf.sbumpc', 'DDX_*', 
           'RegGetValue', 'fstream.read*', 'SqlCeCommand.ExecuteResultSet', 'SqlCommand.ExecuteXmlReader', 'main', 
           'streambuf.sputbackc', 'read', 'm_lpCmdLine', 'CRichEditCtrl.Get*', 'istream.putback', 
           'SqlCeCommand.ExecuteXmlReader', 'SqlCeCommand.BeginExecuteXmlReader', 'filebuf.sgetn', 
           'OdbcDataAdapter.Update', 'filebuf.sgetc', 'SQLPutData', 'recvfrom', 'OleDbDataAdapter.FillSchema', 
           'IDataAdapter.FillSchema', 'CRichEditCtrl.GetLine', 'DbDataAdapter.Update', 'SqlCommand.ExecuteReader', 
           'istream.get', 'ReceiveFrom', '_main', 'fgetc', 'DbDataAdapter.FillSchema', 'kbhit', 'UpdateCommand.Execute*', 
           'Statement.execute', 'fgets', 'SelectCommand.Execute*', 'getch', 'OdbcCommand.ExecuteNonQuery', 
           'CDaoQueryDef.Execute', 'fstream.getline', 'ifstream.getline', 'SqlDataAdapter.FillSchema', 
           'OleDbCommand.ExecuteReader', 'Statement.execute*', 'SqlCeCommand.BeginExecuteNonQuery', 
           'OdbcCommand.ExecuteScalar', 'SqlCeDataAdapter.Update', 'sendmessage', 'mysqlpp.DBDriver', 'fstream.peek', 
           'Receive', 'CDaoRecordset.Open', 'OdbcDataAdapter.FillSchema', '_wgetenv_s', 'OleDbDataAdapter.Update', 
           'readsome', 'SqlCommand.BeginExecuteXmlReader', 'recv', 'ifstream.peek', '_Main', '_tmain', '_Readsome_s', 
           'SqlCeCommand.ExecuteReader', 'OleDbCommand.ExecuteNonQuery', 'fstream.get', 'IDbCommand.ExecuteScalar', 
           'filebuf.sputbackc', 'IDataAdapter.Update', 'streambuf.sbumpc', 'InsertCommand.Execute*', 'RegQueryValue', 
           'IDbCommand.ExecuteReader', 'SqlPipe.ExecuteAndSend', 'Connection.Execute*', 'getdlgtext', 'ReceiveFromEx', 
           'SqlDataAdapter.Update', 'RegQueryValueEx', 'SQLExecute', 'pread', 'SqlCommand.BeginExecuteReader', 'AfxWinMain', 
           'getchar', 'istream.getline', 'SqlCeDataAdapter.Fill', 'OleDbDataReader.ExecuteReader', 'SqlDataSource.Insert', 
           'istream.peek', 'SendMessageCallback', 'ifstream.read*', 'SqlDataSource.Select', 'SqlCommand.ExecuteScalar', 
           'SqlDataAdapter.Fill', 'SqlCommand.BeginExecuteNonQuery', 'getche', 'SqlCeCommand.BeginExecuteReader', 'getenv', 
           'streambuf.snextc', 'Command.Execute*', '_CommandPtr.Execute*', 'SendNotifyMessage', 'OdbcDataAdapter.Fill', 
           'AccessDataSource.Update', 'fscanf', 'QSqlQuery.execBatch', 'DbDataAdapter.Fill', 'cin', 
           'DeleteCommand.Execute*', 'QSqlQuery.exec', 'PostMessage', 'ifstream.get', 'filebuf.snextc', 
           'IDbCommand.ExecuteNonQuery', 'Winmain', 'fread', 'getpass', 'GetDlgItemTextCCheckListBox.GetCheck', 
           'DISP_PROPERTY_EX', 'pread64', 'Socket.Receive*', 'SACommand.Execute*', 'SQLExecDirect', 
           'SqlCeDataAdapter.FillSchema', 'DISP_FUNCTION', 'OracleCommand.ExecuteNonQuery', 'CEdit.GetLine', 
           'OdbcCommand.ExecuteReader', 'CEdit.Get*', 'AccessDataSource.Select', 'OracleCommand.ExecuteReader', 
           'OCIStmtExecute', 'getenv_s', 'DB2Command.Execute*', 'OracleDataAdapter.FillSchema', 'OracleDataAdapter.Fill', 
           'CComboBox.Get*', 'SqlCeCommand.ExecuteNonQuery', 'OracleCommand.ExecuteOracleNonQuery', 'mysqlpp.Query', 
           'istream.read*', 'CListBox.GetText', 'SqlCeCommand.ExecuteScalar', 'ifstream.putback', 'readlink', 
           'CHtmlEditCtrl.GetDHtmlDocument', 'PostThreadMessage', 'CListCtrl.GetItemText', 'OracleDataAdapter.Update', 
           'OleDbCommand.ExecuteScalar', 'stdin', 'SqlDataSource.Delete', 'OleDbDataAdapter.Fill', 'fstream.putback', 
           'IDbDataAdapter.Fill', '_wspawnl', 'fwprintf', 'sem_wait', '_unlink', 'ldap_search_ext_sW', 'signal', 'PQclear', 
           'PQfinish', 'PQexec', 'PQresultStatus', 'atoi'
           ]



""" adj_list 및 라인 수집 방안 수정 예정
"""
def combine_adjacency_list(adjacency_list):
    cgraph = {}
    for ln in adjacency_list:
        cgraph[ln] = set()
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][0])
        # cgraph[ln] = cgraph[ln].union(adjacency_list[ln][1])
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][2])
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][3])
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][4])
    return cgraph


def invert_graph(adjacency_list):
    igraph = {}
    for ln in adjacency_list.keys():
        igraph[ln] = set()
    for ln in adjacency_list:
        adj = adjacency_list[ln]
        for node in adj:
            igraph[node].add(ln)
    return igraph
    pass


# 결국 라인 수집, 이 전에 그래프를 잘 만들어놓으면 얘는 그냥 로직대로, 수집할 뿐이다.
# 대신, 특정 노드를 그대로 수집하는게 아닌, ln을 수집하는 것
# 슬라이서 v0.4의 버전에서는 forward는 고려 안하니까, backward 로직으로 바꿔야 함
def create_forward_slice(adjacency_list, line_no):
    sliced_lines = set()
    line_no = str(line_no)  # line_no를 문자열로 변환
    sliced_lines.add(line_no)
    stack = [line_no]  # 바로 리스트에 추가
    
    while stack:
        cur = stack.pop()
        if cur not in sliced_lines:
            sliced_lines.add(cur)
        if cur not in adjacency_list:
            continue
        adjacents = adjacency_list[cur]  # 문자열 키 접근
        
        for node in adjacents:
            if node not in sliced_lines:
                stack.append(node)
    
    sliced_lines = sorted(sliced_lines, key=int)  # 정렬 시 숫자로 정렬
    return sliced_lines

def create_backward_slice(adjacency_list, line_no):
    inverted_adjacency_list = invert_graph(adjacency_list)
    # print("인버트 콤바인 그래프: ", inverted_adjacency_list)
    return create_forward_slice(inverted_adjacency_list, line_no)

#! csv에서 적용된, \t으로 구분된 key를 인식하기 위해 각 col을 \t을으로 분할(실제로 csv도 그렇게 분할했음)
def read_csv(csv_file_path):
    data = []
    with open(csv_file_path) as fp:
        header = fp.readline()
        header = header.strip()
        h_parts = [hp.strip() for hp in header.split("\t")] # 헤더 항목 리스트로 저장
        
        # 헤더가 아닌 실제 data part를 읽기위한 반복문
        for line in fp:
            line = line.strip()
            instance = {}
            # 각 col을 탭으로 분리
            lparts = line.split("\t")
            for i, hp in enumerate(h_parts):
                if i < len(lparts):
                    content = lparts[i].strip()
                else:
                    content = ''
                instance[hp] = content
            data.append(instance)
        return data

##new CPG 기준 모든 REACHING_DEF, CDG 엣지를 탐지하고 그에 해당하는 시작 - 끝 노드를 수집
# 해당 메소드에서는 edges.csv에 가지고 있는 데이터만을 가지고 종속성을 수집하는 것이 기본적이다.
# 즉, 여기서 node를 또 순회해서 뭔가를 수집하기 싫으면, 외부의 메소드를 통해 가져와야됨 ex. line_numbers, node_id_to_line_numbers
# 여기서 노드를 순환하진 않아서 노드의 여러 데이터를 가져오려면, node_extract함수에서 가져와야 될 여러 데이터들을 추가해야됨됨
def create_adjacency_list(line_numbers, node_id_to_line_numbers, edges, macro_candidate):
    adjacency_list = {}
    
    # 모든 노드들에 대해 가지고있는 ln을 통해 adj_list를 초기화
    for ln in set(line_numbers):
        
        """ adj_list 수정 예정
            이유:
            v0.3 까지만 해도, 종속성 엣지만을 고려해, 종속성을 나타내는 엣지만을 고려,
            근데이제 LOCAL노드라던지, else라던지 이런애들을 추가해야되므로, 이러한 로직을 추가해야된다.
            
            
            현재 아이디어 1): LOCAL은 그렇게 많지 않음 즉, 취약함수 호출을 찾을 때 처럼, 이러한 LOCAL노드의 id, ln을 수집한 다음, 슬라이스 수집할때 그냥 집어넣고, 정렬하면, 상관 없지 않을까?
            -> 근데 수집했다 치자, 지금 순회는 수집된 취약함수를 기반으로 슬라이스를 수집하는데, 이때 LOCAL노드를 어느 틈에 반영해서 추가할지,
            
            현재 아이디어 2): 
            REF 엣지를 가지는 IDENTIFIER를 REACHING_DEF 수집할때 추가로 같은 조건으로 수집한다. 이러면 중복제거하면 어차피 하나만 남음
            
            LOCAL 수집방안:  
            IDENTIFIER 노드는 자신의 선언 LOCAL노드에 대해서 ref 엣지로 가리키고 있다.
            이는, 
            
            else 수집방안: 
            CDG로 이어질거 같지만 대응되는 if 엣지에 대해서, AST 엣지로 이어진다, C_STRUCT - (AST) - C_STRUCT에 해당하는 엣지를 수집

            매크로 변수 수집방안: 
            
            * 추가 아이디어:  
        """
        # CDG, REACHING_DEF가 둘다 이어지는 시작 노드라면 두개의 Set 모두 추가됨
        # 지금 set을 두개로 만들어놓은 이유는 두가지 종속성 엣지만을 고려했기 때문 때문,
        # [0]: CDG, [1]: REACHING_DEF, [2]: LOCAL, 구조체 필드 REF, [3]: else 수집을 위한 AST, [4]: 매크로 변수 수집을 위한 CALL 엣지지
        adjacency_list[ln] = [set(), set(), set(), set(), set()]
    
    # edges.csv 파일에 대해 순환
    for edge in edges:
        edge_type = edge['type'].strip()
        
        if True :            
            # 시작, 끝 노드 id 확보
            # edge 가지고는 ln을 확보할 수 없기 때문이다.
            start_node_id = edge['start'].strip()
            end_node_id = edge['end'].strip()
            
            # 만일 노드 id가 id - ln 어레이 안에 없을 경우 스킵
            if start_node_id not in node_id_to_line_numbers.keys() or end_node_id not in node_id_to_line_numbers.keys():
                continue
            
            #! startType 또는 endType이 'BLOCK'이면 해당 엣지 건너뛰기
            # CPG edge 상으로는 존재하지만 BLOCK 노드와는 코드상에서의 logical한 dependency는 존재 X, 코드 수집에 방해가 되어 일단 제외
            if edge['startType'] == 'BLOCK' or edge['endType'] == 'BLOCK':
                continue
            
            #! 시작노드 id, 끝노드 id를 기반으로 ln - ln 으로 이어지는 쌍을 만들기
            start_ln = node_id_to_line_numbers[start_node_id]
            end_ln = node_id_to_line_numbers[end_node_id]
                        
            # 조건에 맞는 Edge를 추가하는데, 이 메소드에서 nodeType, nodeId, edgeType 추출하지 못하는 요소는는 추가 함수가 필요            
            if edge_type == 'CDG': #Control Flow edges
                adjacency_list[start_ln][0].add(end_ln)
            if edge_type == 'REACHING_DEF' and not edge['startType'] == 'METHOD': # Data Flow edges
                adjacency_list[start_ln][1].add(end_ln)
            # 변수 ref와 구조체 필드 슬라이스 추출을 위한 엣지 수집
            if (edge['startType'] == 'IDENTIFIER' or (edge['startType'] == 'CALL' and edge['endType'] == 'MEMBER')) and edge_type == 'REF':
                adjacency_list[start_ln][2].add(end_ln)    
            #왜 else에 해당하는 노드는 제대로 가리키는데, 정작 line을 가리키는건 +1이 되어있는지 모르겠음
            if (edge['startType'] and edge['endType']  == 'CONTROL_STRUCTURE') and edge_type == 'AST':
                adjacency_list[start_ln][3].add(end_ln)
            #매크로 함수 및 동일한 파일 내에 정의, 선언된 다른 메소드를 호출하는 엣지 수집,
            #수집은 성공, 예상했던대로, callee에 대한 모든 엣지들이 전부 수집된다. 매크로 변수임을 식별할 수 있는 방법은?
            if (edge['startType'] == 'CALL' and end_node_id in macro_candidate) and edge_type == 'CALL':
                adjacency_list[start_ln][4].add(end_ln)
                
    return adjacency_list

#! nodes.csv 파일에 존재하는 Code expression에 해당하는 노드들(코드 상의 모든 노드들)
def extract_nodes_with_location_info(nodes):
    
    node_ids = []   #모든 노드들의 Id, 해당 메소드에서 현재 노드를 식별하기 위해서 사용 
    line_numbers = []   #노드가 위치한 ln
    node_id_to_line_number = {} #노드 Id에 대응되는 ln(이를 통해 노드 쌍을 수집) 
    node_function_to_id = {}    # 함수 이름과 노드 Id 매핑
    macro_candidate = [] # 우선은 매크로 변수를 확인할 수 있는 것은 IS_EXTERNAL이 TRUE인 node들이다.

    for node_index, node in enumerate(nodes):
        assert isinstance(node, dict)
        
        if 'key' in node:
            node_id = node['key'].strip()
            
        else:
            print(f"Warning: 'key' not found in node at index {node_index}")
            continue  # Skip this node or assign a default value)
        
        node_ids.append(node_id)
        
        if node['type'].strip() == "BLOCK":
            continue
        
        #! METHOD이면서 isExternal이 존재하는데, ln이 있는 경우는 현재 확인 상 매크로 변수, 함수 뿐 
        if node['type'].strip() == "METHOD" and node['isExternal'] == "True" and node.get('location', '').strip():
            macro_candidate.append(node_id)
        
        # ln 노드에는 이제 Line number, Column number가 따로 있음
        if 'location' in node.keys():
            location = node['location']
            if location == '':
                continue
            line_num = location
            line_numbers.append(line_num)
            node_id_to_line_number[node_id] = line_num
            
    return line_numbers, node_id_to_line_number, macro_candidate
    pass

def search_function_call(nodes):
    function_calls = set()
    # print("nodes:", nodes)
    for node_idx, node in enumerate(nodes):
        ntype = node['type'].strip()
        # 노드를 순회하면서, CALL에 해당하는 노드를 우선은 다 조회
        if ntype == 'CALL':
            function_name = nodes[node_idx + 1]['name'] 
            
            if function_name  is None or function_name.strip() == '':
                continue
            if function_name.strip() in l_funcs:
                #취약함수가 위치하는 ln을 수집
                node_id = node['key'].strip()
                line_no = int(node['location'])
                if line_no > 0 and node_id is not None:
                    function_calls.add((function_name, line_no, node_id))
    return function_calls

def get_CWE(filename):
    CWEID = filename.split("_")[0]
    return re.sub(r'[^0-9]', '',CWEID)

def extract_lines_from_c_source(file_path, all_slices):
    extracted_lines = []
    # Flatten and convert line numbers to integers
    flat_slices = [int(num) for sublist in all_slices for num in sublist]

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()  # Read all lines at once
            for index in flat_slices:
                if 1 <= index <= len(lines):
                    extracted_lines.append(lines[index - 1].rstrip())  # Access specific line
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

    return extracted_lines

## 전반적인 슬라이스 수집을 하기위한 메인 함수
# root_dir: 순환 돌릴 소스코드, CPG 파일을 포함하는 디렉토리가 존재하는 경로
# slice_dir: 수집된 슬라이스를 저장할 위치
def process_directory(root_dir, slice_dir):

    a = 0
    for sub_dir in os.listdir(root_dir):
    
        if a == 1:
            break    
        slice_Dir = slice_dir
        # 각 json 파일에 실질적으들어갈 데이터 instances
        all_data_instance=[]
        all_data_instance_last_index = -1
        
        sub_dir_path = os.path.join(root_dir, sub_dir)
        
        if not os.path.isdir(sub_dir_path):
            continue

        src_file = os.path.join(sub_dir_path, [f for f in os.listdir(sub_dir_path) if f.endswith('.c') or f.endswith('.cpp')][0])
        src_filename = os.path.basename(src_file)
        
        nodes_csv = os.path.join(sub_dir_path, 'nodes.csv')
        edges_csv = os.path.join(sub_dir_path, 'edges.csv')
        
        ## node, edge, 슬라이스 수집할 set 세팅 ##
        nodes = read_csv(nodes_csv)
        edges = read_csv(edges_csv) 
        call_lines = search_function_call(nodes)
        
        line_numbers, node_id_to_ln, macro_candidate = extract_nodes_with_location_info(nodes)
        
        node_ln_to_id = {}
        for k,v in node_id_to_ln.items():
            if v in node_ln_to_id:
                continue
            node_ln_to_id[v] = k    
        
        adjacency_list = create_adjacency_list(line_numbers, node_id_to_ln, edges, macro_candidate)              
        combined_graph = combine_adjacency_list(adjacency_list)    
        
        for function_name, slice_ln, node_id in call_lines:
            
            data_instance = {}
            all_slices = []
            # foward, backward 슬라이스 수집
            forward_sliced_lines = create_forward_slice(combined_graph, slice_ln)
            backward_sliced_lines = create_backward_slice(combined_graph, slice_ln)
            all_slice_lines = forward_sliced_lines
            all_slice_lines.extend(backward_sliced_lines)
            all_slice_lines = sorted(set(all_slice_lines), key=int)
            
            all_slices.append(all_slice_lines)
            cwe_id = get_CWE(src_filename)
            
            #print("수집될 라인", all_slices)
            
            all_code_slices = extract_lines_from_c_source(src_file, all_slices)
                        
            if cwe_id:
                data_instance['CWE-ID'] = "CWE-" + cwe_id
            else:
                data_instance['CWE-ID'] = "CWE-Unknown"

            data_instance['criterion'] = function_name
            data_instance['line'] = slice_ln
            data_instance['slices'] = all_code_slices
            
            all_data_instance.append(data_instance)
            all_data_instance_last_index+=1
    
        output_path = os.path.join(slice_Dir, f"slices_{sub_dir}.json")

        print(f"Attempting to write to: {output_path}")
        with open(output_path, 'w') as json_file:
            json.dump(all_data_instance, json_file)   
        a += 1 

if __name__ =='__main__':
    
    # 작업할 파일들이 있는 디렉토리
    root_dir = "R_dir"
    # 추출한 슬라이스 파일을 넣을 디렉토리
    slice_dir = 'slices_Dir'
    process_directory(root_dir, slice_dir)    