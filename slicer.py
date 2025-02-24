## 이전 슬라이서 ##

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
           
           
          
def extract_key_number(idx, nodes):
    while idx >= 0:
        c_node = nodes[idx]
        if 'key' in c_node.keys():
            key = c_node['key']
            if key.strip() != '':
                try:
                    ln = int(key)
                    return ln
                except:
                    pass
        idx -= 1
    return -1
    
def combine_control_and_data_adjacents(adjacency_list):
    cgraph = {}
    for ln in adjacency_list:
        cgraph[ln] = set()
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][0])
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][1])
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

def invert_graph_data(adjacency_list):
    igraph = {}
    for ln in adjacency_list:
        adj = adjacency_list[ln]
        for node in adj:
            if node not in igraph:
                igraph[node] = set()
            igraph[node].add(ln)
    return igraph
    pass

def create_backward_slice(adjacency_list, line_no):
    inverted_adjacency_list = invert_graph(adjacency_list)
    return create_forward_slice(inverted_adjacency_list, line_no)


def read_csv(csv_file_path):
    data = []
    with open(csv_file_path) as fp:
        header = fp.readline()
        header = header.strip()
        h_parts = [hp.strip() for hp in header.split()]
        for line in fp:
            line = line.strip()
            instance = {}
            lparts = line.split()
            for i, hp in enumerate(h_parts):
                if i < len(lparts):
                    content = lparts[i].strip()
                else:
                    content = ''
                instance[hp] = content
            data.append(instance)
        return data

def invert_graph_data(adjacency_list):
    igraph = {}
    for ln in adjacency_list.keys():
        igraph[ln] = {}
        
    for node in adjacency_list:
        for var in adjacency_list[node]:
            for Id in adjacency_list[node][var]:
                if Id not in igraph:
                    igraph[Id] = {}
                if var not in igraph[Id]:
                    igraph[Id][var] = set()
                igraph[Id][var].add(node)
    return igraph
    pass

def getDataFromid(data_dict, datas):
    ids = set()
    for data in datas:
        if data in data_dict:
            ids = ids.union(data_dict[data])
    return ids 

def create_forward_slice_data(adjacency_list, line_no, datas):
    sliced_lines = set()
    sliced_lines.add(line_no)
    stack = list()
    stack.append(line_no)
    
    while len(stack) != 0:
        cur = stack.pop()
        if cur not in sliced_lines:
            sliced_lines.add(cur)
        if cur not in adjacency_list:
            continue 
        adjacents = getDataFromid(adjacency_list[cur], datas)
        for node in adjacents:
            if node not in sliced_lines:
                stack.append(node)                
    return sliced_lines

def create_backward_slice_data(adjacency_list, line_no, datas):
    inverted_adjacency_list = invert_graph_data(adjacency_list)
    return create_forward_slice_data(inverted_adjacency_list, line_no, datas)

def create_forward_propagation_slices_data(adjacency_list, ids, datas):
    line_nos = set(ids)
    all_slice_set = set()
    
    for no in line_nos:
        forward_sliced_lines = create_forward_slice_data(adjacency_list, no, datas)
        all_slice_set = all_slice_set.union(set(forward_sliced_lines))
        
    return all_slice_set

## 이런거보면 노드를 식별하는 방법은 적절한 엣지를 찾는것?
def create_adjacency_list_data(line_numbers, edges, target_edge=['REACHES']):
    adjacency_list = {}
    set_list = []
    for ln in set(line_numbers):
        adjacency_list[ln] = {}
        
    for edge in edges:
        edge_type = edge['type'].strip()
        start_node_id = edge['start'].strip()
        edge_var = edge['var'].strip()
        if edge_var == "":
            continue
        end_node_id = edge['end'].strip()
        if edge_type in target_edge:
            if start_node_id not in adjacency_list:
                adjacency_list[start_node_id] = {}
            if edge_var not in adjacency_list[start_node_id]:
                adjacency_list[start_node_id][edge_var] = set()
            adjacency_list[start_node_id][edge_var].add(end_node_id)
    return adjacency_list  

def create_adjacency_list_nodeID(line_numbers, entry_node_ids, edges, target_edge=['CONTROLS','REACHES']):
    adjacency_list = {}
    set_list = []
    target_edge_length = len(target_edge)
    
    for ln in set(line_numbers):
        adjacency_list[ln] = []
        for i in range(target_edge_length):
            adjacency_list[ln].append(set())
    
    # csv의 엣지 리스트만큼 edge를 순회
    for edge in edges:
        edge_type = edge['type'].strip()
        start_node_id = edge['start'].strip()
        # 엔트리 노드 타입이면 건너 뛰기
        if start_node_id in entry_node_ids:
            continue
        end_node_id = edge['end'].strip()
        # 해당 노드들의 엣지 타입이 target_edge와 같으면(control, reaches ...)
        if edge_type in target_edge:
            # 이미 등록한 노드인지 검사
            if start_node_id not in set_list:
                adjacency_list[start_node_id] = []
                for i in range(target_edge_length):
                    adjacency_list[start_node_id].append(set())
                set_list.append(start_node_id)
            adjacency_list[start_node_id][target_edge.index(edge_type)].add(end_node_id)
    return adjacency_list

# 이거의 파악을 신버전에서는 다른 방식으로 구현했다.
def extract_else_line_number(idx, nodes):
    while idx >= 0:
        c_node = nodes[idx]
        if 'location' in c_node.keys() and c_node['type'].strip() != "CompoundStatement":
            location = c_node['location']
            if location.strip() != '':
                try:
                    ln = int(location.split(':')[0]) -1
                    return c_node['key'] , ln
                except:
                    pass
        idx += 1
    return -1, -1 

#location info와 함께 노드 추출 
def extract_nodes_with_location_info(nodes):
    node_indices = {}
    node_ids = []
    line_numbers = []
    node_id_to_line_number = {}
    node_function_to_id = {}
    node_id_to_function_id = {}
    function_id_to_entry = {}
    function_info = {}
    functions = []
    Identifier_id_list = []
    parameter = 1
    return_statement = 1
    function_id_to_callee = {}
    else_key2line = {}
    else_line2key = {}
    for node_index, node in enumerate(nodes):
        assert isinstance(node, dict)
        # function_id = node['functionId'].strip()
        # node_id = node['key'].strip()
        function_id = node.get('functionId', '').strip()  
        
        # Check if 'key' exists
        if 'key' in node:
            node_id = node['key'].strip()
            
        else:
            print(f"Warning: 'key' not found in node at index {node_index}")
            continue  # Skip this node or assign a default value)
        
        node_ids.append(node_id)
        node_indices[node_id] = node_index
        
        if node['type'].strip() == "Function":
            node_function_to_id[node['code'].strip()] = node_id
            function_info['Key'] = node_id
            function_info['FunctionName'] = node['code'].strip()
        if node['type'].strip() == "IdentifierDeclStatement":
            Identifier_id_list.append(node_id)
        if node['type'].strip() == "ElseStatement":
            tmp_key, tmp_line  = extract_else_line_number(node_index, nodes)
            if tmp_line == -1:
                continue 
            else_key2line[tmp_key] = tmp_line
            else_line2key[tmp_line] = tmp_key

        if function_id != "":
            if node['type'].strip() == "Callee":
                if function_id in function_id_to_callee:
                    function_id_to_callee[function_id][node['code'].strip()] = node['key'].strip()
                else:
                    function_id_to_callee[function_id] = {}
                    function_id_to_callee[function_id][node['code'].strip()] = node['key'].strip()
            node_id_to_function_id[node_id] =  function_id
            if node['code'].strip() == "ENTRY":
                function_id_to_entry[function_id] = node_id
                functions.append(function_info)
                parameter=1
                
                # function_info에는 
                function_info = {}
            elif node['type'].strip() =='ReturnStatement':
                function_info['ReturnStatement'+str(return_statement)] = node['code'].strip()
                function_info['ReturnStatementType'+str(return_statement)] = "return;"
            elif node['type'].strip() == 'Parameter': 
                function_info['Parameter'+str(parameter)] = node['code'].strip()
            elif node['type'].strip() == 'ParameterType':
                function_info['ParameterType'+str(parameter)] = node['code'].strip()
                parameter+=1
        
        if 'location' in node.keys():
            location = node['location']
            if location == '':
                continue
            # 여기서 에러 발생 line number 자를때,이제 이거 필요x
            line_num = int(location.split(':')[0])
            line_numbers.append(line_num)
            if 'CompoundStatement' != node['type'].strip():
                node_id_to_line_number[node_id] = line_num
    return else_key2line, else_line2key, Identifier_id_list, function_id_to_callee, functions, function_id_to_entry,node_id_to_function_id,node_function_to_id,node_indices, node_ids,line_numbers,node_id_to_line_number
    pass

def create_adjacency_data(line_numbers, edges):
    adjacency_data = {}
    for ln in set(line_numbers):
        adjacency_data[ln]= set()
    for edge in edges:
        edge_type = edge['type'].strip()
        if edge_type in ['REACHES']:
            edge_var = edge['var'].strip()
            if edge_var == "":
                continue
            start_node_id = edge['start'].strip()
            end_node_id = edge['end'].strip()
            adjacency_data[start_node_id].add(edge_var)
            adjacency_data[end_node_id].add(edge_var)
    return adjacency_data

def create_adjacency_slices(adjacency_list, line_nos):
    line_nos = set(line_nos)
    all_slice_set = set()
    for no in line_nos:
        forward_sliced_lines = create_forward_slice(adjacency_list,no)
        backward_sliced_lines = create_backward_slice(adjacency_list, no)
        all_slice_set = all_slice_set.union(set(forward_sliced_lines))
        all_slice_set = all_slice_set.union(set(backward_sliced_lines))
    line_nos = all_slice_set.union(set(all_slice_set))
    return line_nos

def create_forward_slice(adjacency_list, line_no):
    sliced_lines = set()
    sliced_lines.add(line_no)
    stack = list()
    stack.append(line_no)
    
    while len(stack) != 0:
        cur = stack.pop()
        if cur not in sliced_lines:
            sliced_lines.add(cur)
        adjacents = adjacency_list[cur]
        for node in adjacents:
            if node not in sliced_lines:
                stack.append(node)                
    return sliced_lines

def find_function_info(function_info,callee):
    for function in function_info:
        if function['Key'] == callee: 
            return function
    return -1

def extract_line_number(idx, nodes):
    while idx >= 0:
        c_node = nodes[idx]
        if 'location' in c_node.keys():
            location = c_node['location']
            if location.strip() != '':
                try:
                    ln = int(location.split(':')[0])
                    return ln
                except:
                    pass
        idx -= 1
    return -1

def concat_lines(func,inter_funcs):
    for inter_func in inter_funcs.keys():
        target = inter_func
        insert_data = inter_funcs[inter_func]
        insert_data.reverse()
        i = -1
        for idx ,ln in enumerate(func):
            if ln == target:
                i = idx + 1
                break
        for j in insert_data:
            func.insert(i,j)
    return func

#split의 문제인지 CWEID 추출이 잘 되지 않는다 ex. 'CWE-'로 끝    
def get_CWE(filename):
    CWEID = filename.split("_")[0]
    return re.sub(r'[^0-9]', '',CWEID)

catrgory_dict = {
    "FC" :["CallExpression"],
    "PU" : ["PtrMemberAccess"],
    "AU" : ["ArrayIndexing"],
    "AE" :  ["AdditiveExpression", "MultiplicativeExpression"],
    "ALL" : ["CallExpression", "PtrMemberAccess", "ArrayIndexing", "AdditiveExpression", "MultiplicativeExpression"]
}

def get_criterion(category, node_ln_to_id, nodes, genTest=False):
    assert category in ["FC","PU","AU","AE", "ALL"]
    criterion_list = []
    
    if len(nodes) == 0: return []
    key = -1
    for node_idx, node in enumerate(nodes):
        node_type = node['type'].strip()
        
        # 결정적으로 여기선 criterion이 나올 수 없음: 해당 함수의 블록안에 함수들을 지정하는 것이기 때문
        if node_type == "Function" and not genTest:
            function_name = nodes[node_idx + 1]['code']
            if function_name  is None or function_name.strip() == '':
                    continue
            if function_name.find("bad") >= 0 or function_name.find("good") >= 0:
                 line_no = extract_line_number(node_idx, nodes)
                 key = extract_key_number(node_idx,nodes)
        elif node_type in catrgory_dict[category]:
            if node_type in ["CallExpression"]:
                function_name = nodes[node_idx + 1]['code']
                if function_name  is None or function_name.strip() == '':
                    continue
                if function_name.strip() not in l_funcs:
                    continue
            else :
                function_name = nodes[node_idx]['code']
            line_no = extract_line_number(node_idx, nodes)
            
            # ㅇㅇ 해당 CallExpression 함수들이 위의 Function 함수에 속해 있는지를 확인
            nfunctionId=int(node['functionId'])
            print("nfunctionId: ", nfunctionId)
            if (key == nfunctionId or genTest)and line_no> 0:
                criterion_list.append([node_ln_to_id[line_no],function_name, node_type])
    return criterion_list

def calc_label(node_id_to_function, function_id, Sink_flag, Source_flag, genTest):
    label = 0
    if genTest : return -3
    try : 
        functionName = node_id_to_function[function_id]
        if functionName.find("main") >=0:
            label = -1
            return label
        f_bad = functionName.find("bad") >= 0
        f_goodG2B = functionName.find("goodG2B") >= 0
        f_Source = functionName.find("Source") >= 0
        f_Sink = functionName.find("Sink") >= 0

        if (f_bad and not f_Source and not f_Sink) or (f_goodG2B and not f_Source and not f_Sink):
            if Sink_flag:
                label = 0
            elif Source_flag:
                label = 1
            else :
                if f_goodG2B:
                    label = 1
        elif ( (f_bad or f_goodG2B) and f_Sink ):
            label = 1
        else:
            label = 0
    except:
        label = -2
     
    return label   
    
def create_forward_propagation_slices(adjacency_list, ids):
    line_nos = set(ids)
    all_slice_set = set()
    
    for no in line_nos:
        forward_sliced_lines = create_forward_slice(adjacency_list, no)
        all_slice_set = all_slice_set.union(set(forward_sliced_lines))
        
    return all_slice_set
    
def create_backward_propagation_slices(adjacency_list, line_nos):
    line_nos = line_nos
    all_slice_set = set()
    inverted_adjacency_list = invert_graph(adjacency_list)
    
    for no in line_nos:
        backward_sliced_lines = create_forward_slice(inverted_adjacency_list,no)
        all_slice_set = all_slice_set.union(set(backward_sliced_lines))

    return all_slice_set
    
def extract_function_name(func_declaration):
    pattern = r'\w+\s*\(' 
    match = re.search(pattern, func_declaration)

    if match:
        function_name = match.group(0)
        function_name = function_name.rstrip('(')
        return function_name.strip()  
    else:
        return "None"

def isinId(dst, src):  
    for idx in src:
        if idx in dst:
            return True
    return False
def get_backward_data(adjacency_list, line_no):
    sliced_lines = set()
    sliced_lines.add(line_no)
    stack = list()
    stack.append(line_no)
    datas = set(adjacency_list[line_no])
    while len(stack) != 0:
        cur = stack.pop()
        if cur not in sliced_lines:
            sliced_lines.add(cur)
            #현재 지정한 라인에 해당하는 노드의 데이터 union
            datas = datas.union(set(adjacency_list[cur]))
        if cur not in adjacency_list:
            continue 
        # 인접노드 가져오기(탐색 가능한 노드들)
        adjacents = getDataFromid(adjacency_list[cur], datas)
        for node in adjacents:
            if node not in sliced_lines:
                stack.append(node)             
    return sliced_lines, datas    

      
def main():
    #파싱을 위한 옵션 인자 설정
    parser = argparse.ArgumentParser()
    parser.add_argument('--criterion',help='["FC", "PU", "AU", "AE","ALL"]', default='FC')
    parser.add_argument('--csv', help='normalized csv files to process', default='../data/meta_data')
    parser.add_argument('--src', help='source c files to process', default='../data/raw_data')
    parser.add_argument('--label', default='../label/onlyOne_reassemble_flaw_line.xlsx')
    parser.add_argument('--output', default='../data/processed_data/ALL/slice.json')
    parser.add_argument('--every_file_save', action='store_true')
    parser.add_argument('--genTest', action='store_true')
    
    args = parser.parse_args()
    
    all_data_instance=[]

    all_data_instance_last_index = -1
    
    for idx , filename in enumerate(tqdm(os.listdir(args.csv))):
        filtered_fileName = filename.split('.')[0]
        
        # vertics, edge의 정보가 담긴 csv 로드
        dir_path = os.path.join(args.csv)
        # print(os.path.join(args.csv, filename, 'edges.csva'))
        # nodes = read_csv(os.path.join(args.csv, filename, 'nodes.csv'))#######################################################################################
        # edges = read_csv(os.path.join(args.csv, filename, 'edges.csv'))    
       
        # --csv에 디렉토리를 주는 경우 경로를 이상하게 탐색 아래와 같이 변경
        nodes_csv_path = os.path.join(dir_path, 'nodes.csv')
        edges_csv_path = os.path.join(dir_path, 'edges.csv')
        nodes = read_csv(nodes_csv_path)
        print("Nodes:", nodes)
        edges = read_csv(edges_csv_path)
        
        # filename을 넘기면 자꾸 edges.csv를 먼저 띄우는 것은 해당 반복문이 지정한 디렉토리의 모든 파일을 순회하기 때문
        src  = os.path.join(args.src, 'CWE121_Stack_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_03.c')
        file1 = open(src,'r',encoding = "ISO-8859-1")
        code = file1.readlines()
        file1.close()

        
        else_key2line, else_line2key, Identifier_id_list, function_id_to_callee, function_info, function_id_to_entry, node_id_to_function_id, node_function_to_id, node_indices, node_ids, line_numbers, node_id_to_ln = extract_nodes_with_location_info(nodes)
        # node의 line number -> node id로 매칭 
        node_ln_to_id = {}
        for k,v in node_id_to_ln.items():
            if v in node_ln_to_id:
                continue
            node_ln_to_id[v] = k
        
        # entry면 진입점?    
        entry_node_ids = []
        for k,v in function_id_to_entry.items():
            entry_node_ids.append(v)
        node_id_to_function = {v:k for k,v in node_function_to_id.items()}

        # 노드id에 해당하는 취약점 발생 함수들을 리스트로 추출
        criterion_list = get_criterion(args.criterion,node_ln_to_id,nodes,args.genTest)

        # edge의 타입에 따라 시작 노드, 끝노드를 추출 후 인접리스트를 통해 저장
        # rm
        adjacency_list_REACHES = create_adjacency_list_nodeID(node_ids, entry_node_ids, edges, ['REACHES','REACHES'])
        adjacency_list_CONTROLS = create_adjacency_list_nodeID(node_ids, entry_node_ids, edges, ['CONTROLS','CONTROLS'])
        adjacency_list_DEF = create_adjacency_list_nodeID(node_ids, entry_node_ids, edges, ['DEF','USE'])
       
        adjacency_list_data = create_adjacency_list_data(node_ids,edges)
        invert_adjacency_list_data = invert_graph_data(adjacency_list_data)

        # 해당 노드에 해당하는 인접 리스트들을 추출
        combined_graph_REACHES = combine_control_and_data_adjacents(adjacency_list_REACHES)
        combined_graph_CONTROLS = combine_control_and_data_adjacents(adjacency_list_CONTROLS)
        combined_graph_DEF = combine_control_and_data_adjacents(adjacency_list_DEF)
        
        Sink_flag = False 
        Source_flag = False
        if not args.genTest:
            for function in node_function_to_id:
                if function.find("Sink") >= 0:
                    Sink_flag = True
                elif function.find("Source") >= 0:
                    Source_flag = True
                    
        _datas = set()
        for i, data in enumerate(criterion_list):
            
            data_instance = {}
            target_id = data[0]
            Identifier_ids = []
             
            all_slice_ids = set()
            
            if find_function_info(function_info,node_id_to_function_id[target_id])['FunctionName'] == extract_function_name(code[node_id_to_ln[target_id] -1].strip()):
                continue
            
            focus_datas = set(invert_adjacency_list_data[target_id])
            focus_datas = focus_datas.union(adjacency_list_data[target_id])
            datas = set()
            backward_ids = set()
            tmp_backward_ids = set()
            tmp_datas = set()
            
            
            # 이 과정 중요
            tmp_backward_ids, tmp_datas = get_backward_data(invert_adjacency_list_data,target_id)
            datas = datas.union(tmp_datas)
            backward_ids = backward_ids.union(tmp_backward_ids)
            
            tmp_backward_ids, tmp_datas = get_backward_data(adjacency_list_data,target_id)
            datas = datas.union(tmp_datas)
            backward_ids = backward_ids.union(tmp_backward_ids)
            
            
            datas = focus_datas - datas 
            forward_ids = create_forward_propagation_slices_data(adjacency_list_data, backward_ids, datas)
            sorted_forward_ids = sorted(forward_ids)
            set_forward_ids = sorted_forward_ids[:sorted_forward_ids.index(target_id)+1]
            union_ids = backward_ids.union(set_forward_ids)
            
            forward_ids = create_forward_propagation_slices_data(adjacency_list_data, backward_ids, focus_datas)
            
            union_ids = union_ids.union(forward_ids)
            
            #union_ids = union_ids.union(create_backward_slice(combined_graph_REACHES, target_id))
            union_ids = union_ids.union(create_backward_propagation_slices(combined_graph_CONTROLS,union_ids))
                
            Symbol_ids = create_forward_propagation_slices(combined_graph_DEF, union_ids)
            Identifier_criterions = create_backward_propagation_slices(combined_graph_DEF, Symbol_ids)
        
            for Id in Identifier_criterions:
                if Id in Identifier_id_list:
                    Identifier_ids.append(Id)
            
            slices = union_ids.union(Identifier_ids)
            
            # 여기가 스니펫 만드는 핵심부인듯
            all_slices_line = set()
            for idx in slices:
                if idx in combined_graph_CONTROLS:
                    if len(combined_graph_CONTROLS[idx]) != 0 :
                        if not isinId(slices, combined_graph_CONTROLS[idx]) :
                            continue
                        
                if idx in node_id_to_ln:
                    all_slices_line.add(node_id_to_ln[idx])
                if idx in else_key2line:
                    all_slices_line.add(else_key2line[idx])
                    
            all_slices_line = sorted(all_slices_line)
            label = -8
            
            
            # 레이블링
            label = calc_label(node_id_to_function, node_id_to_function_id[target_id], Sink_flag, Source_flag, args.genTest)
                
            lines = []  # 스니펫이 될 라인들
            for idx,code_line in enumerate(all_slices_line):
                if code_line in else_line2key:
                    lines.append("else\n")    
                elif code[code_line-1].strip()[-1] not in [")", "{", ";"]:
                    tmp_linds = [code[code_line-1]]
                    current_line = code_line
                    valid_stack = []
                    # 괄호 짝 검사
                    for s in code[code_line-1]:
                        if s in "(":
                            valid_stack.append(s)
                        elif s in ")":
                            if valid_stack:
                                valid_stack.pop()
                    if not valid_stack:
                        lines.append(code[code_line-1])
                        continue
                    
                    while(valid_stack):
                        tmp_linds.append(code[current_line])
                        for s in code[current_line]:
                            if s in "(":
                                valid_stack.append(s)
                            elif s in ")":
                                if valid_stack:
                                    valid_stack.pop()
                        current_line +=1
                    #tmp_linds.append(code[current_line]) 
                    lines.append("".join(tmp_linds))  
                else :
                    lines.append(code[code_line-1])

            data_instance['FileName'] = filename
            data_instance['Caller'] = find_function_info(function_info,node_id_to_function_id[target_id])['FunctionName']
            data_instance['Source'] = Source_flag
            data_instance['Sink'] = Sink_flag
            data_instance['idx'] = all_data_instance_last_index
            data_instance['CWE-ID'] = "CWE-"+get_CWE(filename)
            data_instance['category'] = data[2]
            data_instance['criterion'] = data[1]
            data_instance['line'] = node_id_to_ln[data[0]]
            data_instance['label'] = label
            data_instance['slices'] = lines
            
            
            all_data_instance.append(data_instance)
            all_data_instance_last_index+=1 
        if args.every_file_save :
            output_path = os.path.join( args.output, filename + ".json")
            with open(output_path, 'w') as fp:
                json.dump(all_data_instance, fp)
                fp.close()
            all_data_instance = []
            all_data_instance_last_index = -1
    
    # Json으로 덤프        
    if not args.every_file_save :        
        output_path = args.output

        with open(output_path, 'w') as fp:
            json.dump(all_data_instance, fp)
            fp.close()
            
    print("Done")

    pass

if __name__ =='__main__':
    main()

           
           