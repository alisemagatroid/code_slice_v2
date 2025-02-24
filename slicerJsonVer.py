## Joern v4.0.. 이후 슬라이서 ##

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
        h_parts = [hp.strip() for hp in header.split("\t")] # 헤더 항목 리스트로 저장
        
        # 헤더가 아닌 실제 data part를 읽기위한 반복문
        for line in fp:
            line = line.strip()
            instance = {}
            # 각 line을 탭으로 분리
            lparts = line.split("\t")
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

# target edge 변경 필요
# 엣지를 통해 노드 간 관계를 정의하기 위한 함수
# 여기서 여러 함수를 따로 호출해서 조건에 맞는 Edge에 대한 adj를 만들 수록 있어야 함
def create_adjacency_list_nodeID(line_numbers, entry_node_ids, edges, nodes, target_edge=['CONTROLS','REACHES']):
    adjacency_list = {}
    set_list = []
    target_edge_length = len(target_edge)
    
    
    # linenumbers에 대하여 노드Id: ~~~ 형태로 adj 템플릿 생성
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
        # 암튼 기본적으로 노드들에 대한 adj_list가 생성된다
        if edge_type in target_edge:
            # 이미 등록한 노드인지 검사
            if start_node_id not in set_list:
                adjacency_list[start_node_id] = []
                for i in range(target_edge_length):
                    adjacency_list[start_node_id].append(set())
                set_list.append(start_node_id)
            adjacency_list[start_node_id][target_edge.index(edge_type)].add(end_node_id)
        
    # print(adjacency_list)    
    ## 이 위의 로직은 일단 기본적으로 모든 노드의 엣지를 고려해서 adj_list를 만들게 되는데, 
    # 만약 진짜 고려하고자 하는 간선의 데이터만을 가져가는 것이라면 위의 로직은 불필요
    # 그러나 일단 모든 edge를 고려한 adj_list를 만들기 위함이라면, 필요가 없다.
    # 현재 Joern v4.0~ 버전에서는 EdgeType, NodeType이 Clear하게 구분이 안되어있기 때문에
    # 모든 간선을 고려해서 만드는거는 사실 제대로 작동 안할 가능성이 있음
    # 
    
        
    CONTROL_adjacency_list = process_condition_edges(edges, nodes, target_edge_length)
    
    
    # 여기서 선언된 adj 리스트와 Control에서 만든를 병함하게되는데,
    for key, value in CONTROL_adjacency_list.items():
        if key not in adjacency_list:
            adjacency_list[key] = value
        else:
            for i in range(target_edge_length):
                adjacency_list[key][i].update(value[i])
    return adjacency_list


# 새로운 함수: Condition 엣지와 CDG 엣지를 추출해 CONTROL Edge를 구현하는 함수
def process_condition_edges(edges, nodes, target_edge_length):   
    # 이 함수에서 adjacency_list의 CONTROL 값을 처리합니다.
    adjacency_list = {}
    # 해당 리스트에는 Condidition Edge의 end node의 key 즉, adjacency_list의 key가 될 노드의 Id가 들어감
    adj_key_list = []
    set_list = []
    
    # 1. 엣지 타입이 CONDTION인 엣지의 End node key 수집
    # 1-1 해당 키들을(엣지 타입이 Condtion인 end node) adj에 우선 키로써 삽입
    for edge in edges:
        edge_type = edge['type'].strip()
        start_node_id = edge['start'].strip() # 안쓰이는데? 바로 CDG 추출에 쓸 수도?
        end_node_id = edge['end'].strip()
        
        # key가 될 녀석들 수집
        if edge_type == "CONDITION":
            adj_key_list.append(end_node_id)
        
    # print("Condition end node list:", adj_key_list)
    
    for key in adj_key_list:
        adjacency_list[key] = [set() for _ in range(2)]  # 리스트 안에 세트 두 개를 넣음
            
    print("Condition end node list:", adjacency_list)    
    
    # CDG로 이어지는 end 노드를 수집하기 위함
    for edge in edges:
        
        start_node_id = edge['start'].strip() # 시작 노드(key가 될 노드)
        end_node_id = edge['end'].strip()   # 끝 노드 (value가 될 노드)
        edge_type = edge['type'].strip()    # CDG 관계 확인 용

        # 현재 지정된 edge의(현재 라인의) 시작 노드는 Key가 되는 노드에 CDG edge인 경우
        if start_node_id in adj_key_list and edge_type == 'CDG' :
    
    
    # # for edge in edges:
    #     start_node_id = edge['start'].strip() # 안쓰이는데? 
    #     end_node_id = edge['end'].strip()
    #     edge_type = edge['type'].strip() # CDG type을 가지는
        
    #     # 1. edge['type']이 Condtion인 엣지를 찾아 해당 edge의 end 값을 찾기
    #     if edge_type == "CONDITION":
    #         condition_end_node = end_node_id
            
    #         # print("condition_end_node: ", condition_end_node)

    #         # 2. 그 end의 값이 start로 존재하는 edge 중 edge['type']이 CDG인 엣지들의 end 값 찾기
    #         cdg_end_nodes = set()  # CDG 엣지의 end 값을 모으는 집합
            
    #         for inner_edge in edges:
                
    #             # 해당 변수들은 이어져있는 노드간의 엣지가 CDG 관계임을 확인하기 위한 변수들
    #             inner_start_node_id = inner_edge['start'].strip()
    #             inner_end_node_id = inner_edge['end'].strip()
    #             inner_edge_type = inner_edge['type'].strip()
                
    #             ## 이미 위의 변수에서 type을 지정해 해당 값을 변수로 넣었기 때문에, 조건식이 길지 않음
    #             # 이미 CDG edge를 찾음으로써 내가 원하는 라인들(해당 CD를 따르는 라인들)이 걸러짐
    #             if inner_start_node_id == condition_end_node and inner_edge_type == "CDG":
    #                 cdg_end_nodes.add(inner_end_node_id)
    #         # print("CDG 엣지들: ", cdg_end_nodes) 
            
            
    #         # 3. cdg 관계가 성립되는 노드들에 대하여, CallExpression을 지정, 이를 통해 Control 노드를 수집
    #         ## location이 동일한 노드들 중에서 key가 가장 작은 값이 CallExpression이므로 linenumber를 수집하기 위한 
    #         ## Key: location, value: 노드Id를 가지는 Dict 생성
    #         nodes_location = {}
    #         for cdg_end_node in cdg_end_nodes:
    #             for node in nodes:
    #                 if node['key'].strip() == cdg_end_node:
    #                     # 현재 가리키는 node의 location 변수
    #                     location_value = node['location'].strip() 
    #                     if node['location'].strip()  == '':
    #                         continue

    #                     if location_value not in nodes_location:
    #                         nodes_location[location_value] = []
    #                     nodes_location[location_value].append(cdg_end_node)
    #                     #print("node_location_dict: ", nodes_location)

    #             # 현재 nodes_location dict에서 각 key(노드 라인넘버) 별 가장 작은 nodeid 지정
    #             for location_value, node_list in nodes_location.items():
    #                 min_key_node = min(node_list, key=lambda x: x)  # key가 node ID이므로 직접 비교
    #             # adjacency_list에 추가
    #             if condition_end_node not in adjacency_list:
    #                 adjacency_list[condition_end_node] = []
    #                 for i in range(target_edge_length):
    #                     adjacency_list[condition_end_node].append(set())
    #             adjacency_list[condition_end_node][0].add(min_key_node)  # 0번 index는 CONTROLS에 해당
    #print("CONTROL_adj_list: ", adjacency_list)
    return adjacency_list

def extract_reaches_edge(edges, nodes):


# def process_condition_edges(edges, nodes, target_edge_length):
    adjacency_list = {} #최종 추출하고자 하는 리스트
    set_list = [] # 안 쓰나?
    cdg_end_nodes = set()  # CDG 엣지의 end 값을 모으는 집합
    nodes_location = {}
    
    
    #엣지 루프를 통해 cdg_end_nodes 등을 뽑아내고 노드 루프를 통해 따로 필요한 값을 뽑아내야될듯
    for edge in edges:
        edge_type = edge['type'].strip()
        start_node_id = edge['start'].strip() # 안쓰이는데?
        end_node_id = edge['end'].strip()
        
        # 1. edge['type']이 Condtion인 엣지를 찾아 해당 edge의 end 값을 찾기
        if edge_type == "CONDITION":
            condition_end_node = end_node_id
            
            # 엣지 안에서 추가로 다른 조건의 엣지를 찾기위한 과정
            for inner_edge in edges:         
                # 해당 변수들은 이어져있는 노드간의 엣지가 CDG 관계임을 확인하기 위한 변수들
                inner_start_node_id = inner_edge['start'].strip()
                inner_end_node_id = inner_edge['end'].strip()
                inner_edge_type = inner_edge['type'].strip()
                
                ## 이미 위의 변수에서 type을 지정해 해당 값을 변수로 넣었기 때문에, 조건식이 길지 않음
                # 이미 CDG edge를 찾음으로써 내가 원하는 라인들(해당 code Dependency를 따르는 라인들)이 걸러짐
                if inner_start_node_id == condition_end_node and inner_edge_type == "CDG":
                    cdg_end_nodes.add(inner_end_node_id)
                    
            
        # 3. cdg 관계가 성립되는 노드들에 대하여, CallExpression을 지정, 이를 통해 Control 노드를 수집
        ## location이 동일한 노드들 중에서 key가 가장 작은 값이 CallExpression이므로 linenumber를 수집하기 위한 
        ## Key: location, value: 노드Id를 가지는 Dict 생성
    
    
    # 잘 추출 됨 CDG로 이어지는 노드들 CallExpression, Call 포함
    print("cdg_end_nodes", cdg_end_nodes)    
    
    
    for cdg_end_node in cdg_end_nodes:
        for node in nodes:
            if node['key'].strip() == cdg_end_node:
                # 현재 가리키는 node의 location 변수
                location_value = node['location'].strip() 
                if node['functionId'].strip() != '':
                    # location_value를 키로 하고 해당 노드 ID를 리스트에 추가
                    if location_value not in nodes_location:
                        nodes_location[location_value] = []
                    nodes_location[location_value].append(cdg_end_node)
    
    # 잘 추출 됨 cdg_end_nodes를 node를 순회해서 각 조건 노드별 영향을 받는 Call_Expression 들
    print("node_location_dict: ", nodes_location)      

    # 현재 nodes_location dict에서 각 key(노드 라인넘버) 별 가장 작은 nodeid 지정
    for location_value, node_list in nodes_location.items():
    # 리스트가 비어있지 않은 경우에만 min_key_node를 찾도록 추가
        min_key_node = min(node_list, key=lambda x: int(x))

        if condition_end_node not in adjacency_list:
            adjacency_list[condition_end_node] = []
            for _ in range(target_edge_length):
                adjacency_list[condition_end_node].append(set())

            # 중복되지 않은 경우에만 추가
        if min_key_node not in adjacency_list[condition_end_node][0]:
            adjacency_list[condition_end_node][0].add(min_key_node)
    print("CONTROL_adj_list: \n", adjacency_list)
    return adjacency_list




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

# csv로 존재하는 노드들의 데이터를 분석, 코드 취약점을 찾기위한 데이터를 추출하는 함수
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
        
        function_id = node.get('functionId', '').strip()  
        
        # Check if 'key' exists     No Problem
        if 'key' in node:
            node_id = node['key'].strip()
            #print("key:", node_id)
        
        else:
            print(f"Warning: 'key' not found in node at index {node_index}")
            continue  # Skip this node or assign a default value)
        node_ids.append(node_id)
        node_indices[node_id] = node_index
        #print("node_indcies:", node_indices)
        
        # type이 "METHOD" 인 경우 해당 메소드(함수)의 key, 이름을 수집
        if node['type'].strip() == "METHOD":
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
            # Callee는 Joern v4 이후로는 별도로 추출되지 않음
            if node['type'].strip() == "Callee":
                if function_id in function_id_to_callee:
                    function_id_to_callee[function_id][node['code'].strip()] = node['key'].strip()
                else:
                    function_id_to_callee[function_id] = {}
                    function_id_to_callee[function_id][node['code'].strip()] = node['key'].strip()
            node_id_to_function_id[node_id] =  function_id
            
            # 엔트리 노드(코드 전반과 이어지는 노드)는 나중에 제외하기 위해 저장
            # 코드 부분이 Entry로 저장
            if node['code'].strip() == "ENTRY":
                function_id_to_entry[function_id] = node_id
                functions.append(function_info)
                parameter=1
                function_info = {}
                
            # 리턴 근데 FC 상에서는 안쓰는거같기도
            elif node['type'].strip() =='ReturnStatement':
                function_info['ReturnStatement'+str(return_statement)] = node['code'].strip()
                function_info['ReturnStatementType'+str(return_statement)] = "return;"
            
            # 매개변수 full: Parameter, 매개변수 type: ParameterType
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
            # line_num = int(location.split(':')[0])
            line_num = location
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

# callee 매개변수는 
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
    # 정규식으로 CWE와 숫자 부분을 추출
    match = re.search(r'CWE\d+', filename)
    if match:
        return match.group(0)  # CWE121 같은 형식 추출
    return None  # 매칭되지 않으면 None 반환

# 얘를 수정해야됨
catrgory_dict = {
    # "FC" :["CallExpression"],
    "FC" :["CALL"],
    "PU" : ["PtrMemberAccess"],
    "AU" : ["ArrayIndexing"],
    "AE" :  ["AdditiveExpression", "MultiplicativeExpression"],
    "ALL" : ["CallExpression", "PtrMemberAccess", "ArrayIndexing", "AdditiveExpression", "MultiplicativeExpression"]
}

def get_criterion(category, node_ln_to_id, nodes, genTest=False):
    assert category in ["FC","PU","AU","AE", "ALL"]
    
    criterion_list = [] # 리턴할 추출된 취약함수의 키, 함수명
    criterion_set = set()  # 동일한 노드(키)를 제외하기 위한 취약점 set
    
    if len(nodes) == 0: return []
    key = -1
    for node_idx, node in enumerate(nodes):
        node_type = node['type'].strip()
        
        # 결정적으로 여기선 criterion이 나올 수 없음: 해당 함수의 블록안에 함수들을 지정하는 것이기 때문
        if node_type == "METHOD" and not genTest:
            function_name = nodes[node_idx + 1]['code']
            
            # <empty>도 여기서 빼던지 아니면, 추출할때 안나오게 하던지 해야함
            if function_name  is None or function_name.strip() == '':
                    continue
            if function_name.find("bad") >= 0 or function_name.find("good") >= 0:
                 line_no = extract_line_number(node_idx, nodes)
                 key = extract_key_number(node_idx,nodes)
                 
                 
        elif node_type in catrgory_dict[category]:
            
            # Node Type Call인 경우(함수 내의 실제 호출 부(이전이름: CallExpression)
            if node_type == "CALL":
                function_name = extract_function_name(nodes[node_idx + 1])
            else:
                function_name = extract_function_name(node)
                
            if function_name:
                line_no = extract_line_number(node_idx, nodes)
                # print("Extracted line_no: ", line_no)

                if str(line_no) in node_ln_to_id:
                    key = node_ln_to_id[str(line_no)]
                    # 중복된 key를 criterion_set에 추가하여 중복 방지
                    if (key, function_name) not in criterion_set:
                        criterion_list.append([key, function_name])
                        criterion_set.add((key, function_name))
                else:
                    print(f"Warning: line_no {line_no} not found in node_ln_to_id")
    return criterion_list

# get_criterion 함수의 l_funcs 리스트 확인 및 list 만드는 로직이 너무 길어져 따로 함수 생성
def extract_function_name(node): 
    function_name = node['code']
    if function_name is None or function_name.strip() == '':
        return None
    
    match = re.match(r'(\w+)\s*\(', function_name.strip()) 
    
    if match:
        function_name = match.group(1)
        if function_name in l_funcs:
            return function_name
    return None   


# def calc_label(node_id_to_function, function_id, Sink_flag, Source_flag, genTest):
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
    
# def extract_function_name(func_declaration):
#     pattern = r'\w+\s*\(' 
#     match = re.search(pattern, func_declaration)

#     if match:
#         function_name = match.group(0)
#         function_name = function_name.rstrip('(')
#         return function_name.strip()  
#     else:
#         return "None"

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
        # nodes = read_csv(os.path.join(args.csv, filename, 'nodes.csv'))#######################################################################################
        # edges = read_csv(os.path.join(args.csv, filename, 'edges.csv'))    
       
        # --csv에 디렉토리를 주는 경우 경로를 이상하게 탐색 아래와 같이 변경
        nodes_csv_path = os.path.join(dir_path, 'nodes.csv')
        edges_csv_path = os.path.join(dir_path, 'edges.csv')
        nodes = read_csv(nodes_csv_path)
        edges = read_csv(edges_csv_path)
        
        # filename을 넘기면 자꾸 edges.csv를 먼저 띄우는 것은 해당 반복문이 지정한 디렉토리의 모든 파일을 순회하기 때문
        src  = os.path.join(args.src, 'CWE121_Stack_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_03.c')
        file1 = open(src,'r',encoding = "ISO-8859-1")
        
        
        
        #print("쏘스: ", file1)
        # 실제 raw source code 읽기
        code = file1.readlines()
      #  print(code)
        file1.close()

        
        else_key2line, else_line2key, Identifier_id_list, function_id_to_callee, function_info, function_id_to_entry, node_id_to_function_id, node_function_to_id, node_indices, node_ids, line_numbers, node_id_to_ln = extract_nodes_with_location_info(nodes)
        node_ln_to_id = {}
        for k,v in node_id_to_ln.items():
            if v in node_ln_to_id:
                continue
            node_ln_to_id[v] = k
            
        # 엔트리 노드도 감지가 안되므로, 아무값도 들어가지 않음
        # 이는 엣지를 활용해 Adjacency_list를 만들때 활용 됨
        #print("Function_id_to_entry: ", function_id_to_entry)    
            
        
        # 아무값도 출력이 되지 않음, 제대로 데이터가 들어가지 않는것으로 확인
        # 실제 슬라이싱 코드에서 Caller 즉, 자신의 부모함수가 누구인지 정도를 나타내는 데에만 사용
        # 추가적인 로직(Parameter, return 등)을 고려하긴 하지만 FC만의 슬라이스를 추출하는 해당 코드에서는 사용되지 않음
        # 사용하고자 하면 로직을 조금 바꿔야 함     
        print("Function_info: ", function_info)
        
        # entry면 진입점?    
        entry_node_ids = []
        for k,v in function_id_to_entry.items():
            entry_node_ids.append(v)
        
        # 이거 사용 안하나 보네
        node_id_to_function = {v:k for k,v in node_function_to_id.items()}
        
        # 나옴
        #print("node_id_to_function", node_id_to_function)

        # 노드id에 해당하는 취약점 발생 함수들을 리스트로 추출
        criterion_list = get_criterion(args.criterion,node_ln_to_id,nodes,args.genTest)    
        
        # edge의 타입에 따라 시작 노드, 끝노드를 추출 후 인접리스트를 통해 저장
        adjacency_list_REACHES = create_adjacency_list_nodeID(node_ids, entry_node_ids, edges, nodes, ['REACHES','REACHES'])
        adjacency_list_CONTROLS = create_adjacency_list_nodeID(node_ids, entry_node_ids, edges, nodes, ['CONTROLS','CONTROLS'])
        adjacency_list_DEF = create_adjacency_list_nodeID(node_ids, entry_node_ids, edges, nodes, ['DEF','USE'])
       
        # print("Adjacency_list_Reaches", adjacency_list_REACHES)
        # print("Adjacency_list_Control", adjacency_list_CONTROLS)
        # print("Adjacency_list_Def", adjacency_list_DEF)
       
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
            # 이쪽에서 불가능 왜 필요한 함수?
            # if find_function_info(function_info,node_id_to_function_id[target_id])['FunctionName'] == extract_function_name(code[node_id_to_ln[target_id] -1].strip()):
            #     continue
            
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
            print(all_slices_line)
            # label = -8
            
            
            # 레이블링 --> 해당 버전에서는 레이블링을 매뉴얼리하게 할 예정 즉, 레이블 필요 X
            # label = calc_label(node_id_to_function, node_id_to_function_id[target_id], Sink_flag, Source_flag, args.genTest)
             
            
            # 여기 라인 어떻게 모이는지 봐야됨   
            lines = []  # 스니펫이 될 라인들
            for idx,code_line in enumerate(all_slices_line):
                code_line = int(code_line)
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
                    
            cwe_id = get_CWE(filename)        
            
            
            # 애초에 여기서 지칭하는 filename이 edges이기 때문에 CWE를 가리킬 이유가 없음
            # filename, caller, category, criterion, line, slice
            data_instance['FileName'] = filename
            # data_instance['Caller'] = find_function_info(function_info,node_id_to_function_id[target_id])['FunctionName']
            # data_instance['Source'] = Source_flag
            # data_instance['Sink'] = Sink_flag
            # data_instance['idx'] = all_data_instance_last_index
            
            cwe_id = get_CWE(filename)
            if cwe_id:
                data_instance['CWE-ID'] = "CWE-" + cwe_id
            else:
                data_instance['CWE-ID'] = "CWE-Unknown"

            # data_instance['category'] = data[2]
            data_instance['criterion'] = data[1]
            data_instance['line'] = node_id_to_ln[data[0]]
            # data_instance['label'] = label
            
            # 지금 슬라이싱 라인 하나씩 밖에 안돼
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

           
           