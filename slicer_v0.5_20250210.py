""" 250210 - 0.5 version
    패치 예정 내역:
        -추가-
        종속성이 없는(필요없는 라인) 라인을 제거하는 로직 추가
        interprocedure를 고려하지 않은 슬라이스, 함수 영역을 확보하고, 이 범위 안에서 슬라이스를 수집
        
        -제거-
        invert_graph관련 로직 제거
        backward_slice 제거거
        
    이유:
        0.4 버전의 슬라이스에서 이전에는 수집되지 않았던 라인들을 잡았으나 추가적인 보완이 필요
        1. 수집 로직 상, criterion과 직간접적으로 이어지지 않으면 라인 수집이 되지않음
            1.1. 해당 부분을 수정해서 했으나, 전역으로 선언된 변수 등으로 인해 필요 이상의 로직이 수집됨
        2. 그럼에도 불구하고, 전역변수는 수집되지 않음
        
        이러한 문제들을 해결하고자 함
    
    패치 상세:
        1. 전역으로 선언된 요소들은 사전에 슬라이스에 담고 시작하는 등의 슬라이스 수집 로직 수정 예정
        
    개선 점:
        1. 이게 csv 파일을 불러온 node, edge의 경우는 매번 순회하면서 특정 노드, 엣지를 찾아야하는건가?
        그러다보니, 한번의 반복안에서 여러개의 기능이 추가되다보니까, 코드가 분리가 안됨
        
        2. 전반적인 코드 개선 ex. typehint 등
        
        3. 나중에 interfile로 가게되면, 지금처럼 line으로 직접 뜯으면, 잘 수집이 안될 수도
"""
import os
import json
import re 
import warnings
from typing import Dict, Set, List, Tuple

warnings.filterwarnings('ignore')
L_FUNCS = ['StrNCat', 'getaddrinfo', '_ui64toa', 'fclose', 'pthread_mutex_lock', 'gets_s', 'sleep', 
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

def combine_adjacency_list(adjacency_list: Dict[str, List[Set[str]]]) -> Dict[str, Set[str]]:
    cgraph: Dict[str, Set[str]] = {}
    for ln in adjacency_list:
        cgraph[ln] = set()
        # s는 현재 가리키고있는 key(ln의 )
        for s in adjacency_list[ln]:
            cgraph[ln].update(s)
    return cgraph

""" 슬라이스 수집 메소드 v0.2
    기존에 criterion과 직간접적으로 연결된 라인들에 대해서만 수집이 되었지만, 
    직접 연결되지 않아도, 특정 제어문 내에 속한 경우를 개선

    또한, 필요없는 라인들 제거
"""
def create_forward_slice_v2(cgraph: Dict[str, Set[str]], line_no, parent_method_id, method_range: Dict[str, List[Set[str]]], global_variable: Set[str]):
    sliced_lines = set()
    line_no = str(line_no)  # line_no를 문자열로 변환
    sliced_lines.add(line_no) # 우선 취약함수 호출 ln을 슬라이스에 추가가
    stack = [line_no]  # 바로 리스트에 추가하고 수집 시작
    new_global_variable_line = set()
    
    start_line = int(next(iter(method_range[parent_method_id][0])))
    end_line = int(next(iter(method_range[parent_method_id][1])))
    
    while stack:
        cur = stack.pop()
        if cur not in sliced_lines:
            sliced_lines.add(cur)
        if cur not in cgraph:
            continue
        
        adjacents = cgraph[cur]  # adj_list key를 해당 cur로 접근해 이어지는 라인들을 불러온다
        
        for line in adjacents:
            if line not in sliced_lines:
                stack.append(line)
                        
    additional = True
    while additional:
        additional = False

        for key in cgraph:
            key_int = int(key)

            # 현재 key가 sliced_lines에 없고, 연결된 노드 중 하나라도 sliced_lines에 있는 경우
            if key not in sliced_lines:
                if any(line in sliced_lines for line in cgraph[key]):
                    if start_line <= key_int <= end_line:
                        sliced_lines.add(key)
                        additional = True

            # key가 start_line ~ end_line 범위 안에 있는 경우
            if start_line < key_int <= end_line:
                adjacents = cgraph[key]

                for line in adjacents:
                    line_int = int(line)
                    if line not in sliced_lines and start_line <= line_int <= end_line and line_int != key_int:
                        sliced_lines.add(key)
                        sliced_lines.add(line)
                        additional = True        
    
    # 만일 수집된 애들을 key로 전역변수가 있는 라인으로 인접 리스트가 생성된 경우    
    for sliced_line in sliced_lines: 
        is_global = cgraph[sliced_line] & global_variable
        new_global_variable_line.update(is_global)
    
    sliced_lines.update(new_global_variable_line)
    sliced_lines.add(start_line)            
    sliced_lines = sorted(set(sliced_lines), key=int)
    return sliced_lines 

#! csv에서 적용된, \t으로 구분된 key를 인식하기 위해 각 col을 \t을으로 분할
def read_csv(csv_file_path) -> List[Dict[str, str]]:
    data: List[Dict[str, str]] = []
    with open(csv_file_path) as fp:
        header = fp.readline()
        header = header.strip()
        h_parts = [hp.strip() for hp in header.split('\t')] # 헤더 항목 리스트로 저장
        
        for line in fp:
            line = line.strip()
            instance = {}
            # line에서 col을 '\t'로 분리
            lparts = line.split('\t')
            for i, hp in enumerate(h_parts):
                # type별로 가지고 있는 속성이 다르므로 없는 경우 ''
                if i < len(lparts):
                    content = lparts[i].strip()
                else:
                    content = ''
                instance[hp] = content
            data.append(instance)
        return data

def create_adjacency_list(line_numbers: List[str], 
                          node_id_to_ln: Dict[str, str], 
                          edges, 
                          macro_candidate: List[str], 
                          method_range: Dict[str, List[Set[str]]]
                          ) -> Tuple[Dict[str, List[Set[str]]], Set[str]]:
    
    adjacency_list: Dict[str, List[Set[str]]] = {}
    global_variable: Set[str] = set() # 우선은 LOCAL이면서, LINE_NUMBER가 밑의 method_range 내에 속하지 않은 경우를 기반으로 수집
    # 모든 노드들에 대해 가지고있는 ln을 통해 adj_list를 초기화
    for ln in set(line_numbers):
        
        """ adj_list 수정 예정
            이유:
            v0.3 까지만 해도, 종속성 엣지만을 고려해, 종속성을 나타내는 엣지만을 고려,
            단순 CDG, REACHING_DEF만을 수집하게 되면, 슬라이스의 정확성이 떨어진다.

            adj_list를 아래와 같이 확장장
            [0]: CDG: CDG는 제어문의 조건식에 해당하는 노드로부터 조건 충족 여부에 상관없이 범위에 속한 모든 노드에 연결되어, 조건을 조금 더 추가함
            [1]: REACHING_DEF: 데이터 종속성에 해당하는 엣지를 수집한다. METHOD, METHOD_RETURN은 IDENTIFIER가 없어도, 연결되어 이 부분을 제외 
            [2]: REF: 지역, 전역, 구조체 변수 선언에 대한 라인을 수집하기 위해 REF 엣지 수집            
            [3]: AST: if - else에서 else가 존재하는 라인을 수집하기 위해선                    
            [4]: CALL: 매크로 변수 수집을 위한 CALL 엣지
        """   
        adjacency_list[ln] = [set(), set(), set(), set(), set()]

    # edges.csv 파일에 대해 순환
    for edge in edges:
        edge_type = edge['type'].strip()
        
        if True :            
            start_node_id = edge['start'].strip()
            end_node_id = edge['end'].strip()
            
            # 만일 노드 id가 id - ln 어레이 안에 없을 경우 스킵
            if start_node_id not in node_id_to_ln.keys() or end_node_id not in node_id_to_ln.keys():
                continue
            
            # CPG edge 상으로는 존재하지만 BLOCK 노드와는 코드상에서의 logical한 dependency는 존재 X, 코드 수집에 방해가 되어 일단 제외
            if edge['startType'] == 'BLOCK' or edge['endType'] == 'BLOCK':
                continue
            
            start_ln = node_id_to_ln[start_node_id]
            end_ln = node_id_to_ln[end_node_id]
                        
            if edge_type == 'CDG' and (edge['endType'] == 'JUMP_TARGET' or edge['endType'] == 'CONTROL_STRUCTURE' or edge['endType'] == 'IDENTIFIER'): #Control Flow edges
                adjacency_list[start_ln][0].add(end_ln)
                
            if edge_type == 'REACHING_DEF' and not (edge['startType'] == 'METHOD' or edge['endType'] == 'METHOD_RETURN'): # Data Flow edges
                adjacency_list[start_ln][1].add(end_ln)
            
            # 변수 ref 및 구조체 필드 슬라이스 추출을 위한 엣지 수집
            if (edge['startType'] or (edge['startType'] == 'CALL' and edge['endType'] == 'MEMBER')) and edge_type == 'REF':
                adjacency_list[start_ln][2].add(end_ln)

                # end_ln이 method_range 내 어느 범위에도 속하지 않는 경우 global_variable에 추가
                in_method_range = False
                for node_id, ranges in method_range.items():
                    start_set, end_set = ranges
                    # start_set과 end_set이 비어있지 않은 경우 정수 변환하여 범위 비교
                    if start_set and end_set:
                        start_list = sorted(int(x) for x in start_set)  # 정수 변환 후 정렬
                        end_list = sorted(int(x) for x in end_set)  # 정수 변환 후 정렬

                        start_min = start_list[0]  # 최소 시작 라인
                        end_max = end_list[-1]  # 최대 끝 라인
                        
                        # 즉, 수집된 method_range set에서 하나도 겹치지 않는 경우에 
                        if start_min <= int(end_ln) <= end_max:
                            in_method_range = True
                            break

                if not in_method_range and (end_ln not in global_variable):
                    global_variable.add(end_ln)
                    
            if (edge['startType'] and edge['endType']  == 'CONTROL_STRUCTURE') and edge_type == 'AST':
                adjacency_list[start_ln][3].add(end_ln)
                
            #수집은 성공, 예상했던대로, callee에 대한 모든 엣지들이 전부 수집된다. 매크로 변수임을 식별할 수 있는 방법은?
            if (edge['startType'] == 'CALL' and end_node_id in macro_candidate) and edge_type == 'CALL':
                adjacency_list[start_ln][4].add(end_ln)            
    return adjacency_list, global_variable


def extract_nodes_with_location_info(nodes) -> Tuple[List[str], Dict[str, str], List[str], Dict[str, List[Set[str]]]]:
    node_ids: List[str] = []   #모든 노드들의 Id, 해당 메소드에서 현재 노드를 식별하기 위해서 사용 
    line_numbers: List[str] = []   #노드가 위치한 ln
    node_id_to_ln: Dict[str, str] = {} #노드 Id에 대응되는 ln(이를 통해 노드 쌍을 수집) 
    macro_candidate: List[str] = [] # 매크로 변수를 확인할 수 있는 것은 IS_EXTERNAL이 TRUE인 node들이다. 
    method_range: Dict[str, List[Set[str]]] = {} # 함수들의 영역을 확인하기 위한 데이터, 

    for node_index, node in enumerate(nodes):
        assert isinstance(node, dict)
        
        if 'key' in node:
            node_id = node['key'].strip()
            
        else:
            print(f"Warning: 'key' not found in node at index {node_index}")
            continue  # Skip this node or assign a default value)
        
        node_ids.append(node_id)
        
        if node['type'].strip() == 'BLOCK':
            continue
        
        if node['type'].strip() == 'METHOD' and node['isExternal'] == 'True' and node.get('location', '').strip():
            macro_candidate.append(node_id)
        
        # ln 노드에는 이제 Line number, Column number가 따로 있음
        if 'location' in node.keys():
            location = node['location']
            if location == '':
                continue
            line_num = location
            line_numbers.append(line_num)
            node_id_to_ln[node_id] = line_num
            
        if 'location' and 'locationEnd' in node.keys():
            location_end = node['locationEnd']
            if location_end == '' or node['name'] == '<global>':
                continue
            method_start = location
            method_end = location_end
            method_range[node_id] = [set(), set()]
            method_range[node_id][0].add(method_start)
            method_range[node_id][1].add(method_end)
    
    return line_numbers, node_id_to_ln, macro_candidate, method_range

def search_function_call(nodes) -> Set[Tuple[str, int, str, str]]:
    #
    function_calls: Set[Tuple[str, int, str, str]] = set()
    for node_idx, node in enumerate(nodes):
        ntype = node['type'].strip()
        if ntype == 'CALL':
            function_name = nodes[node_idx + 1]['name']     
            if function_name  is None or function_name.strip() == '':
                continue
            if function_name.strip() in L_FUNCS:
                #취약함수가 위치하는 ln을 수집
                node_id = node['key'].strip()
                line_no = int(node['location'])
                parent_method_id = node['functionId'].strip()
                if line_no > 0 and node_id is not None:
                    function_calls.add((function_name, line_no, node_id, parent_method_id))
    return function_calls

def get_CWE(filename):
    CWEID = filename.split('_')[0]
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
                    slice_line = lines[index - 1].rstrip()
                    extracted_lines.append(slice_line)  # Access specific line
    except FileNotFoundError:
        print(f'Error: File not found - {file_path}')
    except Exception as e:
        print(f'An error occurred: {e}')
    return extracted_lines

# root_dir: 추출하기 위해 필요한 파일 위치, slice_dir: 생성된 코드 스니펫이 저장될 위치
def process_directory(root_dir, slice_dir):
    for sub_dir in os.listdir(root_dir):
        
        slice_Dir = slice_dir
        sub_dir_path = os.path.join(root_dir, sub_dir)
        
        #수집한 취약함수 호출에 해당하는 스니펫을 저장하기 위한 데이터
        all_data_instance=[]
        
        if not os.path.isdir(sub_dir_path):
            continue
        
        # 동일한 flaw를 가진 여러 유형의 취약점 코드가 포함된 각 디렉토리를 순회, .c, .cpp파일을 확인한다
        src_file = os.path.join(sub_dir_path, [f for f in os.listdir(sub_dir_path) if f.endswith('.c') or f.endswith('.cpp')][0])
        # 파일 명 추출
        src_filename = os.path.basename(src_file)
        
        # if sub_dir_path == 'R_dir_CWE121_CWE129_fgets\\CWE121_CWE129_fgets_01':
        #     continue
        nodes_csv = os.path.join(sub_dir_path, 'nodes.csv')
        edges_csv = os.path.join(sub_dir_path, 'edges.csv')
        
        # nodes, edges에 대한 데이터 수집을 위해 오브젝트화 
        nodes = read_csv(nodes_csv)
        edges = read_csv(edges_csv) 
        
        # 취약함수 호출 지점을 수집하기 위한 메소드 호출
        call_lines = search_function_call(nodes)      
        
        # nodes를 순회하면서 슬라이스 추출에 필요한 요소들을 수집
        line_numbers, node_id_to_ln, macro_candidate, method_range = extract_nodes_with_location_info(nodes)
         
        # edges를 순회하면서, 슬라이스 추출에 필요한 관계성을 확인 후 인접리스트를 생성
        adjacency_list, global_variable = create_adjacency_list(line_numbers, node_id_to_ln, edges, macro_candidate, method_range)              
        # edge type별로 수집된 인접리스트 병합
        combined_graph = combine_adjacency_list(adjacency_list)   

        for function_name, slice_ln, node_id, parent_method_id in call_lines:
            
            data_instance = {}
            all_slices = []
            forward_sliced_lines = create_forward_slice_v2(combined_graph, slice_ln, parent_method_id, method_range, global_variable)
            all_slice_lines = forward_sliced_lines
            all_slice_lines = sorted(set(all_slice_lines), key=int)
            
            all_slices.append(all_slice_lines)
            cwe_id = get_CWE(src_filename)
            
            all_code_slices = extract_lines_from_c_source(src_file, all_slices)
                        
            if cwe_id:
                data_instance['CWE-ID'] = 'CWE-' + cwe_id
            else:
                data_instance['CWE-ID'] = 'CWE-Unknown'

            data_instance['criterion'] = function_name
            data_instance['line'] = slice_ln
            data_instance['slices'] = all_code_slices
            
            all_data_instance.append(data_instance)
    
        output_path = os.path.join(slice_Dir, f'slices_{sub_dir}.json')

        print(f'Attempting to write to: {output_path}')
        with open(output_path, 'w') as json_file:
            json.dump(all_data_instance, json_file)   

# root_dir: 작업할 파일, slice_dir: 슬라이스 저장할 파일
if __name__ =='__main__':
    root_dir = 'R_dir_CWE121_CWE129_fgets'
    slice_dir = 'slices_Dir'
    process_directory(root_dir, slice_dir)    