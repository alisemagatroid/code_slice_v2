""" 250210 - 0.6 version
    기능 구현 완료 후 코드 개선을 위한 버전
    
    
    250225
    지금 dir 내부의 파일이 고정되어있는 상태, 객체지향으로 바꿀 여지가 다분하다...
    
    
    250226
    extract_node_info의 function_range의 데이터 type, tuple로 변경
    Dict .get, .keys 차이 복습
    
    
    250304
    backward 탐색을 위해 백업한 버전
"""
import os
import json
import re
import warnings
import glob
from typing import Dict, Set, List, Tuple

warnings.filterwarnings('ignore')
# 취약점을 유발할 수 있는 함수의 목록을 set 자료구조에 저장
"""
L_FUNCS = {'StrNCat', 'getaddrinfo', '_ui64toa', 'fclose', 'pthread_mutex_lock', 'gets_s', 'sleep',
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
           'PQfinish', 'PQexec', 'PQresultStatus', 'atoi', 
           }
"""
L_FUNCS = {'parse_mqtt', 'mg_mqtt_broker_handle_subscribe', 'mg_mqtt_next_subscribe_topic', 'mg_dns_uncompress_name', 'mg_http_proto_data', 'mg_parse_http', 'mg_upload', 'mg_create_connection'}

def combine_adjacency_list(adjacency_list: Dict[str, List[Set[str]]]) -> Dict[str, Set[str]]:
    cgraph: Dict[str, Set[str]] = {}
    for ln in adjacency_list:
        cgraph[ln] = set()
        # adj는 현재 가리키고있는 key(라인)로부터 존재하는 각 유형의 인접리스트를 나타낸다.
        for adj in adjacency_list[ln]:
            cgraph[ln].update(adj)
    return cgraph

# 합집합을 구한 인접 리스트를 통해 스니펫으로 추출할 라인들을 선정한다.
def create_forward_slice(cgraph: Dict[str, Set[str]],
                         line_no,
                         parent_method_id,
                         function_range: Dict[str, Tuple[str]],
                         global_variable: Set[str]):
    # 수집될 라인들은 중복해서 수집할 필요가 없고 라인 그대로 즉, key값만 사용하므로 set()을 사용한다.
    sliced_lines = set()
    line_no = str(line_no)  # line_no를 문자열로 변환
    sliced_lines.add(line_no)  # 우선 취약함수 호출 ln을 슬라이스에 추가가
    stack = [line_no]  # 바로 리스트에 추가하고 수집 시작
    new_global_variable_line = set()

    # 어차피 메소드 범위면, 처음에 값 넣을때, int로 변환해서 넣어도 되지 않나.
    range_values = function_range[parent_method_id]
    start_line = int(range_values[0])
    end_line = int(range_values[1])
    
    # 취약 함수 호출 지점을 기반으로(취약 함수 호출 라인을 포함한) 직, 간접적으로 엣지가 발생하는 라인들을 스니펫에 추가한다.
    while stack:
        cur = stack.pop()
        if cur not in sliced_lines:
            sliced_lines.add(cur)
        # end if
        if cur not in cgraph:
            continue
        # end if

        adjacents = cgraph[cur]  # adj_list key를 해당 cur로 접근해 이어지는 라인들을 불러온다

        for line in adjacents:
            if line not in sliced_lines:
                stack.append(line)
            # end if
        # end for
    # end while

    # 취약함수 노드로 직, 간접적으로 엣지가 발생하는 라인들을 스니펫에 추가한다.
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

            # key가 start_line ~ end_line 범위 안에 있는 경우 추가한다.
            if start_line < key_int <= end_line:
                adjacents = cgraph[key]

                for line in adjacents:
                    line_int = int(line)
                    # key로부터 이어지는 라인들이 수집되지 않고, 해당 메소드의 범위 내에 존재하는 경우 추가한다.
                    if line not in sliced_lines and start_line <= line_int <= end_line and line_int != key_int:
                        sliced_lines.add(key)
                        sliced_lines.add(line)
                        additional = True

    # 현재 수집된 라인에서, 전역변수가 위치한 라인으로 이어지는 경우 전역변수 라인을 슬라이스에 추가한다.
    for sliced_line in sliced_lines:
        is_global = cgraph[sliced_line] & global_variable
        new_global_variable_line.update(is_global)

    sliced_lines.update(new_global_variable_line)
    # start_line은 해당 method 이름을 나타내는 라인이다.
    sliced_lines.add(str(start_line))
    sliced_lines = sorted(set(sliced_lines), key=int)
    return sliced_lines

#! csv의 \t으로 구분된 헤더를 인식하기 위해 각 col을 \t을으로 분할한다.
# 현재는 csv의 데이터를 전부 가져와서 한번에 처리하는데, 이를 우선 다 받아오고 필요한 기능별로 함수로 구현
    """
        헤더, 데이터를 따로 리스트로 받고 
        
        후에 data에 값을 추가하는 것은 따로 처리한다.

        cpg의 csv파일을 생성할때, 하나의 파일의 크기가 크지 않을것으로 예상되기에, 리스트화 해서 반복하는 로직으로 수정했다.
        => 엄청 커지면, 리스트화하면, 이거를 메모리에서 잡고있어서 느려질 수 있음
        
        15000 여 라인의 cpg를 .json으로 export시, 180mb정도가 되고
        csv 변환시 edge는 한 13mb, node는 1.9mb 정도
        
    """
def extract_csv_data(csv_file_path) -> List[Dict[str, str]]:
    data: List[Dict[str, str]] = []

    with open(csv_file_path) as fp:
        header = fp.readline()
        header = header.strip()

        h_parts = []

        for hp in header.split('\t'):
            hp_stripped = hp.strip()
            h_parts.append(hp_stripped)
        # end for

        l_parts = []

        for line in fp:
            line = line.strip()
            line_stripped = line.split('\t')
            l_parts.append(line_stripped)
        # end for

        # 확인해 보니, 추후에, line이 h_parts의 길이보다 작은 라인을 사용할 여지가 있음,
        for line in l_parts:
            instance = {}
            for i in range(len(h_parts)):
                # type별로 가지고 있는 속성이 다르므로 없는 경우는 공백으로 처리한다.
                if i < len(line):
                    content = line[i].strip()

                # 없애고 cpg상에서 크기 제대로 안잡히는 라인들은 다 빼고 아래 로직 삭제
                else:
                    content = ''
                instance[h_parts[i]] = content
            data.append(instance)
            # end for
        # end for
        return data

# 스니펫 수집에 필요한 type의 엣지를 찾아 노드 쌍(인접 리스트)을 생성한다.
def create_adjacency_list(line_numbers: List[str],
                          node_id_to_ln: Dict[str, str],
                          edges: List[Dict[str, str]],
                          macro_candidate: List[str],
                          function_range: Dict[str, Tuple[str]]
                          ) -> Tuple[Dict[str, List[Set[str]]], Set[str]]:

    adjacency_list: Dict[str, List[Set[str]]] = {}
    # 우선은 LOCAL이면서, LINE_NUMBER가 밑의 function_range 내에 속하지 않은 경우를 기반으로 수집
    global_variable: Set[str] = set()
    # 모든 노드들에 대해 가지고있는 ln을 통해 adj_list를 초기화
    for ln in set(line_numbers):

        """ adj_list(인접 리스트) 수집 데이터

            [0]: CDG: 제어 종속성을 나타내는 엣지
            [1]: REACHING_DEF: 데이터 종속성을 나타내는 엣지 
            [2]: REF: 지역, 전역, 구조체 변수 참조를 나타내는 엣지            
            [3]: AST: if - else는 CDG로 이어지지 않아 이를 추가하기 위한 AST 엣지                    
            [4]: CALL: 매크로 변수 수집을 위한 CALL 엣지
        """
        adjacency_list[ln] = [set(), set(), set(), set(), set()]

    # edges.csv 파일에 대해 순환
    for edge in edges:
        edge_type = edge['type']
        start_edge_type = edge['startType']
        end_edge_type = edge['endType']

        if True:
            start_node_id = edge['start']
            end_node_id = edge['end']

            # 만일 노드 id가 id - ln 어레이 안에 없을 경우 스킵
            if start_node_id not in node_id_to_ln.keys() or end_node_id not in node_id_to_ln.keys():
                continue

            # BLOCK노드에서는 포함되는 모든 노드에 엣지가 연결되어, 제외한다.
            if start_edge_type == 'BLOCK' or end_edge_type == 'BLOCK':
                continue

            # edges에는 line number에 대한 속성값을 가지고 있지 않아 'extract_nodes_data'에서 추출한 값을 사용한다.
            start_ln = node_id_to_ln[start_node_id]
            end_ln = node_id_to_ln[end_node_id]

            # 제어문의 범위 확인에 필요하지만, 취약함수 호출 라인과 직접 CDG 연결이 되지않아 수집되지 않는 제어문 노드를 수집한다.
            # Control Dependency edges
            if edge_type == 'CDG' and (end_edge_type == 'JUMP_TARGET' or end_edge_type == 'CONTROL_STRUCTURE' or end_edge_type == 'IDENTIFIER'):
                adjacency_list[start_ln][0].add(end_ln)

            # METHOD, METHOD_RETURN 노드는 자신이 포함하고 있는 노드에 전부 REACHING_DEF로 이어져 스니펫 개선을 위해 제외한다.
            if edge_type == 'REACHING_DEF' and not (start_edge_type == 'METHOD' or end_edge_type == 'METHOD_RETURN'):
                adjacency_list[start_ln][1].add(end_ln)

            # 변수 참조 및 구조체 필드가 위치한 라인을 추출하기 위한 조건에 맞는 REF 엣지를 수집한다.
            if edge_type == 'REF' and (start_edge_type or (start_edge_type == 'CALL' and end_edge_type == 'MEMBER')):
                adjacency_list[start_ln][2].add(end_ln)

                # end_ln이 function_range 내 어느 범위에도 속하지 않는 경우 global_variable에 추가한다.

                in_function_range = False
                # 각 함수의 범위 별로 순환한다.
                for fr in function_range.values():         
                    # tuple의 첫번째 값은 ln 두번째 값은 ln_end를 가져왔다.
                    start_line = fr[0]
                    end_line = fr[1]
                    
                    # 둘다 값은 있는데 음수가 있거나 그런 경우가 있다,
                    if int(start_line) <= int(end_ln) <= int(end_line):
                        in_function_range = True
                        break

                # 가리키고 있는 변수의 위치가, 어디에도 위치하지 않으면서, 수집되지 않은 경우에 추가한다.
                if not in_function_range and (end_ln not in global_variable):
                    global_variable.add(end_ln)

            # CONTROL_STRUCTURE 노드간의 AST 엣 지를 수집해 제어문이 위치한 라인을 수집한다.
            if (start_edge_type and end_edge_type == 'CONTROL_STRUCTURE') and edge_type == 'AST':
                adjacency_list[start_ln][3].add(end_ln)

            # macro_candidate를 호출하는 경우 해당 라인과 CALL Edge가 이어져, 해당 라인을 수집한다.
            if (start_edge_type == 'CALL' and end_node_id in macro_candidate) and edge_type == 'CALL':
                adjacency_list[start_ln][4].add(end_ln)
    return adjacency_list, global_variable

# 추출한 nodes에서 필요한 노드 데이터를 추출한다.
# type hint 수정
def extract_nodes_info(nodes: List[Dict[str, str]]) -> Tuple[List[str], Dict[str, str], List[str], Dict[str, List[Set[str]]]]:
    """사용하는 데이터
    Objects:
        line_numbers: 노드가 위치한 ln
        node_id_to_ln: 노드 id에 대응되는 ln(소스코드 상의 해당 노드의 위치)
        macro_candidate: 매크로 변수에 해당하는 노드 id
        function_range: 소스코드 내 함수들의 범위
    """
    line_numbers: List[str] = []
    node_id_to_ln: Dict[str, str] = {}
    macro_candidate: List[str] = []
    function_range: Dict[str, Tuple[str]] = {}

    # 필요한 노드의 구분 없이 일단 다 수집하고있다.
    for node in nodes:
        # 이미 모든 nodes.csv의 행에는 key값은 무조건 존재한다.
        if 'key' in node:
            node_id = node['key']
        # end if
        
        # 자주 사용하는 조건식은 데이터화
        node_type = node['type']
        node_loc = node['location']
        # BLOCK Type 노드의 경우 불필요한 종속성 엣지가 많이 존재하여, skip
        if node_type == 'BLOCK':
            continue
        # end if
        
        # METHOD 노드에서, line number의 값을 가지면서 외부에서 정의되었다고 표시되는 METHOD 노드는 매크로 변수, 함수 뿐이다.
        # 이러면 지금 값의 존재 유무만 확인인
        
        #.get으로 가져오는 거랑 .key()로 확인 하는거랑 처리가 다르다.(Dict 함수 참고)
        if node_type == 'METHOD' and node['isExternal'] == 'True' and len(node_loc) > 0:
            macro_candidate.append(node_id)
        # end if

        # line number가 확인되는 노드
        # 지금은 key가 있는지 확인, 우선 아예 값이 없는 경우가 아니면 조건을 통과하고 ''인 경우 무시한다.
        if len(node_loc) > 0:
            line_numbers.append(node_loc)
            node_id_to_ln[node_id] = node_loc
        # end if

        # 내부에서 선언, 정의된 METHOD 노드는 속성 값으로 line의 시작과 끝을 가지고 있따.
        if 'locationEnd' in node:
            line_num_end = node['locationEnd']

            # line number가 확인되지 않거나, 전역에 해당하는 METHOD 노드는 skip
            if len(line_num_end) == 0 or node['name'] == '<global>' or int(line_num_end) < 0:
                continue
            # end if
            
            function_range[node_id] = (node_loc, line_num_end)
            
        # end if
    # end for
    return (line_numbers, node_id_to_ln, macro_candidate, function_range)

# 취약 함수가 호출된 노드에 대한 정보를 추출한다.
def search_function_call(nodes) -> Set[Tuple[str, int, str]]:
    # 취약함수 호출 지점을 나타내는 오브젝트
    # 같은 라인에 동일한 함수 호출이 존재할 수 있음, Dict로 변경 key: 노드id, 값은 tuple로 
    function_calls: Dict[str, Tuple[str, int, str]] = dict()

    # 모든 노드에 대해서 순환
    for node in nodes:
        if 'type' not in node:
            continue
        #end if
        
        ntype = node.get('type')

        # if조건들 한번씩 더 검토
        if ntype == 'CALL':
            function_name = node['name']

            # empty string을 비교할때는 len == 0 으로 비교하는 것이 더 효율적임임
            if function_name is None or len(function_name) == 0:
                continue
            # end if

            if function_name in L_FUNCS:
                node_id = node['key']
                line_no = int(node['location'])
                parent_method_id = node['functionId']
                function_calls[node_id] = (function_name, line_no, parent_method_id)
            # end if
        # end if
    # end for     
    return function_calls

def get_CWE(filename):
    CWEID = filename.split('_')[0]
    return re.sub(r'[^0-9]', '', CWEID)

# 추출하고자하는 라인을 소스 코드에서 직접 추출한다.
def extract_lines_from_c_source(file_path, all_slices):
    extracted_lines = []
    line_numbers = []

    # 추출한 line을 int값으로 변환한다.   
    for line in all_slices:
        line_numbers.append(int(line))
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            for index in line_numbers:
                if 1 <= index <= len(lines):
                    # line에 직접 접근했으므로 인덱스를 하나 줄여서 사용한다.
                    slice_line = lines[index - 1].rstrip()
                    extracted_lines.append(slice_line)
                # end if
    except FileNotFoundError:
        print(f'Error: File not found - {file_path}')
    except Exception as e:
        print(f'An error occurred: {e}')
    return extracted_lines


def process_sub_directory(root_dir) -> List:
    sub_dirs: List[str] = []

    for dir in os.listdir(root_dir):
        sub_dirs.append(dir)
    # end for
    return sub_dirs

# 서브 디렉토리 내에서 파일을 받아온다.

def load_files(sub_dir_path):
    src_file = os.path.join(sub_dir_path, [f for f in os.listdir(
        sub_dir_path) if f.endswith('.c') or f.endswith('.cpp')][0])
    nodes_csv = os.path.join(sub_dir_path, 'nodes.csv')
    edges_csv = os.path.join(sub_dir_path, 'edges.csv')

    return src_file, nodes_csv, edges_csv


# root_dir: 추출하기 위해 필요한 파일 위치, slice_dir: 생성된 코드 스니펫이 저장될 위치
def process_directory(root_dir, slice_dir):

    # rood_dir 하위의 디렉토리들을 리스트화
    sub_dirs = process_sub_directory(root_dir)

    slice_Dir = slice_dir

    # process_sub_directory: 디렉토리 하나씩 처리
    # 근데 이게.... 뭐 바뀐게 있나? ㅋㅋㅋㅋ
    for sub_dir in sub_dirs:

        all_data_instance = []

        sub_dir_path = os.path.join(root_dir, sub_dir)

        src_file, nodes_csv, edges_csv = load_files(sub_dir_path)

        src_filename = os.path.basename(src_file)

        # nodes, edges에 대한 데이터 수집을 위해 오브젝트화 한다.
        nodes = extract_csv_data(nodes_csv)
        edges = extract_csv_data(edges_csv)

        # 취약함수 호출 지점을 수집하기 위한 메소드 호출한다.
        call_lines = search_function_call(nodes)

        # nodes를 순회하면서 슬라이스 추출에 필요한 요소들을 수집한다.
        (line_numbers, node_id_to_ln, macro_candidate, function_range) = extract_nodes_info(nodes)

        # edges를 순회하면서, 슬라이스 추출에 필요한 관계성을 확인 후 인접리스트를 생성한다.
        adjacency_list, global_variable = create_adjacency_list(line_numbers, node_id_to_ln, edges, macro_candidate, function_range)

        # edge type별로 수집된 인접리스트 병합한다.
        combined_graph = combine_adjacency_list(adjacency_list)
        
        # 수집된 취약함수 호출 라인하나당 스니펫을 생성한다.
        #
        for function_name, slice_ln, parent_method_id in call_lines.values():

            """ 코드 스니펫 구조
                CWE-ID: '파일이름으로 부터 추출한 CWE-ID' 
                criterion: '호출된 취약 함수' 
                line: '취약 함수 호출 위치'
                slices: '코드 슬라이스'
            """
            data_instance = {}
            snippet = []

            sliced_lines = create_forward_slice(combined_graph, slice_ln, parent_method_id, function_range, global_variable)

            snippet = sorted(set(sliced_lines), key=int)

            cwe_id = get_CWE(src_filename)

            all_code_slices = extract_lines_from_c_source(src_file, snippet)

            if cwe_id:
                data_instance['CWE-ID'] = 'CWE-' + cwe_id
            else:
                data_instance['CWE-ID'] = 'CWE-Unknown'
            data_instance['criterion'] = function_name
            data_instance['line'] = slice_ln
            data_instance['slices'] = all_code_slices

            all_data_instance.append(data_instance)
        #end for

        output_path = os.path.join(slice_Dir, f'slices_{sub_dir}.json')
        print(f'Attempting to write to: {output_path}')
        with open(output_path, 'w') as json_file:
            json.dump(all_data_instance, json_file)
    # end for        

# root_dir: 작업할 파일, slice_dir: 슬라이스 저장할 파일
if __name__ == '__main__':
    # root_dir = 'R_dir_CWE121_CWE129_fgets'
    # slice_dir = 'slices_Dir'
    root_dir = 'R_dir_mongoose'
    slice_dir = 'mongoose_slices'
    process_directory(root_dir, slice_dir)
    
