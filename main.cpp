#define WIN32_LEAN_AND_MEAN
#pragma warning (disable:4996)
#include <windows.h>
#include <iostream>
#include <shlobj.h>
#include <string>
#include <TlHelp32.h>
using namespace std;

BOOL Run_as_System(LPCWSTR run) {
    //��Ȩ��Debug�Ի�ȡ���̾��
    //https://blog.csdn.net/zuishikonghuan/article/details/47746451
    HANDLE hToken;
    LUID Luid;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    //ö�ٽ��̻�ȡlsass.exe��ID��winlogon.exe��ID�����������еĿ���ֱ�Ӵ򿪾����ϵͳ����
    DWORD idL, idW;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (0 == wcscmp(pe.szExeFile, L"lsass.exe")) {
                idL = pe.th32ProcessID;
            }
            else if (0 == wcscmp(pe.szExeFile, L"winlogon.exe")) {
                idW = pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    //��ȡ���������lsass����winlogon
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
    if (!hProcess)hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
    HANDLE hTokenx;
    //��ȡ����
    OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx);
    //��������
    DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hToken);
    CloseHandle(hProcess);
    CloseHandle(hTokenx);
    //������Ϣ
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi;
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";//��ʾ����
    //�������̣�������CreateProcessAsUser���򱨴�1314����Ȩ
    BOOL ret = CreateProcessWithTokenW(hToken, LOGON_NETCREDENTIALS_ONLY, NULL, (LPWSTR)run, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
    CloseHandle(hToken);

    return ret;
}

BOOL IsFileExistsA(LPCSTR path) {
    DWORD a = GetFileAttributesA(path);
    if (a != INVALID_FILE_ATTRIBUTES && a != FILE_ATTRIBUTE_DIRECTORY)
    return true;
    return false;
}

BOOL IsDirectoryExistsA(LPCSTR path) {
    DWORD a = GetFileAttributesA(path);
    if (a != INVALID_FILE_ATTRIBUTES && a == FILE_ATTRIBUTE_DIRECTORY)
        return true;
    return false;
}

DWORD GetProcessIdW(LPCWSTR szProcessName){
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hProcessSnapShot == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnapShot, &pe32)) return NULL;
   
    DWORD result = NULL;
    do {
        if (wcscmp(szProcessName, pe32.szExeFile) == 0) {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnapShot, &pe32));
   
    CloseHandle(hProcessSnapShot);
    return result;
}

bool rmdir(const char* dir) {
    HANDLE hFind;
    WIN32_FIND_DATAA wfd;

    std::string searchPath(dir);
    searchPath.append("\\*");

    hFind = FindFirstFileA(searchPath.c_str(), &wfd);
    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    do {
        if (strcmp(wfd.cFileName, ".") == 0 || strcmp(wfd.cFileName, "..") == 0)
            continue;

        std::string file(dir);
        file.append("\\").append(wfd.cFileName);

        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            rmdir(file.c_str());
        }
        else {
            DeleteFileA(file.c_str());
        }
    } while (FindNextFileA(hFind, &wfd));

    FindClose(hFind);

    RemoveDirectoryA(dir);
    return true;
}

HANDLE hConsole;

#define CONSOLE_COLOR_RED(statement) do {\
    SetConsoleTextAttribute(hConsole, 4);\
    statement;\
    SetConsoleTextAttribute(hConsole, 7);\
} while (0)

#define CONSOLE_COLOR_GREEN(statement) do {\
    SetConsoleTextAttribute(hConsole, 2);\
    statement;\
    SetConsoleTextAttribute(hConsole, 7);\
} while (0)

#define CONSOLE_COLOR_YELLOW(statement) do {\
    SetConsoleTextAttribute(hConsole, 6);\
    statement;\
    SetConsoleTextAttribute(hConsole, 7);\
} while (0)

void myexit() {
    getchar();
    exit(1);
}

int wmain(int argc,wchar_t**argv) {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    char currentUser[MAX_PATH] = { 0 };
    DWORD dwSize_currentUser = sizeof currentUser;
    GetUserNameA(currentUser, &dwSize_currentUser);

    if (strcmp(currentUser, "SYSTEM") != 0) {
        printf("\n\n���ֶ�����Ĭ�����������ɺ����������");
        system("start ms-settings:defaultapps?registeredAppMachine=Microsoft Edge");
        system("pause>nul");


        if (DWORD pid = GetProcessIdW(L"msedgewebview2.exe")) {
            printf("\n\n��ֹedge webview����......");
            if (TerminateProcess(OpenProcess(PROCESS_TERMINATE, false, pid), 0)) {
                CONSOLE_COLOR_GREEN(printf("�ɹ�"));
            }
            else {
                CONSOLE_COLOR_RED(printf("ʧ��"));
                myexit();
            }
        }

        if (DWORD pid = GetProcessIdW(L"msedge.exe")) {
            printf("\n\n��ֹedge���������......");
            if (TerminateProcess(OpenProcess(PROCESS_TERMINATE, false, pid), 0)) {
                CONSOLE_COLOR_GREEN(printf("�ɹ�"));
            }
            else {
                CONSOLE_COLOR_RED(printf("ʧ��"));
                myexit();
            }
        }

        printf("\n\nɾ������ļ�......");
        rmdir("C:\\Program Files (x86)\\Microsoft\\Edge");
        rmdir("C:\\Program Files (x86)\\Microsoft\\EdgeWebView");
        rmdir("C:\\Program Files (x86)\\Microsoft\\EdgeCore");
        rmdir("C:\\Program Files (x86)\\Microsoft\\EdgeUpdate");
        rmdir("C:\\ProgramData\\Microsoft\\EdgeUpdate");
        rmdir("C:\\Windows\\System32\\Microsoft-Edge-WebView");

        char szLocal[MAX_PATH] = { 0 };
        if (!SHGetSpecialFolderPathA(0, szLocal, CSIDL_LOCAL_APPDATA, 0)) {
            printf("ʧ��:�޷���ȡlocal·��");
            myexit();
        }
        strcat_s(szLocal, "\\Microsoft\\Edge");
        rmdir(szLocal);

        if (IsDirectoryExistsA("C:\\Program Files (x86)\\Microsoft\\Edge") ||
            IsDirectoryExistsA("C:\\Program Files (x86)\\Microsoft\\EdgeWebView") ||
            IsDirectoryExistsA("C:\\Program Files (x86)\\Microsoft\\EdgeCore") ||
            IsDirectoryExistsA("C:\\Program Files (x86)\\Microsoft\\EdgeUpdate") ||
            IsDirectoryExistsA("C:\\ProgramData\\Microsoft\\EdgeUpdate") ||
            IsDirectoryExistsA("C:\\Windows\\System32\\Microsoft-Edge-WebView") ||
            IsDirectoryExistsA(szLocal)
            )
        {
            CONSOLE_COLOR_YELLOW(printf("����:�����ļ��޷�ɾ����������������"));
        }
        else {
            CONSOLE_COLOR_GREEN(printf("�ɹ�"));
        }

        printf("\n\nɾ����ݷ�ʽ......");
        char szDesktop[MAX_PATH];
        char szDesktop2[MAX_PATH];
        if (!SHGetSpecialFolderPathA(0, szDesktop, CSIDL_DESKTOPDIRECTORY, 0)) {
            printf("ʧ��:�޷���ȡ����·��");
            myexit();
        }
        strcpy_s(szDesktop2, szDesktop);
        strcat_s(szDesktop, "\\edge.lnk");
        strcat_s(szDesktop2, "\\Microsoft Edge.lnk");
        DeleteFileA(szDesktop);
        DeleteFileA(szDesktop2);
        DeleteFileA("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Microsoft Edge.lnk");
        DeleteFileA("C:\\Users\\ADMIN\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\Microsoft Edge.lnk");
        CONSOLE_COLOR_GREEN(printf("�ɹ�"));

        printf("\n\nɾ���û�ע���......");
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Microsoft\\Edge");
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Microsoft\\EdgeUpdate");
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Microsoft\\EdgeWebView");
        RegDeleteTreeA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\microsoft-edge");
        RegDeleteTreeA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\microsoft-edge-holographic");
        CONSOLE_COLOR_GREEN(printf("�ɹ�"));

        CONSOLE_COLOR_YELLOW(printf("\n\n���򼴽���SYSTEM����������У�δ������������Ȩ��\n"));
        system("pause");
        Run_as_System(argv[0]);
        exit(1);
    }
    else {
        printf("\n\nɾ��ϵͳע���......");
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge");
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge Update");
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft EdgeWebView");

        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Edge");
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate");

        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\MicrosoftEdge");
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Edge");

        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Clients\\StartMenuInternet\\Microsoft Edge");

        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\microsoft-edge");

        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\edgeupdate");
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\edgeupdatem");
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\MicrosoftEdgeElevationService");
        CONSOLE_COLOR_GREEN(printf("�ɹ�"));
    }

    CONSOLE_COLOR_GREEN(printf("\n\n��ɣ����ֶ�ɾ������ע���ͼƻ����� (��ɾҲ����ν)"));
    getchar();
}
