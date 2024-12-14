# Rhabdomancer.py - A Ghidra vulnerability research assistant
# Rhabdomancer locates all calls to potentially insecure functions (the candidate points), which
# have been classified in 3 different tiers of decreasing potential for exploitation, from 0 to 2.
#
# Based on Rhabdomancer.java by Marco Ivaldi <raptor@0xdeadbeef.info>
# Copyright (c) 2021 Marco Ivaldi (original Java version)
# Copyright (c) 2024 hackinaggie (Python conversion and modifications)
# This software is licensed under the MIT License.
# See https://github.com/0xdea/ghidra-scripts/blob/main/LICENSE
#
# @author: hackinaggie
# @category: GSS

from collections import OrderedDict
# Ghidra Stuff
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CodeUnit

# UI Stuff
from java.awt import Dimension, FlowLayout
from java.awt.event import ItemEvent
from javax.swing import JPanel, JCheckBox, JScrollPane, JOptionPane, BoxLayout, BorderFactory, JLabel, JComboBox

def main():
    ui = RhabdomancerUI()
    comments, bookmarks, verbose, funcs = ui.dump_options()
    if None in [comments, bookmarks, verbose, funcs]:
        print('[-] Some options not set. Exiting.')
        return

    rm = Rhabdomancer(comments, bookmarks, verbose, funcs)
    RhabdomancerUI.print_banner()
    rm.run()
    if verbose:
        print("\n")
        if comments:
            print('[*] You can filter for this script\'s comments with the prepended tag "RM-" in the Comments window.')
        if bookmarks:
            print('[*] You have to allow "Rhabdomancer" Types in the Bookmarks Window filter to see this script\'s bookmarks.')
        print('[*] Tip: Use Ghidra\'s Undo feature to remove All Comments/Bookmarks performed in this run')

class Rhabdomancer(GhidraScript):
    def __init__(self, comments, bookmarks, verbose, funcs):
        self.comments = comments
        self.bookmarks = bookmarks
        self.verbose = verbose
        self.funcs = funcs
        self.current_program = getCurrentProgram()
        self.bm_manager = self.current_program.getBookmarkManager()
        self.rf_manager = self.current_program.getReferenceManager()

    def run(self):
        actions = 'Listing'
        if self.comments:
            actions += ', commenting'
        if self.bookmarks:
            actions += ', bookmarking'
        print("[*] {} calls to potentially insecure functions...\n".format(actions))

        # Enumerate candidate points at each tier
        for foi in self.funcs:
            if self.verbose:
                print('[*] Looking at FOI: {}'.format(foi))
            func_name = foi.split('-',1)[1]
            func_obj = self.get_target_function(func_name)
            if func_obj:
                self.process_calls(func_obj, foi)

    def get_target_function(self, name):
        """
        Retrieve the function object for the given name.

        Parameters:
        name (str): The name of the function to retrieve.

        Returns:
        ghidra.program.model.symbol.Function: The function object, or None if it cannot be found.
        """
        try:
            symbol = self.current_program.symbolTable.getExternalSymbol(name)
            if not symbol:
                return getFunction(name)
            thunk_address = symbol.object.functionThunkAddresses[0]
            for ref in getReferencesTo(thunk_address):
                if ref.getReferenceType().isCall():
                    return getFunctionContaining(ref.getFromAddress())
        except Exception as e:
            print("[-] Error obtaining function object for {} : '{}'".format(name, str(e)))
        return None

    def process_calls(self, dst_func, tag):
        """Process cross-references to a function and list calls.
        
        Print to console, and potentially bookmark/comment based on user selections.
        """
        callee_name = dst_func.getName()
        callee_addr = dst_func.getEntryPoint()
        listing = self.current_program.getListing()
        uid = "RM-"         # id previous comments
        # NOT limited to 4096 records
        refs = self.rf_manager.getReferencesTo(callee_addr)

        print("[+] {} is called from:".format(callee_name))
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                src_func = listing.getFunctionContaining(call_addr)
                if src_func is not None and not src_func.isThunk():
                    # Print call address and caller function
                    src_name = src_func.getName()
                    print("\t0x{} in {}".format(call_addr, src_name))

                    # Add pre comment tag at candidate point location
                    if self.comments:
                        code_unit = listing.getCodeUnitAt(call_addr)
                        cur_comment = code_unit.getComment(CodeUnit.PRE_COMMENT)
                        new_comment = uid+tag
                        if cur_comment is None:
                            code_unit.setComment(CodeUnit.PRE_COMMENT, new_comment)
                        else:
                            if not cur_comment.startswith(uid):
                                code_unit.setComment(CodeUnit.PRE_COMMENT, "{}\n{}".format(new_comment, cur_comment))
                    
                    # Add a bookmark, unless one already exists
                    if self.bookmarks and len(self.bm_manager.getBookmarks(call_addr)) == 0:
                        tier, f_name = tag.split('-',1)
                        # NOTE: Will have to Filter for 'Rhabdomancer' Types in Bookmarks to see
                        self.bm_manager.setBookmark(call_addr, "Rhabdomancer", tier, "{} is called".format(f_name))

class RhabdomancerUI:
    def __init__(self):
        self.comments = self.bookmarks = self.verbose = self.fois = None
        if self.get_global_options():
            self.get_function_options()

    def get_global_options(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        comments_checkbox = JCheckBox("Make Comments", True)
        bookmarks_checkbox = JCheckBox("Make Bookmarks", True)
        verbose_checkbox = JCheckBox("Verbose Console Output", False)
        panel.add(comments_checkbox)
        panel.add(bookmarks_checkbox)
        panel.add(verbose_checkbox)

        # OS input using ComboBox
        os_panel = JPanel()
        os_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        os_panel.add(JLabel("OS Function calls to look for:"))
        os_input = JComboBox(['Linux', 'Windows'])
        os_panel.add(os_input)
        panel.add(os_panel)
        
        result = JOptionPane.showConfirmDialog(None, panel, "Global Options", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            self.comments = comments_checkbox.isSelected()
            self.bookmarks = bookmarks_checkbox.isSelected()
            self.verbose = verbose_checkbox.isSelected()
            self.os = os_input.getSelectedItem()
            return True
        else:
            self.comments = None
            self.bookmarks = None
            self.verbose = None
            self.os = None
            return False

    def get_function_options(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
         
        # Create OS-Specific functions panel
        if self.os == 'Linux':
            os_panel = RhabdomancerUI.create_os_panel(self.LINUX_FOI)
        elif self.os == 'Windows':
            os_panel = RhabdomancerUI.create_os_panel(self.WINDOWS_FOI)
        else:
            raise Exception('Invalid OS Selection')
        
        # Add scroll pane
        scroll_pane = JScrollPane(os_panel)
        scroll_pane.setPreferredSize(Dimension(800, 600))
        panel.add(scroll_pane)
        
        result = JOptionPane.showConfirmDialog(None, panel, 
            "Select Functions", JOptionPane.OK_CANCEL_OPTION)  
        if result == JOptionPane.OK_OPTION:
            self.fois = self.get_selected_items(os_panel)
        else:
            self.fois = None

    def dump_options(self):
        return self.comments, self.bookmarks, self.verbose, self.fois
    
    @staticmethod
    def create_os_panel(foi_dict):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        
        for tier_name, categories in foi_dict.items():
            # Create tier panel with border
            tierPanel = JPanel()
            tierPanel.setLayout(BoxLayout(tierPanel, BoxLayout.Y_AXIS))
            tierPanel.setBorder(BorderFactory.createTitledBorder(tier_name))
            
            # Add select all checkbox for tier
            tierCheckbox = JCheckBox("Select All " + tier_name)
            tierPanel.add(tierCheckbox)
            categoryCheckboxes = []
            functionCheckboxes = []
            
            for category_name, functions in categories.items():
                # Create category panel
                categoryPanel = JPanel()
                categoryPanel.setLayout(BoxLayout(categoryPanel, BoxLayout.Y_AXIS))
                categoryPanel.setBorder(BorderFactory.createTitledBorder(category_name))
                
                # Add select all checkbox for category
                categoryCheckbox = JCheckBox("Select All " + category_name)
                categoryPanel.add(categoryCheckbox)
                categoryCheckboxes.append((categoryCheckbox, []))
                
                # Add function checkboxes
                for func in functions:
                    funcCheckbox = JCheckBox(func)
                    categoryPanel.add(funcCheckbox)
                    functionCheckboxes.append(funcCheckbox)
                    categoryCheckboxes[-1][1].append(funcCheckbox)
                
                # Add category to tier panel
                tierPanel.add(categoryPanel)
            
            # Add listeners for tier checkbox
            tierCheckbox.addItemListener(lambda e, boxes=functionCheckboxes: 
                RhabdomancerUI.toggle_checkboxes(boxes, e.getStateChange() == ItemEvent.SELECTED))
                
            # Add listeners for category checkboxes
            for categoryCheckbox, funcBoxes in categoryCheckboxes:
                categoryCheckbox.addItemListener(lambda e, boxes=funcBoxes: 
                    RhabdomancerUI.toggle_checkboxes(boxes, e.getStateChange() == ItemEvent.SELECTED))
            
            panel.add(tierPanel)
        return panel

    @staticmethod
    def toggle_checkboxes(checkboxes, state):
        for checkbox in checkboxes:
            checkbox.setSelected(state)

    def get_selected_items(self, panel):
        # Process Linux selections
        selected = set()
        for outer_panel in panel.getComponents():
            for tier_component in outer_panel.getComponents():
                for category_component in tier_component.getComponents(): # e.g. LT2 - Logging - 
                    if isinstance(category_component, JCheckBox) and category_component.isSelected():
                        txt = category_component.getText()
                        if 'Select All' not in txt:
                            selected.add(txt)
        
        out = []
        if self.os == 'Linux':
            fois = self.LINUX_FOI
        else:
            fois = self.WINDOWS_FOI
        for func_name in selected:
            found_tier = False
            for tier_name, categories in fois.items():
                if found_tier:
                    break
                for _, functions in categories.items():
                    if func_name in functions:
                        out.append("{}-{}".format(tier_name, func_name))
                        found_tier = True
                        break
            if not found_tier:
                print('[-] Didn\'t find tier for {}'.format(func_name))
        return out
    
    @staticmethod
    def print_banner():
        msg = "Rhabdomancer - A Ghidra vulnerability research assistant\n" \
        "Copyright (c) 2021 Marco Ivaldi <raptor@0xdeadbeef.info>(original Java version)\n" \
        'Copyright (c) 2024 hackinaggie (Python conversion and modifications)\n'
        wrap = '*' * 79 + '\n'
        print(wrap + msg + wrap)

    # Linux-focused vulnerability research dictionaries
    LINUX_FOI = OrderedDict({
        # Tier 0: direct code execution, privilege escalation, and classic buffer overflow vectors
        'LT0': OrderedDict({
            'Execution': [
                "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve", "dlopen", "dlsym", "fork", "clone"
                ],
            'Strings': [
                "strcpy", "strcat", "sprintf", "vsprintf", "gets", "getchar"
                ],
            'CLI' : [
                "getopt", "getopt_long", "read", "scanf", "fscanf", "sscanf"
                ],
            'Network': [
                "recv", "recvfrom", "recvmsg", "accept"
                ],
            'File': [
                "readlink", "symlink", "link", "mktemp"
                ],
            'Privileges': [
                "setuid", "seteuid", "setgid", "setegid", "setreuid", "setregid"
                ],
            'SharedMemory': [
                "shmat", "shmget", "mmap"
                ],
            'ShellExpansion': [
                "wordexp", "glob"
                ]
        }),
        # Tier 1: memory operations, network functions, and file operations that could be misused
        'LT1' : OrderedDict({
            'String': [
                "strncpy", "strncat", "strtok", "strlcpy", "strlcat", "strlen"
                ],
            'Memory': [
                "memcpy", "memmove", "memset", "bcopy"
                ],    
            'File': [
                "open", "fopen", "write", "truncate", "mkdir", "chmod", "chown", "unlink", "rmdir", "rename", "tempnam", "dup", "dup2", "fcntl"
                ],
            'Network': [
                "bind", "connect", "listen", "send", "sendto", "sendmsg", "socket"
                ],
            'Process': [
                "kill", "ptrace", "nice","signal", "sigaction", "sigsuspend"
                ],
            'Terminal': [
                "tcgetattr", "tcsetattr", "ttyname"
                ]
        }),
        # Tier 2: memory management, environment variables, and general-purpose functions that might be part of an exploit chain
        'LT2' : OrderedDict({
            'MemoryAllocation': [
                "malloc", "calloc", "realloc", "free", "alloca"
                ],
            'Env': [
                "getenv", "setenv", "putenv", "clearenv"
                ],
            'File': [
                "mkstemp", "mkdtemp", "tmpfile", "realpath", "dirname", "getcwd", "chdir", "fchdir"
                ],
            'FmtStr': [
                "printf", "fprintf", "snprintf", "vprintf", "vfprintf", "vsnprintf"
                ],
            'Logging': [
                "syslog", "err", "errx", "warn", "warnx"
                ],
            'Time': [
                "time", "localtime", "mktime", "strftime"
                ],
            'Random': [
                "rand", "random", "rand_r", "srand"
                ],
            'ProcessInfo': [
                "getpid", "getppid", "getpgrp", "getsid"
                ],
            'UserInfo': [
                "getuid", "getgid", "geteuid", "getegid"
                ]
        })
    })

    # Windows-focused vulnerability research dictionaries
    WINDOWS_FOI = OrderedDict({
        # Tier 0: code execution, registry operations, and service manipulation
        'WT0': OrderedDict({
            'Execution': [
                "WinExec", "CreateProcess", "CreateProcessAsUser", "ShellExecute", "ShellExecuteEx", "system", "_popen"
                ], 
            'String': [
                "strcpy", "_strcpy", "wcscpy", "_wcscpy", "StrCpy", "lstrcpy", "strcat", "_strcat", "wcscat", "_wcscat", "StrCat", "lstrcat", "sprintf", "wsprintf", "lstrcpyA", "lstrcpyW"
                ],
            'Registry': [
                "RegCreateKey", "RegSetValue", "RegSetValueEx"
                ],
            'File': [
                "DeleteFile", "RemoveDirectory", "MoveFile", "CopyFile"
                ],
            'Memory': [
                "WriteProcessMemory", "VirtualProtect", "VirtualAlloc"
                ],
            'Services': [
                "CreateService", "StartService", "ChangeServiceConfig"
                ],
            'DLL': [
                "LoadLibrary", "LoadLibraryEx", "GetProcAddress"
                ]
        }),
        # Tier 1: memory management, file operations, and network functions
        'WT1': OrderedDict({
            'String': [
                "strncpy", "_strncpy", "wcsncpy", "_wcsncpy", "StrCpyN", "strncat", "_strncat", "wcsncat", "_wcsncat", "StrCatN"
                ],
            'Memory': [
                "memcpy", "RtlCopyMemory", "CopyMemory", "MoveMemory", "ReadProcessMemory", "HeapAlloc", "LocalAlloc", "GlobalAlloc"
                ],
            'File': [
                "CreateFile", "WriteFile", "ReadFile", "SetFilePointer", "FindFirstFile", "FindNextFile"
                ], 
            'Registry': [
                "RegOpenKey", "RegQueryValue", "RegEnumKey"
                ],
            'Network': [
                "socket", "connect", "send", "recv", "WSASocket", "WSAConnect", "WSASend", "WSARecv"
                ],
            'Process/Thread': [
                "CreateThread", "CreateRemoteThread", "OpenProcess", "TerminateProcess", "ExitProcess"
                ]
        }), 
        # Tier 2: COM objects, cryptographic functions, and general Windows API calls
        'WT2' : OrderedDict({
            'Memory allocation': [
                "malloc", "calloc", "realloc", "free", "_malloc", "CoTaskMemAlloc", "CoTaskMemRealloc"
                ],
            'Environment': [
                "GetEnvironmentVariable", "SetEnvironmentVariable", "ExpandEnvironmentStrings"
                ],
            'File operations': [
                "GetTempPath", "GetTempFileName", "GetFullPathName", "GetCurrentDirectory", "SetCurrentDirectory"
                ],
            'Format strings': [
                "printf", "fprintf", "sprintf", "vprintf", "_printf", "wprintf", "fwprintf", "swprintf"
                ],
            'Security': [
                "CryptGenRandom", "CryptCreateHash", "CryptEncrypt", "CryptDecrypt", "CertOpenStore", "CertCreateSelfSignCertificate"
                ],
            'Error handling': [
                "GetLastError", "SetLastError", "FormatMessage"
                ],
            'COM': [
                "CoCreateInstance", "CoInitialize", "CoInitializeSecurity"
                ],
            'Misc': [
                "GetSystemTime", "SetSystemTime", "rand", "srand"
                ]
        })
    })

if __name__ == '__main__':
    main()