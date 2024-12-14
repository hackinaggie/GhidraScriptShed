# SourceSinkSleuth looks for potential user-input sources in code paths to a selected function
# Look for NOTEs in code to see where you can easily modify the script
# @author hackinaggie
# @category GSS

from java.awt import Dimension
from java.awt.event import ItemEvent
from javax.swing import JPanel, JCheckBox, JScrollPane, JOptionPane, BoxLayout, BorderFactory, JLabel, JTextField
from ghidra.util.task import ConsoleTaskMonitor

# Ghidra Stuff
CURRENT_PROGRAM = getCurrentProgram()           # Gets the current program
TASK_MONITOR = ConsoleTaskMonitor()             # Handles monitor output to console

# SourceSinkSleuth stuff
VERBOSE = False
TGT_OS = 'linux'
TGT_FUNC_NAME = None
DEPTH_LIMIT = 6             # Set default recursion depth limit (Kinda arbitrary)
DEPTH_CURRENT = 0           # keep track of current nesting depth
VISITED_FUNCS_SET = set()   # keep track of visited funcs for efficiency
VISITED_FUNCS_LIST = []     # Allows printing of cool ordered path in Ghidra's Jython 2.7 without ordered sets
SEARCH_FWD = False          # If user sets to true (in dialog box), will search forwards instead of backwards.

# NOTE: User optional funcs, edit if you'd like to search for/from them
USER_FUNCS = {
    'User Functions':[
        # 'super_cool_func', 'interesting_one', etc
    ]
}

def main():
    global DEPTH_LIMIT, VERBOSE, SEARCH_FWD, TGT_FUNC_NAME, FOIS
    ui = SourceSinkSleuthUI()
    tgt_func, chosen_FOIs, options_input = ui.dump_options()
    if tgt_func is None:
        print("[-] No valid target function provided. Exiting.")
        exit()
    elif chosen_FOIs is None:
        print("[-] No input categories selected. Exiting.")
        exit()
    elif options_input is None:
        print("[-] No options provided. Exiting.")
        exit()

    # Apply Options
    try:
        DEPTH_LIMIT = int(options_input['depth'])
        if DEPTH_LIMIT < 1:
            print("Depth limit must be at least 1. Using default value of {}".format(DEPTH_LIMIT))
            DEPTH_LIMIT = 5
    except ValueError:
        print("Invalid depth limit input. Using default value of {}".format(DEPTH_LIMIT))
    VERBOSE = options_input['verbose']
    SEARCH_FWD = options_input['search_fwd']
    TGT_FUNC_NAME = tgt_func.getName()
    # Lazy accounting for unicode/ascii versions of foi
    FOIS = chosen_FOIs
    if TGT_OS == 'windows':
        new_fois = []
        for foi in FOIS:
            new_fois.append([foi+'W', foi+'A'])
        FOIS.extend(new_fois)

    # Continue with analysis after inputs
    SourceSinkSleuthUI.print_banner()
    analyze_calls(tgt_func)

def pp_code_path(foi):
    if VERBOSE:
        indent = "   {} ".format('-'*DEPTH_CURRENT)
    else:
        indent = '\t'

    if SEARCH_FWD:
        path = TGT_FUNC_NAME + ' --> ' + ' --> '.join(VISITED_FUNCS_LIST)
        path += ' --> {}'.format(foi)
        msg = "[!] Path to FOI ({}) found at depth {}:\n{}{}".format(foi, DEPTH_CURRENT+2, indent, path)
    else:
        path = TGT_FUNC_NAME + ' <-- ' + ' <-- '.join(VISITED_FUNCS_LIST)
        msg = "[!] Path from FOI ({}) found at depth {}:\n{}{}".format(foi, DEPTH_CURRENT+2, indent, path)
    print(msg)

def analyze_calls(target_input):
    global VISITED_FUNCS_LIST, VISITED_FUNCS_SET, DEPTH_CURRENT

    if SEARCH_FWD:
        starting_points = get_referenced_funcs(target_input)
    else:
        starting_points = get_referencing_funcs(target_input)

    for calling_func in starting_points:
        if not calling_func:
            continue
        try:
            find_FOI_recursively(calling_func)
        finally:
            # Reset after analyzing every path
            VISITED_FUNCS_SET.clear()
            del VISITED_FUNCS_LIST      # Ensure the mem is freed
            VISITED_FUNCS_LIST = []
            DEPTH_CURRENT = 0

# Check if the function is an FOI
def func_is_FOI(function):
    if function and FOIS:
        f_name = function.getName()   

        for foi in FOIS:
            if foi == f_name:
                pp_code_path(foi)
                return True
    return False

# Get all functions that have references to a function, including indirect calls
def get_referencing_funcs(func):
    return func.getCallingFunctions(TASK_MONITOR)

# Get all functions that the `func` references (calls)
def get_referenced_funcs(func):
    # Get all calls in current function
    return func.getCalledFunctions(TASK_MONITOR)

# Trace arguments and intermediate data flow between functions
def find_FOI_recursively(caller_func):
    global DEPTH_CURRENT, VISITED_FUNCS_SET, VISITED_FUNCS_LIST
    caller_f_name = caller_func.getName()
    
    # Early exit if already visited to prevent infinite recursion
    if caller_f_name in VISITED_FUNCS_SET:
        return False
    # Add the current function to visited sets
    VISITED_FUNCS_SET.add(caller_f_name)      
    VISITED_FUNCS_LIST.append(caller_f_name)  
    
    if VERBOSE:
        if DEPTH_CURRENT == 0:
            print("\n[+] Analyzing Referrer function: {}".format(caller_f_name))
        else:
            if SEARCH_FWD:
                print("   {} Analyzing callee: {}".format('-'*DEPTH_CURRENT, caller_f_name))
            else:
                print("   {} Analyzing caller: {}".format('-'*DEPTH_CURRENT, caller_f_name))

    # Track FOIs found in this recursion level
    foi_found = func_is_FOI(caller_func)

    try:
        if SEARCH_FWD:
            called_funcs = caller_func.getCalledFunctions(TASK_MONITOR)
            for called_func in called_funcs:
                # Check if the called function is an FOI
                if func_is_FOI(called_func):
                    foi_found = True
                    continue  # Continue checking other functions

                # Recurse into called functions if not a bad recursion target
                if called_func and not is_bad_recurse_tgt(called_func):
                    if DEPTH_CURRENT < DEPTH_LIMIT:
                        DEPTH_CURRENT += 1
                        try:
                            # Recursively search, accumulating FOI findings
                            recursive_foi = find_FOI_recursively(called_func)
                            foi_found |= recursive_foi
                        finally:
                            DEPTH_CURRENT -= 1
                    else:
                        print("Reached recursion limit; unable to recurse in to called function: {}".format(called_func.getName()))
        else:
            # Backward search (finding callers)
            if DEPTH_CURRENT < DEPTH_LIMIT:
                caller_funcs = get_referencing_funcs(caller_func)
                for calling_func in caller_funcs:
                    if calling_func and not is_bad_recurse_tgt(calling_func):
                        DEPTH_CURRENT += 1
                        try:
                            # Recursively search, accumulating FOI findings
                            recursive_foi = find_FOI_recursively(calling_func)
                            foi_found |= recursive_foi
                        finally:
                            DEPTH_CURRENT -= 1
            else:
                print("   {} Reached recursion limit. Unable to recurse into functions called by {}".format(
                    '-'*DEPTH_CURRENT, caller_f_name))
    finally:
        # Remove the current function from visited sets after exploration
        # This allows retracing different paths
        VISITED_FUNCS_SET.discard(caller_f_name)
        if VISITED_FUNCS_LIST and VISITED_FUNCS_LIST[-1] == caller_f_name:
            VISITED_FUNCS_LIST.pop()

    return foi_found

def is_bad_recurse_tgt(func):
    name = func.getName()
    if not (func.isThunk() or func.isExternal() or name == TGT_FUNC_NAME):
        # avoid infinite loops caused by cyclic function calls
        return name in VISITED_FUNCS_SET
    return True

class SourceSinkSleuthUI:
    def __init__(self):
        self.tgt_func = self.fois = self.options = None
        # set options, os, tgt_func
        if self.choose_options() and self.tgt_func:
            # set fois
            self.choose_functions()
    
    @staticmethod
    def get_os_type():
        """Determine if binary is Windows or Linux/Unix based"""
        # Check for common Windows DLL imports
        windows_dlls = ['kernel32.dll', 'user32.dll', 'ntdll.dll', 'advapi32.dll']
        for dll in windows_dlls:
            if any(lib.lower() == dll for lib in CURRENT_PROGRAM.getExternalManager().getExternalLibraryNames()):
                return 'windows'
        # Otherwise assume Unix/Linux
        return 'linux'

    def choose_options(self):
        global TGT_OS
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        panel.add(JLabel("Choose a target function:"))
        tgt_func = JTextField()
        panel.add(tgt_func)
        panel.add(JLabel("Enter recursion depth limit (default is {}):".format(DEPTH_LIMIT)))
        depth_input = JTextField(str(DEPTH_LIMIT), 5)
        panel.add(depth_input)
        
        verbose_checkbox = JCheckBox("VERBOSE", VERBOSE)
        search_fwd_checkbox = JCheckBox("SEARCH FORWARD", SEARCH_FWD)
        panel.add(search_fwd_checkbox)
        panel.add(verbose_checkbox)
        
        result = JOptionPane.showConfirmDialog(None, panel, "Global Options", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            self.tgt_func = SourceSinkSleuthUI.get_target_function(tgt_func.getText())
            TGT_OS = SourceSinkSleuthUI.get_os_type()
            self.options = {
                'search_fwd' : search_fwd_checkbox.isSelected(),
                'verbose' : verbose_checkbox.isSelected(),
                'depth' : depth_input.getText(),
            }
            return True
        else:
            return False

    def choose_functions(self):         
        # Get all available funcs
        if TGT_OS == 'linux':
            all_funcs = SourceSinkSleuthUI.LINUX_FOI
        else:
            all_funcs = SourceSinkSleuthUI.WINDOWS_FOI
        if USER_FUNCS['User Functions']:
            all_funcs.update(USER_FUNCS)

        # Add scroll pane
        os_panel = SourceSinkSleuthUI.create_os_panel(all_funcs)
        scroll_pane = JScrollPane(os_panel)
        # NOTE: Modify if don't want a big panel
        scroll_pane.setPreferredSize(Dimension(300, 500))
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.add(scroll_pane)
        
        result = JOptionPane.showConfirmDialog(None, panel, 
            "Select Functions", JOptionPane.OK_CANCEL_OPTION)  
        if result == JOptionPane.OK_OPTION:
            self.fois = self.get_selected_items(os_panel, all_funcs)
        else:
            self.fois = None

    def dump_options(self):
        return self.tgt_func, self.fois, self.options
    
    @staticmethod
    def create_os_panel(foi_dict):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        categoryCheckboxes = []
        functionCheckboxes = []
        
        for category_name, functions in foi_dict.items():
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
            panel.add(categoryPanel)

        # Add listeners for category checkboxes
        for categoryCheckbox, funcBoxes in categoryCheckboxes:
            categoryCheckbox.addItemListener(lambda e, boxes=funcBoxes: 
                SourceSinkSleuthUI.toggle_checkboxes(boxes, e.getStateChange() == ItemEvent.SELECTED))
        return panel

    @staticmethod
    def toggle_checkboxes(checkboxes, state):
        for checkbox in checkboxes:
            checkbox.setSelected(state)

    def get_selected_items(self, panel, all_funcs):
        # Process Linux selections
        selected = set()
        for outer_panel in panel.getComponents():
            for category_component in outer_panel.getComponents():
                if isinstance(category_component, JCheckBox) and category_component.isSelected():
                    txt = category_component.getText()
                    if 'Select All' not in txt:
                        selected.add(txt)
        out = []
        for func_name in selected:
            for _, functions in all_funcs.items():
                if func_name in functions:
                    out.append(func_name)
                    break
        return out
    
    @staticmethod
    def get_target_function(target_input):
        # Handle internal methods
        if target_input.startswith("0x"):
            target_addr = toAddr(target_input)
            target_func = getFunctionAt(target_addr)
        else:
            target_func = getFunction(target_input)
        if target_func:
            return target_func
        
        # Handle imported APIs
        for ext_func in CURRENT_PROGRAM.getFunctionManager().getExternalFunctions():
            if ext_func.getName() == target_input:
                return getFunctionAt(ext_func.getFunctionThunkAddresses()[0])
        print("[-] Function not found: {}".format(target_input))
        return target_func
    
    @staticmethod
    def print_banner():
        msg = """
 _____                                  _____  _         _     _____  _               _    _     
/  ___|                                /  ___|(_)       | |   /  ___|| |             | |  | |    
\ `--.   ___   _   _  _ __   ___   ___ \ `--.  _  _ __  | | __\ `--. | |  ___  _   _ | |_ | |__  
 `--. \ / _ \ | | | || '__| / __| / _ \ `--. \| || '_ \ | |/ / `--. \| | / _ \| | | || __|| '_ \ 
/\__/ /| (_) || |_| || |   | (__ |  __//\__/ /| || | | ||   < /\__/ /| ||  __/| |_| || |_ | | | |
\____/  \___/  \__,_||_|    \___| \___|\____/ |_||_| |_||_|\_\\\\____/ |_| \___| \__,_| \__||_| |_|

Version 1.0
@hackinaggie
"""
        print(msg)

    # Categories of Functions of Interest for user to choose from
    LINUX_FOI = {
        'Network': [
            "recv", "recvfrom", "send", "sendto", "socket", "accept", "bind", "listen", "gethostbyname"
            ],
        'Strings': [
            "scanf", "gets", "fgets", "sscanf", "strcpy", "strncpy", "strcat", "strncat"
            ],
        'Files': [
            "fgets", "fread", "fscanf", "read", "write", "open", "close", "unlink", "chmod", "chown"
            ],
        'Memory Allocation': [
            "malloc", "calloc", "realloc", "free"
            ],
        'Misc': [
            "getopt", "argv", "getenv", "setenv", "putenv"
            ],
        'Code Execution': [
            "system", "popen", "exec", "execl", "execlp", "execv", "execvp", "fork", "ptrace"
            ],
    }

    WINDOWS_FOI = {
        # NOTE: Unicode/Ascii versions are taken care of in main()
        'Code Execution': [
            'CreateProcess', 'OpenProcess', 'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread', 'VirtualProtect'
            ],
        'Network': [
            'socket', 'WSAStartup', 'connect', 'WSAConnect', 'bind', 'listen', 'accept', 'send', 'WSASend', 'recv', 'WSARecv'
            ],
        'Strings': [
            'strcmp', 'lstrcmp', 'strdup'
            ],
        'Files': [
            'CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'CopyFile', 'MoveFile', 'FindFirstFile'
            ],
        'Registry': [
            'RegOpenKey', 'RegQueryValue', 'RegSetValue', 'RegDeleteValue'
            ],
        'Memory Allocation': [
            'HeapAlloc', 'VirtualAlloc', 'HeapFree', 'VirtualFree', 'RtlMoveMemory'
            ]
    }

if __name__ == '__main__':
    main()
