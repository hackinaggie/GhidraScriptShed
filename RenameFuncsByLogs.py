#Rename functions based on logging function called
#@author hackinaggie
#@category GSS

# Based on https://blog.convisoappsec.com/en/automatically-renaming-functions-with-ghidra/
# Better configuration, more efficient, better error handling, handle refs > 4096

import ghidra.program.model.pcode.PcodeOp as PcodeOp
import ghidra.program.model.symbol.RefType as RefType
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JComboBox, JOptionPane, BoxLayout, Box
from java.awt import FlowLayout

CURRENT_PROGRAM = getCurrentProgram()           # Gets the current program
TASK_MONITOR = ConsoleTaskMonitor()             # Handles monitor output to console
DECOMP_IFC = DecompInterface()                  # Interface to a single decompile process
DECOMP_IFC.setOptions(DecompileOptions())
DECOMP_IFC.openProgram(CURRENT_PROGRAM)

AGGRESSIVE = True
VERBOSE = False
CURRENT_NAMES = []

def get_target_function(name):
    """
    Retrieve the function object for the given name.

    Parameters:
    name (str): The name of the function to retrieve.

    Returns:
    ghidra.program.model.symbol.Function: The function object, or None if it cannot be found.
    """
    try:
        # Handle internal methods
        if name.startswith("0x"):
            target_addr = toAddr(name)
            target_func = getFunctionAt(target_addr)
        else:
            symbol = CURRENT_PROGRAM.symbolTable.getExternalSymbol(name)
            if not symbol:
                return getFunction(name)
            thunk_address = symbol.object.functionThunkAddresses[0]
            for ref in getReferencesTo(thunk_address):
                if ref.getReferenceType() == RefType.COMPUTED_CALL:
                    return getFunctionContaining(ref.getFromAddress())
    except Exception as e:
        print("[-] Error obtaining function object for {} : '{}'".format(name, str(e)))
    return None


def get_callers(function):
    """
    Retrieve the list of functions that call the given function. Exclude non-default func-names

    Parameters:
    function (ghidra.program.model.symbol.Function): The function to find callers for.

    Returns:
    list[ghidra.program.model.symbol.Function]: The list of caller functions, or None if an error occurs.
    """
    try:
        address = function.getEntryPoint()
        callers = set()
        # Return ALL references, even if more than 4096
        refs = CURRENT_PROGRAM.referenceManager.getReferencesTo(address)
        for ref in refs:
            if ref.getReferenceType().isCall():
                caller = getFunctionContaining(ref.getFromAddress())
                if caller is None: 
                    continue
                callers.add(caller)
        return list(callers)
    except Exception as e:
        print("[-] Error enumerating Callers to {} : '{}'".format(function.getName(), str(e)))
    return None

def resolve_varnode(varnode):
    """
    Resolve the varnode to a string of its underlying value.

    Parameters:
    varnode (ghidra.program.model.pcode.Varnode): The varnode to resolve

    Returns:
    str: The resolved argument values. OR None if failed
    """
    if varnode.isConstant():    # if a gConstat Number, return that
        resolved = varnode.getOffset()
    elif varnode.isUnique():    # if a Temp variable, try to get the data value at that addr
        def_pcodeOp = varnode.getDef()
        constant_offset = def_pcodeOp.getInput(0).getOffset()
        constant_addr = toAddr(constant_offset)
        data = getDataContaining(constant_addr)
        # Return the defined data (strings) at the specified address or null if no data exists.
        if data:
            resolved = data.getValue()
        else:
            resolved = data
    else:
        # Return the name of the decompiled variable this varnode represents
        resolved = varnode.getHigh().getName()
    return resolved

def get_called_function_from_pcode(pcode_op):
    """
    Retrieve the function object for the function called by a given p-code operation.

    Parameters:
    pcode_op (ghidra.program.model.pcode.PcodeOp): The p-code operation to analyze.

    Returns:
    String: The called function's address, or None if it cannot be determined.
    """
    if pcode_op.getOpcode() == PcodeOp.CALLIND:
        func_pointer = pcode_op.getInputs()[0]
        if func_pointer and func_pointer.isAddress():
            func_addr = func_pointer.getAddress()
            return func_addr
    elif pcode_op.getOpcode() == PcodeOp.CALL:
        called_addr = pcode_op.getInput(0).getAddress()
        return called_addr
    return None

def get_calls_from_all_callers(callers, callee, argnum):
    """
    Retrieve the call information for a given function from all of its callers.

    Parameters:
    callers (list[ghidra.program.model.symbol.Function]): The list of caller functions.
    callee (ghidra.program.model.symbol.Function): The callee function.
    argnum (int): The index of the argument containing the function name to be renamed.

    Returns:
    dict: A dictionary mapping caller function names to their call information.
    """
    callers_info = {}
    for caller in callers:
        try:
            caller_name = caller.getName()
            if not caller_name.startswith('FUN_'):
                print('[*] Skipping {} caller, only renaming those with default names (FUN_*)'.format(
                    caller_name
                ))
                continue
            caller_info = {
                caller_name : get_calls_from_caller(caller, callee, argnum)
            }
            callers_info.update(caller_info)
        except Exception as e:
            print("[-] Error when getting calls from {} to {} : {}".format(
                caller, callee, e
            ))
    return callers_info

def get_calls_from_caller(caller, callee, argnum):
    """
    Retrieve the call information for a given function from a specific caller.

    Parameters:
    caller (ghidra.program.model.symbol.Function): The caller function.
    callee (ghidra.program.model.symbol.Function): The callee function.
    argnum (int): The index of the argument containing the function name to be renamed.

    Returns:
    dict: A dictionary mapping the argument values to their call counts.
    """
    calls = {}
    res = DECOMP_IFC.decompileFunction(caller, 30, TASK_MONITOR) # 30 Second timeout 
    high_func = res.getHighFunction()
    found_candidate = False
    no_name_calls = []
    if high_func:
        for pcode_op in high_func.getPcodeOps():
            if pcode_op.getOpcode() in [PcodeOp.CALL, PcodeOp.CALLIND]:
                try:
                    called_func = get_called_function_from_pcode(pcode_op)
                except Exception as e:
                    print("[-] Error resolving called function from Pcode at 0x{} : {}".format(
                        get_pcode_addr(pcode_op), e
                    ))
                if not called_func:
                    print('[*] Unable to get function address from Pcode func call at 0x{}'.format(
                        get_pcode_addr(pcode_op)
                    ))

                elif called_func == callee.getEntryPoint():
                    try:
                        rename_arg = resolve_varnode(pcode_op.getInputs()[argnum+1])
                        if rename_arg:
                            found_candidate = True
                            if rename_arg in calls:
                                calls[rename_arg] += calls[rename_arg]
                            else:
                                calls.update({rename_arg: 1})
                        else:
                            no_name_calls.append(get_pcode_addr(pcode_op))
                    except Exception as e:
                        print("[-] Error resolving function call args from Pcode ({}): {}".format(
                            pcode_op.getMnemonic, e
                        ))
    # Error handling
    if not found_candidate:
        msg = '[-] Error getting callee name in calls from {} : Unable to find name candidates.'
        if no_name_calls:
            msg += '\n\tCalls at: ' + str(no_name_calls)
        print(msg.format(caller.getName()))
    return calls

def select_best_name(candidates):
    """
    Select the best name from a set of candidates based on popularity.
    NOTE: Could add more character validity check for the name but best to let user do manual upon Exception raise

    Parameters:
    candidates (dict): A dictionary mapping candidate names to their call counts.

    Returns:
    str: The selected best name.
    bool: Whether the best name already exists in the program (Ghidra allows duplicate func names)
    """
    popular = str(max(candidates, key=candidates.get))
    popular = popular.replace(' ', '_')
    return popular

def get_pcode_addr(pcode_op):
    """
    Get the address of a PcodeOp object.
    
    Parameters:
    pcode_op (ghidra.program.model.pcode.PcodeOp): The PcodeOp to get the address of

    Returns:
    ghidra.program.model.address: The address
    """
    return pcode_op.getSeqnum().getTarget()

def rename_all(callers_candidates):
    """
    Rename all functions based on the provided candidate names.

    Parameters:
    callers_candidates (dict): A dictionary mapping function names to their candidate names.
    """
    global CURRENT_NAMES
    total = len(callers_candidates)
    count = 0
    for current_fname in callers_candidates:
        candidates = callers_candidates[current_fname]
        
        if len(candidates) == 0:
            print("[-] Error ( {} ) has Zero name candidates".format(current_fname))
            continue
        elif len(candidates) > 1:
            if not AGGRESSIVE:
                if VERBOSE:
                    print('[*] Warning ( {} ) has multiple name candidates, manually change (or use Aggressive mode): \n\t{}'.format(
                        current_fname, str(candidates)
                    ))
                continue
            else:
                if VERBOSE:
                    print("[*] Warning ( {} ) has multiple name candidates, choosing most popular: {}".format(
                        current_fname, str(candidates)
                    ))
                new_name = select_best_name(candidates)
                
        else:
            new_name = next(iter(candidates))

        if not new_name:
            print("[-] Error ( {} ) candidate is None".format(current_fname))
            continue
        # append address to prevent duplicate func names
        if new_name in CURRENT_NAMES:
            new_name += '_' + getFunction(current_fname).getEntryPoint().toString()

        try:
            getFunction(current_fname).setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        except Exception as e:
            print("[-] Error ( {} ) unable to rename to {}. Manual editing recommended: {}".format(
                current_fname, new_name, e
            ))
            continue
        print("[+] {} renamed to {}".format(current_fname, new_name))
        count += 1
        CURRENT_NAMES.append(new_name)
    perc = (float(count) / float(total)) * 100.0
    print("From {} functions {} were renamed - {}% ".format(total, count, perc))
    print("\n[*] P.S. You can double click on function names/addresses in Console to jump to them."
          "\n[*] Also, use the Ghidra Undo function to undo all the Script's actions."
    )

def rename_from_logging_function(function_name, arg_num):
    """
    Rename functions based on the calls made to a specific logging function.

    Parameters:
    function_name (str): The name of the logging function to use.
    arg_num (int): The index of the argument containing the function name to be renamed.
    """
    callee = get_target_function(function_name)
    if callee is None:
        print('[-] Unable to find logging function "{}". Exiting...'.format(function_name))
        return
    callers = get_callers(callee)
    if callers is None:
        print('[-] Unable to find functions that reference "{}". Exiting...'.format(function_name))
    callers_info = get_calls_from_all_callers(callers, callee, arg_num)
    if callers_info is None:
        print('[-] Unable to enumerate Call arguments in refs to "{}".'.format(function_name))
    rename_all(callers_info)

def configure_script():
    global AGGRESSIVE, VERBOSE, CURRENT_NAMES
    log_func, func_name_argidx = RenameFuncsByLogsUI.get_target_options()
    if None in [log_func, func_name_argidx]:
        return None, None
    options = RenameFuncsByLogsUI.get_global_options()
    if options is None:
        return None, None
    
    AGGRESSIVE = options['aggressive']
    VERBOSE = options['verbose']
    CURRENT_NAMES = [func.getName() for func in CURRENT_PROGRAM.getFunctionManager().getFunctions(True)]
    return log_func, func_name_argidx


def main():
    log_func, func_name_argidx = configure_script()
    if None not in [log_func, func_name_argidx]:
        RenameFuncsByLogsUI.print_banner(log_func, func_name_argidx)
        rename_from_logging_function(log_func, func_name_argidx)
    else:
        print("[-] Invalid options given. Exiting.")

class RenameFuncsByLogsUI:
    @staticmethod
    def get_target_options():
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        
        # Function name input
        name_panel = JPanel()
        name_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        name_panel.add(JLabel("Enter the logging function name:"))
        log_function_input = JTextField(20)
        name_panel.add(log_function_input)
        panel.add(name_panel)
        
        # Add some vertical spacing
        panel.add(Box.createVerticalStrut(10))
        
        # Argument index input using ComboBox
        arg_panel = JPanel()
        arg_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        arg_panel.add(JLabel("Select the argument index:"))
        arg_index_input = JComboBox([str(i) for i in range(10)])  # 0-9 options
        arg_panel.add(arg_index_input)
        panel.add(arg_panel)
        
        # Show dialog
        result = JOptionPane.showConfirmDialog(
            None,
            panel,
            "Logging Function Configuration",
            JOptionPane.OK_CANCEL_OPTION
        )
        
        
        try:
            if result == JOptionPane.OK_OPTION:
                function_name = log_function_input.getText()
                arg_index = int(arg_index_input.getSelectedItem())
                return function_name, arg_index
            else:
                return None, None
        except Exception:
            return None, None

    @staticmethod
    def get_global_options():
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        aggressive_checkbox = JCheckBox("AGGRESSIVE", AGGRESSIVE)
        verbose_checkbox = JCheckBox("VERBOSE", VERBOSE)
        panel.add(aggressive_checkbox)
        panel.add(verbose_checkbox)
        result = JOptionPane.showConfirmDialog(None, panel, "Global Options", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            return {
                'aggressive': aggressive_checkbox.isSelected(),
                'verbose': verbose_checkbox.isSelected()
            }
        else:
            return None
    
    @staticmethod
    def print_banner(l_name, a_idx):
        banner = """
+---------------------------------------------------+
|              RenameFuncsByLogs.py                 |
|              ====================                 |
|                                                   |
| Rename functions based on logging function called |
| Version 1.0                                       |
| @hackinaggie                                      |     
+---------------------------------------------------+

[+] Using the argument at index {} in calls to {}
    Aggressive = {}\tVerbose = {}
"""
        print(banner.format(a_idx, l_name, AGGRESSIVE, VERBOSE))

if __name__ == '__main__':
    main()