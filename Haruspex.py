# Haruspex.py - Extract pseudo-code from Ghidra's decompiler 
# Ghidra script to extract pseudo-code from decompiler in a format suitable
# for IDE import or static analysis tools
#
# Based on Haruspex.java by Marco Ivaldi <raptor@0xdeadbeef.info)
# Copyright (c) 2022-2024 Marco Ivaldi <raptor@0xdeadbeef.info>
# This software is licensed under the MIT License.
# See https://github.com/0xdea/ghidra-scripts/blob/main/LICENSE
#
# @author: hackinaggie
# @category: GSS

from javax.swing import JPanel
from ghidra.app.decompiler import DecompInterface
from docking.widgets.filechooser import GhidraFileChooser, GhidraFileChooserMode
from ghidra.util.task import ConsoleTaskMonitor
import os

def get_all_functions(program):
    """
    Collect all non-external, non-thunk Function objects
    """
    try:
        return [ 
            func for func in program.getFunctionManager().getFunctions(True)
            if not(func.isExternal() or func.isThunk())
        ]
    except Exception as e:
        print('[-] Unable to enumerate functions: {}'.format(e))
        return None

def main():
    """
    Main script execution method
    """
    print("\nHaruspex.py - Extract Ghidra decompiler's pseudo-code\n")
    print("Copyright (c) 2022-2024 Marco Ivaldi <raptor@0xdeadbeef.info>")
    # idk anything about copyrights don't sue me :'(
    print("Modified by hackinaggie\n\n")
    
    # Use Ghidra's file chooser to select output directory
    file_chooser = GhidraFileChooser(JPanel())
    file_chooser.setTitle("Select Output Directory for Decompiled Code")
    file_chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY)
    output_dir = file_chooser.getSelectedFile(True)
    if output_dir is None:
        print("[-] No output directory selected. Exiting.\n")
        return
    output_path = output_dir.getAbsolutePath()
    current_program = getCurrentProgram()

    functions = get_all_functions(current_program)

    # Setup decompiler
    decomp = DecompInterface()
    decomp.toggleCCode(True)
    decomp.toggleSyntaxTree(True)
    decomp.setSimplificationStyle("decompile")
    
    if not decomp.openProgram(current_program):
        print("[-] Could not initialize the decompiler, exiting.\n\n")
        return
    print("[*] Extracting pseudo-code from {} functions...\n\n".format(len(functions)))
    
    for func in functions:
        results = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
        decompiled = results.getDecompiledFunction()
        if decompiled is not None:
            # Save to file
            try:
                output_filename = "{}@{}.c".format(
                    func.getName(), func.getEntryPoint()
                )
                output_filepath = os.path.join(output_path, output_filename)
                with open(output_filepath, 'w') as f:
                    f.write(decompiled.getC())
            except Exception as e:
                print("[-] Cannot write to output file '{}': {}\n".format(
                    output_filepath, e
                ))
        else:
            print("[-] Unable to decompile function '{}'\n".format(func.getName()))

if __name__ == '__main__':
    main()