# Names unindentified functions with a nomenclature that provides a preview of included capabilities within the function
#@author hackinaggie
#@category GSS

# Based on https://github.com/AGDCservices/Ghidra-Scripts/blob/master/Preview_Function_Capabilities.py
# Using Apache 2.0 License at https://github.com/AGDCservices/Ghidra-Scripts/blob/master/LICENSE
# Summary of changes
# Linux functionality, cross-architecture (use pcode in threads)

import re
import collections
import ghidra.program.model.pcode.PcodeOp as PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Ghidra Stuff
CURRENT_PROGRAM = getCurrentProgram()       # Gets the current program
TASK_MONITOR = ConsoleTaskMonitor()         # Handles monitor output to console
DECOMP_INTERFACE = DecompInterface()        # Interface to a single decompile process
DECOMP_INTERFACE.openProgram(CURRENT_PROGRAM)

# Func Name stuff
GHIDRA_FUNC_PREFIX = 'FUN_'
CUSTOM_AUTO_FUNC_PREFIX = 'pfc__'
CUSTOM_AUTO_THREAD_PREFIX = CUSTOM_AUTO_FUNC_PREFIX + 'TS__'

# NOTE: Set to True to inlcude more noisy APIs (like strlen) that increase rename noise in analysis
VERBOSE_FUNCS = True

def main():
    print('=' * 57)
    print('Cross-Platform Preview Function Capability (PFC) Analyzer')
    print('=' * 57)

    # Determine OS type
    os_type = get_os_type()
    print('Detected OS type: {}'.format(os_type))
    
    # rename thread starts with auto name
    threadRootsList = get_thread_roots()
    print("[*] Found {} threads start locations.".format(len(threadRootsList)))
    if len(threadRootsList) > 0:
        print('\tMarking them with {}'.format(CUSTOM_AUTO_THREAD_PREFIX))

    for thread_start in threadRootsList:
        newFuncName = '{:s}{:s}{:s}'.format(
            CUSTOM_AUTO_THREAD_PREFIX , GHIDRA_FUNC_PREFIX, thread_start.toString()
        )
        t_starter = getFunctionAt(thread_start)
        if t_starter == None:
            createFunction(thread_start, newFuncName)
        else:
            t_starter.setName(newFuncName, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        
    # Get all functions the script will look at
    funcList = [
        f for f in CURRENT_PROGRAM.getListing().getFunctions(True) if (
            f.getName().startswith((GHIDRA_FUNC_PREFIX, CUSTOM_AUTO_FUNC_PREFIX))
            and not f.getName().startswith(CUSTOM_AUTO_THREAD_PREFIX)
            and not f.isThunk()
        )]
    
    print('[*] Previewing function capability for {} undefined functions...'.format(len(funcList)))
    
    # Determine which of those are parent nodes
    parentNodes = set()
    for curFunc in funcList:
        curFuncParents = curFunc.getCallingFunctions(TASK_MONITOR)
        parentNodes.update(curFuncParents)

    # Determine which are leafs
    leafNodes = [f for f in funcList if f not in parentNodes ]
    funcRenamedCount = -1    # temp

    # Iterate until no changes are made, meaning all funcs were renamed
    while funcRenamedCount != 0:
        funcRenamedCount = 0
        nodesTraversed = set()
        curNodes = leafNodes[:]

        # Recursively rename functions starting from leafs up through parents
        # Ensures child functionality is propagated to the parent functions
        while True:
            parentNodes = set()
            for curFunc in curNodes:
                # Rename the func
                oldFuncName = curFunc.getName()
                newFuncName = build_new_func_name(curFunc, os_type)
                if newFuncName and newFuncName != oldFuncName:
                    curFunc.setName(newFuncName, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    funcRenamedCount += 1
                # Update parent nodes; keep only funcs previously IDd as valid rename tgts
                curFuncParents = curFunc.getCallingFunctions(TASK_MONITOR)
                parentNodes.update( curFuncParents & set(funcList) )
                # prevent infinite loops
                nodesTraversed.add(curFunc)
                parentNodes = parentNodes - nodesTraversed

            # No more parents; restart at new leaf
            if len(parentNodes) == 0:
                break

            # Rename parentNodes in next iteration of loop
            curNodes = parentNodes.copy()
    print('Analysis Complete')

def get_os_type():
    """Determine if binary is Windows or Linux/Unix based"""
    # Check for common Windows DLL imports
    windows_dlls = ['kernel32.dll', 'user32.dll', 'ntdll.dll', 'advapi32.dll']
    for dll in windows_dlls:
        if any(lib.lower() == dll for lib in CURRENT_PROGRAM.getExternalManager().getExternalLibraryNames()):
            return 'windows'
    # Otherwise assume Unix/Linux
    return 'linux'

def get_called_function_from_pcode(pcode_op):
    """
    Retrieve the name of the function called by a given p-code operation.

    Parameters:
    pcode_op (ghidra.program.model.pcode.PcodeOp): The p-code operation to analyze.

    Returns:
    String: The called function's address, or None if it cannot be determined.
    """
    out_name = None
    if pcode_op.getOpcode() == PcodeOp.CALL:
        called_addr = pcode_op.getInput(0).getAddress()
        out_name = getFunctionAt(called_addr).getName()
    else:
        try:
            call = getInstructionAt(get_pcode_addr(pcode_op))
            
            if call.getOperandRefType(0).isCall():
                # Try to resolve the address to a function
                func_pointer = pcode_op.getInput(0)
                if func_pointer and func_pointer.isAddress():
                    func_addr = func_pointer.getAddress()
                    out_name = getFunctionContaining(func_addr).getName()
            # process calls to function pointers stored in data variables
            elif call.getOperandRefType(0).isData():
                data_ptr = pcode_op.getInput(0)
                if data_ptr.isAddress():
                    curData = getDataAt(data_ptr)
                    if curData == None:
                        curData = getUndefinedDataAt(data_ptr)

                    # get the data variable label
                    if curData.getExternalReference(0) != None:
                        out_name = curData.getExternalReference(0).getLabel()
                    else:
                        out_name = curData.getLabel()
            else:
                out_name = None
        except Exception:
            out_name = None
    return out_name

def get_pcode_addr(pcode_op):
    """
    Get the address of a PcodeOp object.
    
    Parameters:
    pcode_op (ghidra.program.model.pcode.PcodeOp): The PcodeOp to get the address of

    Returns:
    ghidra.program.model.address: The address
    """
    return pcode_op.getSeqnum().getTarget()

def build_new_func_name(func, os_type):
    """
    Build function name based on its capabilities.
    Now handles both Windows and Linux APIs.
    """
    # Select appropriate categories and APIs based on OS
    if os_type == 'windows':
        categoryNomenclatureDict = WINDOWS_CATEGORIES
        apiPurposeDict = WINDOWS_APIS
    else:
        categoryNomenclatureDict = LINUX_CATEGORIES
        apiPurposeDict = LINUX_APIS

    # Get function info
    refToCount = getSymbolAt(func.getEntryPoint()).getReferenceCount()

    # Get all calls in current function
    callList = []
    res = DECOMP_INTERFACE.decompileFunction(func, 30, TASK_MONITOR)
    high_func = res.getHighFunction()
    if high_func:
        for pcode_op in high_func.getPcodeOps():
            if pcode_op.getOpcode() in [PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER]:
                try:
                    f_name = get_called_function_from_pcode(pcode_op)
                    if f_name is not None:
                        callList.append(f_name)
                except Exception as e:
                    print("[-] Error resolving called function from Pcode at 0x{} : {}".format(
                        get_pcode_addr(pcode_op), e
                    ))

    if not callList:
        if func.isThunk():
            callList.append(getInstructionAt(func.getEntryPoint()))
        else:
            return '{}zc_{}{}__xref_{:02d}'.format(
            CUSTOM_AUTO_FUNC_PREFIX, GHIDRA_FUNC_PREFIX, func.getEntryPoint(), refToCount
            )
 
    # Find the APIs used within this func's calls
    apiUsed = set()
    pattern = r'^(?:FID_conflict:)?(?:_)*(?P<baseName>.+?)(?:A|W|Ex|ExA|ExW)?(?:@[a-fA-F0-9]+)?$'
    for curApiName in callList:
        if not curApiName.lower().startswith((
            'dat_', 'byte_', 'word_', 'dword_', 'qword_',
            GHIDRA_FUNC_PREFIX, CUSTOM_AUTO_FUNC_PREFIX, CUSTOM_AUTO_THREAD_PREFIX
            )):
            match = re.search(pattern, curApiName)
            if match is not None:
                curApiName = match.group('baseName')
                #print('CurApiName:', curApiName)
                apiUsed.add(curApiName)

    # map API's called to functionality to use for naming
    implementedApiPurpose = set()
    for entry in apiUsed:
        implementedApiPurpose.add(apiPurposeDict.get(entry))

    # identify functionality from child functions already renamed by this script
    # this will allow api usage to propagate up to the root function
    childFuncApiPurpose = dict()
    for curApiName in callList:
        if curApiName.startswith(CUSTOM_AUTO_FUNC_PREFIX) == True:
            # pull out api capabilities based on naming convention
            for category in categoryNomenclatureDict:
                pattern = category + '_' + '([a-zA-Z]+)+_?([a-zA-Z]+)?'
                match = re.search(pattern, curApiName)
                # if category is found, save into results
                if match is not None:
                    apiPurpose = set()
                    if match.group(1) is not None:
                        apiPurpose.update(list(match.group(1).lower()))
                    if match.group(2) is not None:
                        apiPurpose.update(list(match.group(2).lower()))
                    if category in childFuncApiPurpose:
                        childFuncApiPurpose[category].update(apiPurpose)
                    else:
                        childFuncApiPurpose[category] = apiPurpose

    newFuncNamePurpose = ''
    # Build func purpose using current func's & child funcs' api calls
    for category in categoryNomenclatureDict:
        # if the symbol is found in the current function, add it to the parent string
        parentStr = ''
        for symbol in categoryNomenclatureDict[category]:
            if (category + symbol.upper()) in implementedApiPurpose:
                parentStr += symbol.upper()

        # if the symbol is found in a child function, add it to child string
        childStr = ''
        if category in childFuncApiPurpose:
            for symbol in categoryNomenclatureDict[category]:
                if symbol.lower() in childFuncApiPurpose[category]:
                    childStr += symbol.lower()

        # combine the parent / child symbol list into one final string
        if (len(parentStr) > 0) or (len(childStr) > 0):
            newFuncNamePurpose += category
            if len(parentStr) > 0:
                newFuncNamePurpose += '_' + parentStr
            if len(childStr) > 0:
                newFuncNamePurpose += '_' + childStr
            newFuncNamePurpose += '__'
    
    # build the final function name
    if len(newFuncNamePurpose) > 0:
        # targeted functionality found
        finalFuncName = '{:s}{:s}xref_{:02d}_{:s}'.format(
            CUSTOM_AUTO_FUNC_PREFIX, newFuncNamePurpose, refToCount, func.getEntryPoint().toString()
        )
    else:
        # no targeted functionality identified
        finalFuncName = '{:s}{:s}{:s}__xref_{:02d}'.format(
            CUSTOM_AUTO_FUNC_PREFIX, GHIDRA_FUNC_PREFIX, func.getEntryPoint().toString(), refToCount
        )
    return finalFuncName

def get_thread_param_from_pcode(pcodeOpAST, paramIndex):
    '''
    Recursively trace P-code operations to find the thread start address
    from a given parameter index
    '''
    if pcodeOpAST is None:
        return None
        
    opcode = pcodeOpAST.getOpcode()
    
    # COPY operation might directly contain our target
    if opcode == PcodeOp.COPY:
        input0 = pcodeOpAST.getInput(0)
        if input0.isAddress():
            return input0.getAddress()
        elif input0.isConstant():
            return toAddr(input0.getOffset())
    
    # LOAD operation might be loading our function pointer
    elif opcode == PcodeOp.LOAD:
        input1 = pcodeOpAST.getInput(1)
        if input1.isAddress():
            return input1.getAddress()
            
    # For indirect calls/references, recursively trace the inputs
    elif opcode in [PcodeOp.CALL, PcodeOp.CALLIND]:
        # The parameter we want will be in the input corresponding to our parameter index
        # Account for the call target being input0
        if pcodeOpAST.getNumInputs() > paramIndex + 1:
            param = pcodeOpAST.getInput(paramIndex + 1)
            if param.isAddress():
                return param.getAddress()
            elif param.isConstant():
                return toAddr(param.getOffset())
            
            # If not direct address/constant, try to trace where it came from
            varnode = param.getDef()
            if varnode:
                return get_thread_param_from_pcode(varnode, paramIndex)
                
    return None

def get_thread_roots():
    '''
    Returns a list of addresses of the root functions for all threads
    found in the program using P-code analysis for architecture independence
    '''
    threadStartEaSet = set()
    for funcName, paramIndex in THREAD_APIs.items():
        # get list of API references
        funcList = list(CURRENT_PROGRAM.getSymbolTable().getSymbols(funcName))
        if len(funcList) == 0:
            continue
            
        # get all references to target thread-start function
        funcReferences = funcList[0].getReferences()
        
        for ref in funcReferences:
            if not ref.getReferenceType().isCall():
                continue
                
            # Get function containing the call
            callingFunc = getFunctionContaining(ref.getFromAddress())
            if callingFunc is None:
                continue
                
            # Decompile to get high function
            results = DECOMP_INTERFACE.decompileFunction(callingFunc, 30, TASK_MONITOR)
            if not results.decompileCompleted():
                continue
                
            highFunction = results.getHighFunction()
            if highFunction is None:
                continue
                
            # Get P-code ops for the function
            pcodeOps = highFunction.getPcodeOps(ref.getFromAddress())
            
            # Look through P-code operations at this address
            for pcodeOp in pcodeOps:
                if pcodeOp.getOpcode() in [PcodeOp.CALL, PcodeOp.CALLIND]:
                    # Try to get thread start address from the parameter
                    threadStart = get_thread_param_from_pcode(pcodeOp, paramIndex)
                    if threadStart and getFunctionContaining(threadStart) is not None:
                        threadStartEaSet.add(threadStart)                        
    return threadStartEaSet

# Category nomenclature is OS-independent
BASE_CATEGORIES = collections.OrderedDict({
    'netw': ['c','l','s','r'],                        # connect, listen, send, receive
    'file': ['r','w','d','c','m','e'],                # read, write, delete, copy, move, enumerate
    'proc': ['e','c','r','w','p','m'],                # execute, create, read, write, permissions, modify
    'thread': ['c','o','s','r','e','k','l','w','i'],  # create, open, suspend, resume, exit, kill, lock, wait, info
    'str': ['d','f','t','p'],                         # compare, duplicate, find, tokenize, parse
    'mem': ['c','m','u','r','h'],                     # copy, move, unmap, resize, heap
    'crypto': ['e','d','h','r','k','c'],              # encrypt, decrypt, hash, random, key, certificate
    'ipc': ['c','s','r','o','a','d','p','f'],         # create, send, receive, operation, attach, detach, pipe, fifo
    'time': ['g','s','f'],                            # get, sleep, format
    'env': ['g','s','u'],                             # get, set, unset
    'user': ['i','l','p'],                            # info, lookup, permissions
    'term': ['c','g','s','n'],                        # check, get, set, name
})

# NOTE: Edit to your liking
if VERBOSE_FUNCS:
    BASE_CATEGORIES['netw'].extend(['b','t','m','i','d'])   # build, terminate, modify, info, disconnect
    BASE_CATEGORIES['file'].extend(['h','p','i'])           # handle, permissions, info
    BASE_CATEGORIES['proc'].extend(['h','t','i','d'])       # handle, terminate, info, daemon
    BASE_CATEGORIES['str'].extend(['c', 'm','a','l'])       # compare, modify, append, length
    BASE_CATEGORIES['mem'].extend(['a','f','s'])            # alloc, free, set


# Windows-specific categories
WINDOWS_CATEGORIES = collections.OrderedDict(BASE_CATEGORIES)
WINDOWS_CATEGORIES.update({
    'reg': ['h','r','w','d'],                        # handle, read, write, delete
    'serv': ['h','c','d','s','r','w'],               # handle, create, delete, start, read, write
})

# Linux-specific categories
LINUX_CATEGORIES = collections.OrderedDict(BASE_CATEGORIES)
LINUX_CATEGORIES.update({
    'sig': ['h','s','m','t'],                       # handle, send, mask, timer
    'fs': ['m','l','s','r','c','d','i'],            # mount, link, stat, read, create, delete, info
})

# Windows API mapping
WINDOWS_APIS = {
    # Network operations
    'socket': 'netwB',
    'WSAStartup': 'netwB',
    'connect': 'netwC',
    'WSAConnect': 'netwC',
    'bind': 'netwL',
    'listen': 'netwL',
    'accept': 'netwL',
    'send': 'netwS',
    'WSASend': 'netwS',
    'recv': 'netwR',
    'WSARecv': 'netwR',
    
    # File operations
    'CreateFile': 'fileH',
    'ReadFile': 'fileR',
    'WriteFile': 'fileW',
    'DeleteFile': 'fileD',
    'CopyFile': 'fileC',
    'MoveFile': 'fileM',
    'FindFirstFile': 'fileE',
    
    # Process operations
    'CreateProcess': 'procC',
    'OpenProcess': 'procH',
    'WriteProcessMemory': 'procW',
    'ReadProcessMemory': 'procR',
    'VirtualProtect': 'procP',
    
    # Thread operations
    'CreateThread': 'threadC',
    'CreateRemoteThread': 'threadC',
    'OpenThread': 'threadO',
    'SuspendThread': 'threadS',
    'ResumeThread': 'threadR',
    
    # Registry operations
    'RegOpenKey': 'regH',
    'RegQueryValue': 'regR',
    'RegSetValue': 'regW',
    'RegDeleteValue': 'regD',
    
    # Service operations
    'OpenService': 'servH',
    'CreateService': 'servC',
    'DeleteService': 'servD',
    'StartService': 'servS',
    
    # Crypto operations
    'CryptEncrypt': 'cryptoE',
    'CryptDecrypt': 'cryptoD',
    'CryptCreateHash': 'cryptoH',
    'CryptGenRandom': 'cryptoR',
    
    # Memory operations
    'HeapAlloc': 'memA',
    'VirtualAlloc': 'memA',
    'HeapFree': 'memF',
    'VirtualFree': 'memF',
    'RtlMoveMemory': 'memM',
    
    # String operations
    'strcmp': 'strC',
    'lstrcmp': 'strC',
    'strdup': 'strD',
}

# Linux API mapping
LINUX_APIS = {
    # Network operations
    'socket': 'netwB',         # Base socket creation
    'connect': 'netwC',        # Connect to remote
    'bind': 'netwL',           # Local binding
    'listen': 'netwL',         # Listen for connections
    'accept': 'netwL',         # Accept connections
    'send': 'netwS',           # Send data
    'recv': 'netwR',           # Receive data
    'sendto': 'netwS',         # Send UDP data
    'recvfrom': 'netwR',       # Receive UDP data
    'gethostbyname': 'netwI',  # DNS lookup
    'getaddrinfo': 'netwI',    # Address resolution
    'setsockopt': 'netwM',     # Modify socket
    'shutdown': 'netwD',       # Close connection
    
    # File operations
    'open': 'fileH',           # Handle creation
    'read': 'fileR',           # Read from file
    'write': 'fileW',          # Write to file
    'unlink': 'fileD',         # Delete file
    'rename': 'fileM',         # Move/rename file
    'readdir': 'fileE',        # Enumerate directory
    'fopen': 'fileH',          # Stream creation
    'fclose': 'fileC',         # Close file
    'fread': 'fileR',          # Read from stream
    'fwrite': 'fileW',         # Write to stream
    'fprintf': 'fileW',        # Formatted write
    'fscanf': 'fileR',         # Formatted read
    'fseek': 'fileM',          # Move file pointer
    'ftell': 'fileI',          # Get position
    'chmod': 'fileP',          # Change permissions
    'chown': 'fileP',          # Change ownership
    'truncate': 'fileM',       # Modify file size
    
    # Process operations
    'fork': 'procC',           # Create process
    'execve': 'procC',         # Execute program
    'system': 'procE',         # Execute shell command
    'ptrace': 'procR',         # Read process memory
    'waitpid': 'procW',        # Wait for process
    'exit': 'procE',           # End process
    'getpid': 'procI',         # Get process ID
    'setuid': 'procP',         # Set user ID
    'setgid': 'procP',         # Set group ID
    'daemon': 'procD',         # Daemonize process
    'nice': 'procM',           # Modify priority
    
    # Thread operations
    'pthread_create': 'threadC',    # Create thread
    'pthread_join': 'threadO',      # Wait for thread
    'pthread_exit': 'threadE',      # End thread
    'pthread_cancel': 'threadK',    # Kill thread
    'pthread_mutex_lock': 'threadL',# Lock mutex
    'pthread_cond_wait': 'threadW', # Wait on condition
    'pthread_self': 'threadI',      # Get thread ID
    
    # Signal operations
    'signal': 'sigH',          # Handle signal
    'kill': 'sigS',            # Send signal
    'sigprocmask': 'sigM',     # Modify signal mask
    'sigaction': 'sigH',       # Advanced signal handling
    'raise': 'sigS',           # Send signal to self
    'alarm': 'sigT',           # Timer signal
    
    # Filesystem operations
    'mount': 'fsM',            # Mount filesystem
    'link': 'fsL',             # Create hard link
    'stat': 'fsS',             # Get file status
    'symlink': 'fsL',          # Create symbolic link
    'readlink': 'fsR',         # Read symbolic link
    'chdir': 'fsC',            # Change directory
    'mkdir': 'fsC',            # Create directory
    'rmdir': 'fsD',            # Remove directory
    'getcwd': 'fsI',           # Get current directory
    
    # Crypto operations
    'EVP_EncryptInit': 'cryptoE',   # Initialize encryption
    'EVP_DecryptInit': 'cryptoD',   # Initialize decryption
    'EVP_DigestInit': 'cryptoH',    # Initialize hashing
    'RAND_bytes': 'cryptoR',        # Generate random
    'EVP_EncryptUpdate': 'cryptoE', # Encrypt data
    'EVP_DecryptUpdate': 'cryptoD', # Decrypt data
    'EVP_DigestUpdate': 'cryptoH',  # Update hash
    'EVP_PKEY_new': 'cryptoK',      # Create key
    'X509_new': 'cryptoC',          # Create certificate
    
    # Memory operations
    'malloc': 'memA',          # Allocate memory
    'free': 'memF',            # Free memory
    'memmove': 'memM',         # Move memory
    'memcpy': 'memC',          # Copy memory
    'memset': 'memS',          # Set memory
    'mmap': 'memM',            # Map memory
    'munmap': 'memU',          # Unmap memory
    'calloc': 'memA',          # Allocate zeroed memory
    'realloc': 'memR',         # Resize allocation
    'brk': 'memH',             # Change heap size
    
    # IPC operations
    'msgget': 'ipcC',          # Create message queue
    'msgsnd': 'ipcS',          # Send message
    'msgrcv': 'ipcR',          # Receive message
    'semget': 'ipcC',          # Create semaphore
    'shmget': 'ipcC',          # Create shared memory
    'semop': 'ipcO',           # Semaphore operation
    'shmat': 'ipcA',           # Attach shared memory
    'shmdt': 'ipcD',           # Detach shared memory
    'pipe': 'ipcP',            # Create pipe
    'mkfifo': 'ipcF',          # Create named pipe
    
    # String operations
    'strcmp': 'strC',          # Compare strings
    'strncmp': 'strC',         # Compare n chars
    'strdup': 'strD',          # Duplicate string
    'strcpy': 'strD',          # Copy string
    'strncpy': 'strD',         # Copy n chars
    'strcat': 'strA',          # Concatenate strings
    'strncat': 'strA',         # Concatenate n chars
    'strlen': 'strL',          # Get string length
    'strchr': 'strF',          # Find character
    'strstr': 'strF',          # Find substring
    'strtok': 'strT',          # Tokenize string
    'sprintf': 'strF',         # Format string
    'snprintf': 'strF',        # Safe format string
    'sscanf': 'strP',          # Parse string
    
    # Time operations
    'time': 'timeG',           # Get time
    'gettimeofday': 'timeG',   # Get precise time
    'clock_gettime': 'timeG',  # Get clock time
    'sleep': 'timeS',          # Sleep seconds
    'usleep': 'timeS',         # Sleep microseconds
    'nanosleep': 'timeS',      # Sleep nanoseconds
    'strftime': 'timeF',       # Format time
    
    # Environment operations
    'getenv': 'envG',          # Get environment var
    'setenv': 'envS',          # Set environment var
    'putenv': 'envS',          # Change environment
    'unsetenv': 'envU',        # Remove env var
    
    # User/Group operations
    'getuid': 'userI',         # Get user ID
    'getgid': 'userI',         # Get group ID
    'getpwnam': 'userL',       # Look up user
    'getgrnam': 'userL',       # Look up group
    
    # Terminal operations
    'isatty': 'termC',         # Check if terminal
    'tcgetattr': 'termG',      # Get terminal attributes
    'tcsetattr': 'termS',      # Set terminal attributes
    'ttyname': 'termN',        # Get terminal name
}

# Dictionary mapping thread creation functions to their thread start argument index
THREAD_APIs = {
    # Windows APIs
    'CreateThread': 3,
    '_beginthreadex': 3, 
    '__beginthreadex': 3,
    '_beginthread': 1,
    '__beginthread': 1,
    # Linux APIs
    'pthread_create': 2,
    'clone': 1
}

if __name__ == '__main__':
    main()
