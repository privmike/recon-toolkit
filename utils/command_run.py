import shutil
import subprocess

from utils.logger import log

def check_tool_installed(tool):
    return shutil.which(tool) is not None

def execute_command(commandList, timeout=300):

    toolName = commandList[0]
    commandString = ' '.join(commandList)

    if not check_tool_installed(toolName):
        errMsg = f"tool {toolName} tidak ditemukan di sistem, silahkan install terlebih daulu"
        log.error(errMsg)
        return None, errMsg, 127

    try:
        log.debug(f"Run: {commandString}")

        result = subprocess.run(
            commandList,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            log.debug(f"Command {commandString} error exit code {result.returncode}")

        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        log.error(f"Command {commandString} Timeout {timeout} detik")
        return None, "Timeout", 124

    except Exception as e:
        log.error(f"eksekusi {toolName} error : {str(e)}")
        return None, str(e), 1