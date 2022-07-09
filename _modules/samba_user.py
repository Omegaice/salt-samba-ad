from __future__ import annotations 

import salt.utils.files
import salt.utils.hashutils
import salt.utils.itertools
import salt.utils.path
import salt.utils.platform
import salt.utils.stringutils
from salt.exceptions import CommandExecutionError, NotImplemented

import logging 
log = logging.getLogger(__name__)

__virtualname__ = "samba_user"

def __virtual__():
    return __virtualname__

def _samba_tool(arguments, ignore_error=False):
    _tool = salt.utils.path.which("samba-tool")
    if not _tool:
        raise CommandExecutionError("Command 'samba-tool' cannot be found")
    result = __salt__["cmd.run_all"]([_tool] + arguments, python_shell=False)
    if result["retcode"] and not ignore_error:
        raise CommandExecutionError(result["stderr"])
    return result["stdout"]

def _isBitSet(value: int, bit: int) -> bool:
    return(value & bit) != 0 

# https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
# https://gitlab.com/samba-team/samba/-/blob/master/libds/common/flags.h
def _uacToJson(value: int):
    retVal = {}
    retVal["SCRIPT"] = _isBitSet(value, 0x00000001)
    retVal["ACCOUNTDISABLE"] = _isBitSet(value, 0x00000002)
    retVal["HOMEDIR_REQUIRED"] = _isBitSet(value, 0x00000008)
    retVal["LOCKOUT"] = _isBitSet(value, 0x00000010)
    retVal["PASSWD_NOTREQD"] = _isBitSet(value, 0x00000020)
    retVal["PASSWD_CANT_CHANGE"] = _isBitSet(value, 0x00000040)

    retVal["ENCRYPTED_TEXT_PWD_ALLOWED"] = _isBitSet(value, 0x00000080)
    retVal["TEMP_DUPLICATE_ACCOUNT"] = _isBitSet(value, 0x00000100)
    retVal["NORMAL_ACCOUNT"] = _isBitSet(value, 0x00000200)
    retVal["INTERDOMAIN_TRUST_ACCOUNT"] = _isBitSet(value, 0x00000800)
    retVal["WORKSTATION_TRUST_ACCOUNT"] = _isBitSet(value, 0x00001000)
    retVal["SERVER_TRUST_ACCOUNT"] = _isBitSet(value, 0x00002000)
    retVal["DONT_EXPIRE_PASSWORD"] = _isBitSet(value, 0x00010000)
    retVal["MNS_LOGON_ACCOUNT"] = _isBitSet(value, 0x00020000)
    retVal["SMARTCARD_REQUIRED"] = _isBitSet(value, 0x00040000)
    retVal["TRUSTED_FOR_DELEGATION"] = _isBitSet(value, 0x000800000)
    retVal["NOT_DELEGATED"] = _isBitSet(value, 0x00100000)
    retVal["USE_DES_KEY_ONLY"] = _isBitSet(value, 0x00200000)
    retVal["DONT_REQ_PREAUTH"] = _isBitSet(value, 0x00400000)
    retVal["PASSWORD_EXPIRED"] = _isBitSet(value, 0x00800000)
    retVal["TRUSTED_TO_AUTH_FOR_DELEGATION"] = _isBitSet(value, 0x01000000)
    retVal["NO_AUTH_DATA_REQUIRE"] = _isBitSet(value, 0x02000000)
    retVal["PARTIAL_SECRETS_ACCOUNT"] = _isBitSet(value, 0x04000000)
    retVal["USE_AES_KEY"] = _isBitSet(value, 0x08000000)
    return retVal

def add():
    """Add a new user."""
    raise NotImplemented()

def add_unixattrs():
    """Add RFC2307 attributes to a user."""
    raise NotImplemented()

def create():
    """Add a new user."""
    raise NotImplemented()

def delete(name):
    """Delete a user."""
    if not show(name):
        return True
    return _samba_tool(["user", "delete", name])

def disable(name):
    """Disable a user."""
    user_info = show(name)
    if not user_info:
        return True
    if user_info["userAccountControl"]["ACCOUNTDISABLE"]:
        return True
    return _samba_tool(["user", "disable", name])

def update():
    """Modify User AD object."""
    raise NotImplemented()

def enable(name):
    """Enable a user."""
    user_info = show(name)
    if not user_info:
        raise CommandExecutionError("User '{}' does not exist".format(name))
    if not user_info["userAccountControl"]["ACCOUNTDISABLE"]:
        return True
    return _samba_tool(["user", "enable", name])

def get_groups(name):
    """Get the direct group memberships of a user account."""
    user_info = show(name)
    if not user_info:
        raise CommandExecutionError("User '{}' does not exist".format(name))
    return sorted(_samba_tool(["user", "getgroups", name], ignore_error=True).splitlines())

def get_password():
    """Get the password fields of a user/computer account."""
    raise NotImplemented()

def list():
    """List all users."""
    return sorted(_samba_tool(["user", "list"], ignore_error=True).splitlines())

def move():
    """Move a user to an organizational unit/container."""
    raise NotImplemented()

def password():
    """Change password for a user account (the one provided in authentication)."""
    raise NotImplemented()

def rename():
    """Rename a user and related attributes."""
    raise NotImplemented()

def sensitive():
    """Set/unset or show UF_NOT_DELEGATED for an account."""
    raise NotImplemented()

def set_expiry():
    """Set the expiration of a user account."""
    raise NotImplemented()

def set_password():
    """Set or reset the password of a user account."""
    raise NotImplemented()

def set_primary_group():
    """Set the primary group a user account."""
    raise NotImplemented()

def show(name):
    """Display a user AD object."""
    lines = _samba_tool(["user", "show", name], ignore_error=True).splitlines()
    info = dict([tuple(line.split(":", 1)) for line in lines])
    if not info:
        raise CommandExecutionError("User '{}' does not exist".format(name))
    info["userAccountControl"] = _uacToJson(int(info["userAccountControl"]))
    return info

def sync_passwords():
    """Sync the password of user accounts."""
    raise NotImplemented()

def unlock(name):
    """Unlock a user account."""
    user_info = show(name)
    if not user_info:
        raise CommandExecutionError("User '{}' does not exist".format(name))
    if "lockoutTime" not in user_info or user_info["lockoutTime"] == 0:
        return True
    return _samba_tool(["user", "unlock", name])