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

__func_alias__ = {"list_": "list"}

__virtualname__ = "samba_group"

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

def add():
    """Creates a new AD group."""
    raise NotImplemented()

def addmembers():
    """Add members to an AD group."""
    raise NotImplemented()

def addunixattrs():
    """Add RFC2307 attributes to a group."""
    raise NotImplemented()

def create():
    """Creates a new AD group."""
    raise NotImplemented()

def delete():
    """Deletes an AD group."""
    raise NotImplemented()

def edit():
    """Modify Group AD object."""
    raise NotImplemented()

def list_():
    """List all groups."""
    return sorted(_samba_tool(["group", "list"], ignore_error=True).splitlines())

def list_members(name):
    """List all members of an AD group."""
    if not show(name):
        raise CommandExecutionError("Group '{}' does not exist".format(name))
    return sorted(_samba_tool(["group", "listmembers", name], ignore_error=True).splitlines())

def move():
    """Move a group to an organizational unit/container."""
    raise NotImplemented()

def removemembers():
    """Remove members from an AD group."""
    raise NotImplemented()

def rename():
    """Rename a group and related attributes."""
    raise NotImplemented()

def show(name):
    """Display a group AD object."""
    lines = _samba_tool(["group", "show", name], ignore_error=True).splitlines()
    info = dict([tuple(line.split(":", 1)) for line in lines])
    if not info:
        raise CommandExecutionError("Group '{}' does not exist".format(name))
    return info

def stats():
    """Summary statistics about group memberships."""
    raise _samba_tool(["group", "stats"], ignore_error=True)