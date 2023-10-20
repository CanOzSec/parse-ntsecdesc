#!/usr/bin/env python3

import base64
from parse_ntsecdesc.helpers.structs import SCHEMA_OBJECTS, EXTENDED_RIGHTS, WELL_KNOWN_SIDS
from parse_ntsecdesc.helpers.sddl import parse_ntSecurityDescriptor
from argparse import ArgumentParser
from colorama import Fore


OBJECT_TYPES_GUID = {}
OBJECT_TYPES_GUID.update(SCHEMA_OBJECTS)
OBJECT_TYPES_GUID.update(EXTENDED_RIGHTS)


def pretty_print_acl(sid, isInherited, grantPerms, guid="", inheritedGuid=""):
    a = sid.split("-")
    formatInherit = f"  INHERITED" if isInherited else ""
    if inheritedGuid and inheritedGuid[1:-1] in OBJECT_TYPES_GUID:
        inheritedGuid = f"{OBJECT_TYPES_GUID[inheritedGuid[1:-1]]} {inheritedGuid}"
    if guid and guid[1:-1] in OBJECT_TYPES_GUID:
        guid = f"{OBJECT_TYPES_GUID[guid[1:-1]]} {guid}"

    guids = f"\n{Fore.WHITE}\n\tInherited Guid: {inheritedGuid}\n\tGuid: {guid}" if (inheritedGuid or guid) else ""

    if sid in WELL_KNOWN_SIDS:
        sid = WELL_KNOWN_SIDS[sid]
    if len(a) > 7:
        print(Fore.BLACK + "{\n" + Fore.RED + f"\t{sid}" + Fore.MAGENTA + f" {formatInherit}")
        print(Fore.YELLOW + f"\t{grantPerms}{guids}" + Fore.BLACK + "\n}")
    else:
        print(Fore.BLACK + "{\n" + Fore.CYAN + f"\t{sid}" + Fore.MAGENTA + f" {formatInherit}")
        print(Fore.YELLOW + f"\t{grantPerms}{guids}" + Fore.BLACK + "\n}")


def main():
    parser = ArgumentParser()
    parser.add_argument("-i", "--input", default="", required=True, help="Base64 encoded ntSecurityDescriptor")
    args = parser.parse_args()
    rawSecurityDescriptor = base64.b64decode(args.input)
    out = parse_ntSecurityDescriptor(rawSecurityDescriptor)
    for ace in out['DACL']['ACEs']:
        try:
            sid = ace.get('SID')
            access = ace.get('Access Required')
            isAllowed = True if ("Allowed" in ace.get('Type')) else False
            objFlags = ace.get('Object Flags')
            guid = ace.get("GUID")
            inheritedGuid = ace.get("Inherited GUID")
            if objFlags:
                isInherited = objFlags["Inherited Object Type Present"]
            if not sid:
                continue
            if not isAllowed:
                continue
            grantPerms = []
            for perm in access:
                if access[perm]:
                    grantPerms.append(perm)
            pretty_print_acl(sid, isInherited, grantPerms, guid=guid, inheritedGuid=inheritedGuid)
            
        except:
            print(Fore.RED + "Parsing Error!")

if __name__ == "__main__":
    main()
