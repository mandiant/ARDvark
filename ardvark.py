# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.
# 
# Authored by Jake Nicastro
# Email: jake.nicastro@mandiant.com
# Twitter: @nicastronaut
#
# Filesystem.cache parsing authored by Willi Ballenthin
# Email: william.ballenthin@fireeye.com
# Twitter: @williballenthin
#
# ARDvark
#
# Written for Python 3.7
# 
# Description:
#   ARDvark extracts useful information for forensic analysts and incident responders
#   related to application usage and user logon activity recorded in the Apple
#   Remote Desktop remote management database file (rmdb.sqlite3) populated on
#   ARD administrator machines, as well as the plist files that are used to cache
#   the data on client machines and are sent to the administrator machine to be
#   put into the RMDB. It also parses the filesystem.cache files found on ARD-enabled machines
#   and provides a complete file listing of client machines as well as users and groups.

import sqlite3
import csv
import datetime
import plistlib
import os
import sys
import struct
import collections
from argparse import ArgumentParser


WorkingDir = os.getcwd()
MacTimeBase = datetime.datetime.strptime("2001-01-01", "%Y-%m-%d")    # Used for converting Mac Absolute time


def conv_mac_time(time):
    """ Convert raw absolute Mac time to human readable format"""
    r_time = MacTimeBase + datetime.timedelta(seconds=float(time))
    time = r_time.strftime("%Y-%m-%d %H:%M:%S")
    return time


def calc_end(run, launch):
    """Add run length to launch time and return end time in human readable format"""
    end = float(launch) + float(run)
    r_end_time = MacTimeBase + datetime.timedelta(seconds=float(end))
    end_time = r_end_time.strftime("%Y-%m-%d %H:%M:%S")
    return end_time


def chg_state(state):
    """Convert run state values and return strings"""
    if state == 1:
        return "Terminated"
    return "Running"


def get_hostname(mac_addr, conn):
    """Look up hostname for given MAC address and return hostname, if available"""
    name = ""
    tmp_cursor = conn.cursor()
    tmp_tuple = (mac_addr,)
    tmp_cursor.execute("SELECT SystemInformation.Value FROM SystemInformation \
                        WHERE SystemInformation.PropertyName = 'UnixHostName' \
                        AND SystemInformation.ComputerID = ?", tmp_tuple)
    name = tmp_cursor.fetchone()
    if name:
        return name[0]
    else:
        name = "NA"
        return name


def app_usage_plist(pl):
    """Creates CSV for application usage data from AppUsage.plist"""
    with open("AppUsagePlist.csv", "w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["App Location", "App Name", "Was Quit", "Frontmost Time", "Launch Time", "End time", "User"])
        for app in pl.items():    # Each item is a tuple with 2 items (filepath, dict(rundata, name)). Rundata is a list of dicts
            app_list = []
            for val in app:
                if val == app[0]:    # For the first item in the tuple: filepath
                    app_list.append(val)
                else:
                    app_list.append(val["Name"])
                    for key in val:    # The other value is the dict with runData and name
                        if key != "Name":
                            for run_set in val[key]:    # The value of runData is a list of dicts
                                run_list = []
                                for x in app_list:
                                    run_list.append(x)
                                was_quit = "False"
                                for item in run_set:
                                    if item == "Frontmost":
                                        frontmost = run_set[item]
                                    if item == "Launched":
                                        launched = run_set[item]
                                    if item == "runLength":
                                        run_length = run_set[item]
                                    if item == "userName":
                                        username = run_set[item]
                                    if item == "wasQuit":
                                        was_quit = run_set[item]
                                end = calc_end(run_length, launched)
                                launched = conv_mac_time(launched)
                                run_list.extend((was_quit, frontmost, launched, end, username))
                                writer.writerow(run_list)


def user_act_plist(pl):
    """Creates CSV for user login activity data from UserAcct.tmp plist"""
    with open("UserActivityPlist.csv", "w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["Username (Short)", "UID", "Type", "Login Time", "Logout Time", "Source IP"])
        for user_set in pl.items():    # userSet is a tuple
            user_set_list = []
            for val in user_set:
                if val == user_set[0]:    # Username should be first in each userSet tuple
                    user_set_list.append(val)
                else:
                    user_set_list.append(val["uid"])
                    for key in val:    # Second value is a dict of each login type + uid
                        if key != "uid":
                            for login_set in val[key]:    # Each key is a different login type with possibly >1 set of login/logout times
                                login_list = []    # List that being written for each line of the csv
                                for x in user_set_list:
                                    login_list.append(x)    # Feed username/uid to list
                                login_list.append(key)
                                host = "NA"    # Set host to NA by default
                                for item in login_set:
                                    if item == "inTime":
                                        in_time = conv_mac_time(login_set[item])
                                    if item == "outTime":
                                        out_time = conv_mac_time(login_set[item])
                                    if item == "host":
                                        host = login_set[item]
                                login_list.extend((in_time, out_time, host))
                                writer.writerow(login_list)


def app_usage(app_usage_data, conn):
    """Creates CSV for application usage data from RMDB"""
    with open("AppUsageRMDB.csv", "w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["MAC Address", "Hostname", "App Name", "App Location", "Launch Time",
                        "Frontmost Time", "End Time", "Last Updated", "UserName", "Last Reported Run State"])
        for row in app_usage_data:
            lst = list(row)    # Convert the tuple to a list for mutation
            lst[0] = ":".join(x + y for x, y in zip(lst[0][::2], lst[0][1::2]))
            lst.insert(1, get_hostname(lst[0], conn))    # Get hostname for the MAC address
            lst[6] = calc_end(lst[6], lst[4])    # Calculate end time
            lst[4] = conv_mac_time(lst[4])    # Convert the launch time to human readable format
            lst[7] = conv_mac_time(lst[7])    # Convert LastUpdated to human readable format
            lst[9] = chg_state(lst[9])    # Change RunState from boolean to words
            writer.writerow(lst)


def user_activity(user_act_data, conn):
    """Creates CSV for user login activity data from RMDB"""
    with open("UserActivityRMDB.csv", "w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["Dest MAC", "Dest Hostname", "Last Updated", "UserName", "Login Type", "Login", "Logout", "Remote Host"])
        for row in user_act_data:
            lst = list(row)    # Convert the tuple to a list for mutation
            lst[0] = ":".join(x + y for x, y in zip(lst[0][::2], lst[0][1::2]))
            lst.insert(1, get_hostname(lst[0], conn))    # Get hostname for the MAC address
            lst[2] = conv_mac_time(lst[2])    # Convert LastUpdated time to human readable format
            lst[5] = conv_mac_time(lst[5])    # Convert Login time to human readable format
            if lst[6] != "NA":    # Convert logout time to human readable format (if available)
                lst[6] = conv_mac_time(lst[6])
            writer.writerow(lst)


Header = collections.namedtuple('Header', [
    'magic', 'version',
    'unk1', 'unk2',
    'ts_delta',
    'total_entries', 'total_folders',
    'total_files', 'total_symlinks',
    'entries_offset', 'entries_length',
    'names_offset', 'names_length',
    'kinds_offset', 'kinds_length',
    'versions_offset', 'versions_length',
    'users_offset', 'users_length',
    'groups_offset', 'groups_length',
    'complete_size'
])


def parse_header(buf):
    fields = struct.unpack_from('>IIIIIIIIIIIIIIIIIIIIII', buf, 0x0)
    return Header(*fields)


TableHeader = collections.namedtuple('TableHeader', [
    'count',
    'magic',
    'entries_length',
    'strings_offset',
    'strings_length',
])


def parse_table_header(buf):
    return TableHeader(*struct.unpack_from('>IQIII', buf, 0x0))


TableEntryDescriptor = collections.namedtuple('TableEntryDescriptor', [
    'offset',
    'owner',
    'string_length',
])


TableEntry = collections.namedtuple('TableEntry', [
    'index',  # index into the table of this entry
    'descriptor',
    'string',
])


def parse_table_entry(buf, header, index, offset):
    desc = TableEntryDescriptor(*struct.unpack_from('>IIH', buf, offset))
    start = 0x18 + header.entries_length + desc.offset
    # +1 to account for the leading 0x01
    end = start + desc.string_length + 1
    # [1:] to strip the leading 0x01 (maybe string type?)
    string = buf[start:end][1:].decode('utf-8')
    return TableEntry(index, desc, string)


Table = collections.namedtuple('Table', [
    'header',
    'entries',
])


def parse_table(buf):
    buf = buf
    header = parse_table_header(buf)
    entries = []
    offset = 0x18  # sizeof(TableHeader)
    for i in range(header.count):
        entries.append(parse_table_entry(buf, header, i, offset))
        offset += 10  # sizeof(TableEntry)

    return Table(header, entries)


EntryDescriptor = collections.namedtuple('EntryDescriptor', [
    'parent',
    'field_4', 'field_8', 'field_C', 'field_E',
    'field_12', 'field_14', 'field_16',
    'unk1', 'unk2',
    'field_20', 'field_28',
    'match_count',
    'field_2E', 'version_resource',
    'type_flags',
    'field_36',
    'previous_owner',
    'name_reference',
    'kind_reference',
    'version_reference',
    'user_reference',
    'group_reference',
])


def parse_entry(buf):
    return EntryDescriptor(
        *struct.unpack_from('>IIIHIHHIIHQIHHIHHIIIIII', buf, 0x0))


class Entry:
    def __init__(self, index, offset, descriptor):
        self.offset = offset
        self.index = index
        self.descriptor = descriptor

    def get_name(self):
        return self.index.names[self.descriptor.name_reference].string.rstrip('\x0d')

    def get_kind(self):
        return self.index.kinds[self.descriptor.kind_reference].string.rstrip('+')

    def get_version(self):
        return self.index.versions[self.descriptor.version_reference].string

    def get_user(self):
        return self.index.users[self.descriptor.user_reference].string

    def get_group(self):
        return self.index.groups[self.descriptor.group_reference].string

    def is_directory(self):
        return self.descriptor.type_flags & 0x2 == 0x2

    def get_path(self):
        if self.offset in self.index._path_cache:
            return self.index._path_cache[self.offset]

        filename = self.get_name()

        if self.is_directory():
            filename = filename + '/'

        if self.descriptor.parent != 0x0:
            parent = self.index.get_entry(self.descriptor.parent)
            path = parent.get_path() + filename
        else:
            path = filename

        self.index._path_cache[self.offset] = path
        return path

    def __str__(self):
        parts = []

        for k, v in (('path', self.get_path().ljust(32)),
                     ('kind', self.get_kind().ljust(5)),
                     ('user', self.get_user().ljust(16)),
                     ('group', self.get_group().ljust(16)),
                     ('version', self.get_version())):
            if v:
                parts.append('%s: %s' % (k, v))

        return 'file: %s' % (' '.join(parts))


class Index:
    def __init__(self, buf):
        self.buf = buf
        self.header = parse_header(buf)
        self.names = self.get_names_table().entries
        self.kinds = self.get_kinds_table().entries
        self.versions = self.get_versions_table().entries
        self.users = self.get_users_table().entries
        self.groups = self.get_groups_table().entries

        # not exported.
        # written to in `Entry.get_path()`.
        #
        # map from entry offset to path
        self._path_cache = {}

    def get_table(self, start, length):
        return parse_table(self.buf[start:start + length])

    def get_names_table(self):
        return self.get_table(self.header.names_offset,
                              self.header.names_length)

    def get_kinds_table(self):
        return self.get_table(self.header.kinds_offset,
                              self.header.kinds_length)

    def get_versions_table(self):
        return self.get_table(self.header.versions_offset,
                              self.header.versions_length)

    def get_users_table(self):
        return self.get_table(self.header.users_offset,
                              self.header.users_length)

    def get_groups_table(self):
        return self.get_table(self.header.groups_offset,
                              self.header.groups_length)

    def get_entry(self, offset):
        # offset is absolute offset, which is an odd choice
        desc = parse_entry(self.buf[offset:])
        return Entry(self, offset, desc)

    def get_entries(self):
        for i in range(self.header.total_entries):
            yield self.get_entry(0x58 + i * 0x50)

    def get_name_entry(self, name):
        for entry in self.names:
            if entry.string == name:
                return entry
        raise KeyError(name)

    def get_entries_by_name(self, name):
        name_entry = self.get_name_entry(name)

        entry = self.get_entry(name_entry.descriptor.owner)
        yield entry

        while entry.descriptor.previous_owner != 0x0:
            entry = self.get_entry(entry.descriptor.previous_owner)
            yield entry


def parse_index(buf):
    return Index(buf)


def print_namedtuple(item, output):
    output.write(item.__class__.__name__ + ":")
    for field in item._fields:
        v = getattr(item, field)
        if isinstance(v, int):
            output.write('  - %s: 0x%x' % (field, v))
        else:
            output.write('  - %s: %s' % (field, v))


def fscache(buf):
    ''' Decodes filesystem.cache and writes file system listing to text file '''
    with open("fscache.txt", "w", newline="") as output:
        index = parse_index(buf)
        print_namedtuple(index.header, output)
        output.write("Files:")
        for entry in index.get_entries():
            output.write('  - ' + str(entry) + "\n")


def main():
    p = ArgumentParser(description="""ARDvark is a tool to parse application usage and remote user connection activity
                                        from the Remote Management SQLite database and the associated cache plist files
                                        for Apple Remote Desktop""")
    p.add_argument("-d", "--db", help="Parse an rmdb.sqlite3 file")
    p.add_argument("-u", "--uplist", help="Parse UserAcct.tmp plist file")
    p.add_argument("-a", "--aplist", help="Parse AppUsage.plist file")
    p.add_argument("-f", "--fscache", help="Parse filesystem.cache file")
    args = p.parse_args()
    if args.db:
        print("Parsing Remote Management Database...")
        rmdb = args.db
        conn = sqlite3.connect(rmdb)    # Establishes connection to the DB
        c = conn.cursor()    # Creates cursor object for execution
        app_usage_data = c.execute("""SELECT ApplicationName.ComputerID, ApplicationName.AppName, ApplicationName.AppURL,
                                    ApplicationUsage.FrontMost, ApplicationUsage.LaunchTime, ApplicationUsage.RunLength,
                                    ApplicationUsage.LastUpdated, ApplicationUsage.UserName, ApplicationUsage.RunState
                                    FROM ApplicationName INNER JOIN ApplicationUsage
                                    ON ApplicationName.ComputerID = ApplicationUsage.ComputerID
                                    AND ApplicationName.ItemSeq = ApplicationUsage.ItemSeq""")
        app_usage(app_usage_data, conn)
        user_act_data = c.execute("SELECT * FROM UserUsage")
        user_activity(user_act_data, conn)
        conn.close()
        print("AppUsageRMDB.csv and UserActivityRMDB.csv created in %s." % (WorkingDir))
    if args.uplist:
        print("Parsing User Activity plist...")
        with open(args.uplist, 'rb') as f:
            pl = plistlib.load(f)
            user_act_plist(pl)
        print("UserActivityPlist.csv created in %s." % (WorkingDir))
    if args.aplist:
        print("Parsing Application Usage plist...")
        with open(args.aplist, 'rb') as f:
            pl = plistlib.load(f)
            app_usage_plist(pl)
        print("AppUsagePlist.csv created in %s." % (WorkingDir))
    if args.fscache:
        print("Parsing filesystem cache...")
        with open(args.fscache, 'rb') as f:
            buf = f.read()
            fscache(buf)
        print("fscache.txt created in %s." % (WorkingDir))
    else:
        p.print_help()


main()
