# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import platform
from os.path import expanduser
import time
import json
import shutil
import inspect
import fnmatch
import getpass
import tempfile
import argparse
from collections import defaultdict

try:
    from scandir import walk
except ImportError:
    from os import walk

import viper.common.out as out
from viper.common.colors import bold
from viper.common.utils import convert_size
from viper.common.objects import File
from viper.common.abstracts import get_argparse_parser_actions
from viper.common.network import download
from viper.common.version import __version__
from viper.core.session import __sessions__
from viper.core.project import __project__
from viper.core.plugins import __modules__
from viper.core.database import Database
from viper.core.storage import store_sample, get_sample_path
from viper.core.config import __config__, console_output
from viper.common.autorun import autorun_module
from viper.core.archiver import Compressor

cfg = __config__

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass


# setup a database instance module wide (refresh with db.__init__() if needed)
db = Database()


def get_password_twice():
    password = getpass.getpass('Password: ')
    if password == getpass.getpass('confirm Password: '):
        return password
    else:
        return False


class Commands(object):
    output = []

    def __init__(self):
        db.__init__()
        # Map commands to their related functions.
        self.commands = dict()
        for item in Command().get_subclasses():
            instance = item()
            self.commands.update({instance.cmd: dict(obj=instance.run,
                                                     description=instance.description,
                                                     parser_args=get_argparse_parser_actions(instance.parser),
                                                     fs_path_completion=instance.fs_path_completion)})


class Command(object):
    cmd = ""
    description = ""
    command_line = []
    args = None
    authors = []
    output = []
    fs_path_completion = False

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog=self.cmd, description=self.description)

    def log(self, event_type, event_data):
        self.output.append(dict(
            type=event_type,
            data=event_data
        ))
        out.print_output([{'type': event_type, 'data': event_data}], console_output['filename'])

    def _is_subclass(self, obj):
        return inspect.isclass(obj) and issubclass(obj, self.__class__)

    def get_subclasses(self):
        """Yields all subclasses of this class"""
        for name, obj in inspect.getmembers(sys.modules[__name__], predicate=self._is_subclass):
            if hasattr(obj, "__bases__") and self.__class__ in obj.__bases__:
                yield obj


class About(Command):
    ##
    # ABOUT
    #
    # This command prints some useful information regarding the running
    # Viper instance
    cmd = "about"
    description = "Show information about this Viper instance"

    def run(self, *args):
        try:
            self.parser.parse_args(args)
        except SystemExit:
            return

        rows = list()
        rows.append(["Viper Version", __version__])
        rows.append(["Python Version", platform.python_version()])
        rows.append(["Homepage", "https://viper.li"])
        rows.append(["Issue Tracker", "https://github.com/viper-framework/viper/issues"])

        self.log('table', dict(header=['About', ''], rows=rows))

        rows = list()
        rows.append(["Configuration File", cfg.config_file])

        if __project__.name:
            rows.append(["Active Project", __project__.name])
            rows.append(["Storage Path", __project__.path])
            rows.append(["Database Path", db.engine.url])
        else:
            rows.append(["Active Project", "default"])
            rows.append(["Storage Path", __project__.path])
            rows.append(["Database Path", db.engine.url])

        self.log('table', dict(header=['Configuration', ''], rows=rows))


class Analysis(Command):
    ##
    # ANALYSIS
    #
    # This command allows you to view the stored output from modules that have been run
    # with the currently opened file.
    cmd = "analysis"
    description = "View the stored analysis"

    def __init__(self):
        super(Analysis, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true',
                           help="List all module results available for the current file")
        group.add_argument('-v', '--view', metavar='ANALYSIS ID', type=int, help="View the specified analysis")
        group.add_argument('-d', '--delete', metavar='ANALYSIS ID', type=int, help="Delete an existing analysis")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        # check if the file is already stores, otherwise exit
        malware = db.find(key='sha256', value=__sessions__.current.file.sha256)
        if not malware:
            self.log('error', "The opened file doesn't appear to be in the database, have you stored it yet?")
            return

        if args.list:
            # Retrieve all analysis for the currently opened file.

            analysis_list = malware[0].analysis
            if not analysis_list:
                self.log('info', "No analysis available for this file yet")
                return

            # Populate table rows.
            rows = [[analysis.id, analysis.cmd_line, analysis.stored_at] for analysis in analysis_list]

            # Display list of existing results.
            self.log('table', dict(header=['ID', 'Cmd Line', 'Saved On (UTC)'], rows=rows))

        elif args.view:
            # Retrieve analysis wth the specified ID and print it.
            result = db.get_analysis(args.view)
            if result:
                self.log('info', bold('Cmd Line: ') + result.cmd_line)
                for line in json.loads(result.results):
                    self.log(line['type'], line['data'])
            else:
                self.log('info', "There is no analysis with ID {0}".format(args.view))


class Clear(Command):
    ##
    # CLEAR
    #
    # This command simply clears the shell.
    cmd = "clear"
    description = "Clear the console"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        os.system('clear')


class Close(Command):
    ##
    # CLOSE
    #
    # This command resets the open session.
    # After that, all handles to the opened file should be closed and the
    # shell should be restored to the default prompt.
    cmd = "close"
    description = "Close the current session"

    def run(self, *args):
        try:
            self.parser.parse_args(args)
        except SystemExit:
            return

        __sessions__.close()


class Copy(Command):
    ##
    # COPY
    #
    # This command copies the opened file into another project. Analysis, Notes
    # and Tags are - by default - also copies. Children can (optionally) also
    # be copied (recursively).
    cmd = "copy"
    description = "Copy opened file(s) into another project"

    def __init__(self):
        super(Copy, self).__init__()
        self.parser.add_argument('project', type=str, help="Project to copy file(s) to")

        self.parser.add_argument('-d', '--delete', action='store_true', help="delete original file(s) after copy ('move')")
        self.parser.add_argument('--no-analysis', action='store_true', help="do not copy analysis details")
        self.parser.add_argument('--no-notes', action='store_true', help="do not copy notes")
        self.parser.add_argument('--no-tags', action='store_true', help="do not copy tags")

        self.parser.add_argument('-c', '--children', action='store_true', help="also copy all children - if --delete was "
                                                                               "selected also the children will be deleted "
                                                                               "from current project after copy")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        if not __project__.name:
            src_project = "default"
        else:
            src_project = __project__.name

        db.copied_id_sha256 = []
        res = db.copy(__sessions__.current.file.id,
                      src_project=src_project, dst_project=args.project,
                      copy_analysis=True, copy_notes=True, copy_tags=True, copy_children=args.children)

        if args.delete:
            __sessions__.close()
            for item_id, item_sha256 in db.copied_id_sha256:
                db.delete_file(item_id)
                os.remove(get_sample_path(item_sha256))
                self.log('info', "Deleted: {}".format(item_sha256))

        if res:
            self.log('success', "Successfully copied sample(s)")
            return True
        else:
            self.log('error', "Something went wrong")
            return False


class Delete(Command):
    ##
    # DELETE
    #
    # This command deletes the currently opened file (only if it's stored in
    # the local repository) and removes the details from the database
    cmd = "delete"
    description = "Delete the opened file"

    def __init__(self):
        super(Delete, self).__init__()

        self.parser.add_argument('-a', '--all', action='store_true', help="Delete ALL files in this project")
        self.parser.add_argument('-f', '--find', action="store_true", help="Delete ALL files from last find")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        while True:
            choice = input("Are you sure? It can't be reverted! [y/n] ")
            if choice == 'y':
                break
            elif choice == 'n':
                return

        if args.all:
            if __sessions__.is_set():
                __sessions__.close()

            samples = db.find('all')
            for sample in samples:
                db.delete_file(sample.id)
                os.remove(get_sample_path(sample.sha256))

            self.log('info', "Deleted a total of {} files.".format(len(samples)))
        elif args.find:
            if __sessions__.find:
                samples = __sessions__.find
                for sample in samples:
                    db.delete_file(sample.id)
                    os.remove(get_sample_path(sample.sha256))
                self.log('info', "Deleted {} files.".format(len(samples)))
            else:
                self.log('error', "No find result")

        else:
            if __sessions__.is_set():
                rows = db.find('sha256', __sessions__.current.file.sha256)
                if rows:
                    malware_id = rows[0].id
                    if db.delete_file(malware_id):
                        self.log("success", "File deleted")
                    else:
                        self.log('error', "Unable to delete file")

                os.remove(__sessions__.current.file.path)
                __sessions__.close()

                self.log('info', "Deleted opened file.")
            else:
                self.log('error', "No session open, and no --all argument. Nothing to delete.")


class Export(Command):
    ##
    # EXPORT
    #
    # This command will export the current session to file or zip.
    cmd = "export"
    description = "Export the current session to file or zip"
    fs_path_completion = True

    def __init__(self):
        super(Export, self).__init__()

        self.parser.add_argument('-z', '--zip', action='store_true', help="Export session in a zip archive (PW support: No)")
        self.parser.add_argument('-7', '--sevenzip', action='store_true', help="Export session in a 7z archive (PW support: Yes)")
        self.parser.add_argument('-p', '--password', action='store_true', help="Protect archive with a password (PW) if supported")
        self.parser.add_argument('value', help="path or archive name")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            self.log('error', "No open session")
            self.parser.print_usage()
            return

        # Check for valid export path.
        if args.value is None:
            self.parser.print_usage()
            return

        if args.zip and args.sevenzip:
            self.log('error', "Please select either -z or -7 not both, abort")

        store_path = os.path.join(args.value, __sessions__.current.file.name)

        if not args.zip and not args.sevenzip:
            # Abort if the specified path already exists
            if os.path.isfile(store_path):
                self.log('error', "Unable to export file: File exists: '{0}'".format(store_path))
                return

            if not os.path.isdir(args.value):
                try:
                    os.makedirs(args.value)
                except OSError as err:
                    self.log('error', "Unable to export file: {0}".format(err))
                    return

            try:
                shutil.copyfile(__sessions__.current.file.path, store_path)
            except IOError as e:
                self.log('error', "Unable to export file: {0}".format(e))
            else:
                self.log('info', "File exported to {0}".format(store_path))

            return
        elif args.zip:
            cls = "ZipCompressor"

        elif args.sevenzip:
            cls = "SevenZipSystemCompressor"
        else:
            cls = ""
            self.log('error', "Not implemented".format())

        c = Compressor()

        if args.password:
            if c.compressors[cls].supports_password:
                _password = get_password_twice()
                if not _password:
                    self.log('error', "Passwords did not match, abort")
                    return
                res = c.compress(__sessions__.current.file.path, file_name=__sessions__.current.file.name,
                                 archive_path=store_path, cls_name=cls, password=_password)
            else:
                self.log('warning', "ignoring password (not supported): {}".format(cls))
                res = c.compress(__sessions__.current.file.path, file_name=__sessions__.current.file.name,
                                 archive_path=store_path, cls_name=cls)

        else:
            res = c.compress(__sessions__.current.file.path, file_name=__sessions__.current.file.name,
                             archive_path=store_path, cls_name=cls)

        if res:
            self.log('info', "File archived and exported to {0}".format(c.output_archive_path))
        else:
            self.log('error', "Unable to export file: {0}".format(c.err))


class Find(Command):
    ##
    # FIND
    #
    # This command is used to search for files in the database.
    cmd = "find"
    description = "Find a file"

    def __init__(self):
        super(Find, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-t', '--tags', action='store_true', help="List available tags and quit")
        group.add_argument('type', nargs='?', choices=["all", "latest", "name", "type", "mime", "md5", "sha1", "sha256", "tag", "note", "any", "ssdeep"], help="Where to search.")
        self.parser.add_argument("value", nargs='?', help="String to search.")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # One of the most useful search terms is by tag. With the --tags
        # argument we first retrieve a list of existing tags and the count
        # of files associated with each of them.
        if args.tags:
            # Retrieve list of tags.
            tags = db.list_tags()

            if tags:
                rows = []
                # For each tag, retrieve the count of files associated with it.
                for tag in tags:
                    count = len(db.find('tag', tag.tag))
                    rows.append([tag.tag, count])

                # Generate the table with the results.
                header = ['Tag', '# Entries']
                rows.sort(key=lambda x: x[1], reverse=True)
                self.log('table', dict(header=header, rows=rows))
            else:
                self.log('warning', "No tags available")

            return

        # At this point, if there are no search terms specified, return.
        if args.type is None:
            self.parser.print_usage()
            return

        key = args.type
        if key != 'all' and key != 'latest':
            try:
                # The second argument is the search value.
                value = args.value
            except IndexError:
                self.log('error', "You need to include a search term.")
                return
        else:
            value = None

        # Search all the files matching the given parameters.
        items = db.find(key, value)
        if not items:
            return

        # Populate the list of search results.
        rows = []
        count = 1
        for item in items:
            tag = ', '.join([t.tag for t in item.tag if t.tag])
            row = [count, item.name, item.mime, item.md5, tag]
            if key == 'ssdeep':
                row.append(item.ssdeep)
            if key == 'latest':
                row.append(item.created_at)

            rows.append(row)
            count += 1

        # Update find results in current session.
        __sessions__.find = items

        # Generate a table with the results.
        header = ['#', 'Name', 'Mime', 'MD5', 'Tags']
        if key == 'latest':
            header.append('Created At')
        if key == 'ssdeep':
            header.append("Ssdeep")
        self.log("table", dict(header=header, rows=rows))


class Help(Command):
    ##
    # HELP
    #
    # This command simply prints the help message.
    # It lists both embedded commands and loaded modules.
    cmd = "help"
    description = "Show this help message"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        self.log('info', "Commands")

        rows = []
        for command_name, command_item in Commands().commands.items():
            rows.append([command_name, command_item['description']])

        rows.append(["exit, quit", "Exit Viper"])
        rows = sorted(rows, key=lambda entry: entry[0])

        self.log('table', dict(header=['Command', 'Description'], rows=rows))
        self.log('info', "Modules")

        rows = []
        for module_name, module_item in __modules__.items():
            rows.append([module_name, module_item['description']])

        rows = sorted(rows, key=lambda entry: entry[0])

        self.log('table', dict(header=['Command', 'Description'], rows=rows))


class Info(Command):
    ##
    # INFO
    #
    # This command returns information on the open session. It returns details
    # on the file (e.g. hashes) and other information that might available from
    # the database.
    cmd = "info"
    description = "Show information on the opened file"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if __sessions__.is_set():
            self.log('table', dict(
                header=['Key', 'Value'],
                rows=[
                    ['Name', __sessions__.current.file.name],
                    ['Tags', __sessions__.current.file.tags],
                    ['Path', __sessions__.current.file.path],
                    ['Size', __sessions__.current.file.size],
                    ['Type', __sessions__.current.file.type],
                    ['Mime', __sessions__.current.file.mime],
                    ['MD5', __sessions__.current.file.md5],
                    ['SHA1', __sessions__.current.file.sha1],
                    ['SHA256', __sessions__.current.file.sha256],
                    ['SHA512', __sessions__.current.file.sha512],
                    ['SSdeep', __sessions__.current.file.ssdeep],
                    ['CRC32', __sessions__.current.file.crc32],
                    ['Parent', __sessions__.current.file.parent],
                    ['Children', __sessions__.current.file.children]
                ]
            ))


class New(Command):
    ##
    # NEW
    #
    # This command is used to create a new session on a new file,
    # useful for copy & paste of content like Email headers
    cmd = "new"
    description = "Create new file"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        title = input("Enter a title for the new file: ")
        # Create a new temporary file.
        tmp = tempfile.NamedTemporaryFile(delete=False)
        # Open the temporary file with the default editor, or with nano.
        os.system('"${EDITOR:-nano}" ' + tmp.name)
        __sessions__.new(tmp.name)
        __sessions__.current.file.name = title
        self.log('info', "New file with title \"{0}\" added to the current session".format(bold(title)))


class Notes(Command):
    ##
    # NOTES
    #
    # This command allows you to view, add, modify and delete notes associated
    # with the currently opened file.
    cmd = "notes"
    description = "View, add and edit notes on the opened file"

    def __init__(self):
        super(Notes, self).__init__()
        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true', help="List all notes available for the current file")
        group.add_argument('-a', '--add', action='store_true', help="Add a new note to the current file")
        group.add_argument('-v', '--view', metavar='NOTE ID', type=int, help="View the specified note")
        group.add_argument('-e', '--edit', metavar='NOTE ID', type=int, help="Edit an existing note")
        group.add_argument('-d', '--delete', metavar='NOTE ID', type=int, help="Delete an existing note")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        # check if the file is already stores, otherwise exit as no notes command will work if the file is not stored in the database
        malware = db.find(key='sha256', value=__sessions__.current.file.sha256)
        if not malware:
            self.log('error', "The opened file doesn't appear to be in the database, have you stored it yet?")
            return

        if args.list:
            # Retrieve all notes for the currently opened file.

            notes = malware[0].note
            if not notes:
                self.log('info', "No notes available for this file yet")
                return

            # Populate table rows.
            rows = [[note.id, note.title] for note in notes]

            # Display list of existing notes.
            self.log('table', dict(header=['ID', 'Title'], rows=rows))

        elif args.add:
            title = input("Enter a title for the new note: ")

            # Create a new temporary file.
            with tempfile.NamedTemporaryFile(mode='w+') as tmp:
                # Open the temporary file with the default editor, or with nano.
                os.system('"${EDITOR:-nano}" ' + tmp.name)
                # Once the user is done editing, we need to read the content and
                # store it in the database.
                body = tmp.read()
                db.add_note(__sessions__.current.file.sha256, title, body)

            self.log('info', 'New note with title "{0}" added to the current file'.format(bold(title)))

        elif args.view:
            # Retrieve note wth the specified ID and print it.
            note = db.get_note(args.view)
            if note:
                self.log('info', bold('Title: ') + note.title)
                if isinstance(note.body, bytes):
                    # OLD: Old style, the content is stored as bytes
                    # This is fixed when the user edits the old note.
                    body = note.body.decode()
                else:
                    body = note.body
                self.log('info', '{}\n{}'.format(bold('Body:'), body))
            else:
                self.log('info', "There is no note with ID {0}".format(args.view))

        elif args.edit:
            # Retrieve note with the specified ID.
            note = db.get_note(args.edit)
            if note:
                # Create a new temporary file.
                with tempfile.NamedTemporaryFile(mode='w+') as tmp:
                    # Write the old body to the temporary file.
                    if isinstance(note.body, bytes):
                        # OLD: Old style, the content is stored as bytes
                        body = note.body.decode()
                    else:
                        body = note.body
                    tmp.write(body)
                    tmp.flush()
                    tmp.seek(0)
                    # Open the old body with the text editor.
                    os.system('"${EDITOR:-nano}" ' + tmp.name)
                    # Read the new body from the temporary file.
                    body = tmp.read()
                    # Update the note entry with the new body.
                    db.edit_note(args.edit, body)

                self.log('info', "Updated note with ID {0}".format(args.edit))

        elif args.delete:
            # Delete the note with the specified ID.
            db.delete_note(args.delete)
        else:
            self.parser.print_usage()


class Open(Command):
    ##
    # OPEN
    #
    # This command is used to open a session on a given file.
    # It either can be an external file path, or a SHA256 hash of a file which
    # has been previously imported and stored.
    # While the session is active, every operation and module executed will be
    # run against the file specified.
    cmd = "open"
    description = "Open a file"
    fs_path_completion = True

    def __init__(self):
        super(Open, self).__init__()
        self.parser = argparse.ArgumentParser(prog=self.cmd, description=self.description,
                                              epilog="You can also specify a MD5 or SHA256 hash to a previously stored file in order to open a session on it.")

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-f', '--file', action='store_true', help="Target is a file")
        group.add_argument('-u', '--url', action='store_true', help="Target is a URL")
        group.add_argument('-l', '--last', action='store_true', help="Target is the entry number from the last find command's results")
        self.parser.add_argument('-t', '--tor', action='store_true', help="Download the file through Tor")
        self.parser.add_argument("value", metavar='PATH, URL, HASH or ID', nargs='*', help="Target to open. Hash can be md5 or sha256. ID has to be from the last search.")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        target = " ".join(args.value)

        if not args.last and target is None:
            self.parser.print_usage()
            return

        # If it's a file path, open a session on it.
        if args.file:
            target = os.path.expanduser(target)

            if not os.path.exists(target) or not os.path.isfile(target):
                self.log('error', "File not found: {0}".format(target))
                return

            __sessions__.new(target)
        # If it's a URL, download it and open a session on the temporary file.
        elif args.url:
            data = download(url=target, tor=args.tor)

            if data:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.write(data)
                tmp.close()

                __sessions__.new(tmp.name)
        # Try to open the specified file from the list of results from
        # the last find command.
        elif args.last:
            if __sessions__.find:
                try:
                    target = int(target)
                except ValueError:
                    self.log('warning', "Please pass the entry number from the last find to -l/--last (e.g. open -l 5)")
                    return

                for idx, item in enumerate(__sessions__.find, start=1):
                    if idx == target:
                        __sessions__.new(get_sample_path(item.sha256))
                        break
            else:
                self.log('warning', "You haven't performed a find yet")
        # Otherwise we assume it's an hash of an previously stored sample.
        else:
            target = target.strip().lower()

            if len(target) == 32:
                key = 'md5'
            elif len(target) == 64:
                key = 'sha256'
            else:
                self.parser.print_usage()
                return

            rows = db.find(key=key, value=target)

            if not rows:
                self.log('warning', "No file found with the given hash {0}".format(target))
                return

            path = get_sample_path(rows[0].sha256)
            if path:
                __sessions__.new(path)


class Parent(Command):
    ##
    # PARENT
    #
    # This command is used to view or edit the parent child relationship between files.
    cmd = "parent"
    description = "Add or remove a parent file"

    def __init__(self):
        super(Parent, self).__init__()

        self.parser.add_argument('-a', '--add', metavar='SHA256', help="Add parent file by sha256")
        self.parser.add_argument('-d', '--delete', action='store_true', help="Delete Parent")
        self.parser.add_argument('-o', '--open', action='store_true', help="Open The Parent")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            self.log('error', "No open session")
            self.parser.print_usage()
            return

        # If no arguments are specified, there's not much to do.
        if args.add is None and args.delete is None and args.open is None:
            self.parser.print_usage()
            return

        if not db.find(key='sha256', value=__sessions__.current.file.sha256):
            self.log('error', "The opened file is not stored in the database. "
                              "If you want to add it use the `store` command.")
            return

        if args.add:
            if not db.find(key='sha256', value=args.add):
                self.log('error', "the parent file is not found in the database. ")
                return
            db.add_parent(__sessions__.current.file.sha256, args.add)
            self.log('info', "parent added to the currently opened file")

            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if args.delete:
            db.delete_parent(__sessions__.current.file.sha256)
            self.log('info', "parent removed from the currently opened file")

            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if args.open:
            # Open a session on the parent
            if __sessions__.current.file.parent:
                __sessions__.new(get_sample_path(__sessions__.current.file.parent[-64:]))
            else:
                self.log('info', "No parent set for this sample")


class Projects(Command):
    ##
    # PROJECTS
    #
    # This command retrieves a list of all projects.
    # You can also switch to a different project.
    cmd = "projects"
    description = "List or switch existing projects"

    def __init__(self):
        super(Projects, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true', help="List all existing projects")
        group.add_argument('-s', '--switch', metavar='PROJECT NAME', help="Switch to the specified project")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if cfg.get('paths').storage_path:
            base_path = cfg.get('paths').storage_path
        else:
            base_path = os.path.join(expanduser("~"), '.viper')

        projects_path = os.path.join(base_path, 'projects')

        if args.list:
            if not os.path.exists(projects_path):
                self.log('info', "The projects directory does not exist yet")
                return

            self.log('info', "Projects Available:")

            rows = []
            for project in os.listdir(projects_path):
                project_path = os.path.join(projects_path, project)
                if os.path.isdir(project_path):
                    current = ''
                    if __project__.name and project == __project__.name:
                        current = 'Yes'
                    rows.append([project, time.ctime(os.path.getctime(project_path)), current])

            self.log('table', dict(header=['Project Name', 'Creation Time', 'Current'], rows=rows))
        elif args.switch:
            if __sessions__.is_set():
                __sessions__.close()
                self.log('info', "Closed opened session")

            __project__.open(args.switch)
            self.log('info', "Switched to project {0}".format(bold(args.switch)))

            # Need to re-initialize the Database to open the new SQLite file.
            db.__init__()
        else:
            self.log('info', self.parser.print_usage())


class Rename(Command):
    ##
    # RENAME
    #
    # This command renames the currently opened file in the database.
    cmd = "rename"
    description = "Rename the file in the database"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if __sessions__.is_set():
            if not __sessions__.current.file.id:
                self.log('error', "The opened file does not have an ID, have you stored it yet?")
                return

            self.log('info', "Current name is: {}".format(bold(__sessions__.current.file.name)))

            new_name = input("New name: ")
            if not new_name:
                self.log('error', "File name can't  be empty!")
                return

            db.rename(__sessions__.current.file.id, new_name)

            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)
        else:
            self.log('error', "No open session")


class Sessions(Command):
    ###
    # SESSION
    #
    # This command is used to list and switch across all the opened sessions.
    cmd = "sessions"
    description = "List or switch sessions"

    def __init__(self):
        super(Sessions, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true', help="List all existing sessions")
        group.add_argument('-s', '--switch', type=int, help="Switch to the specified session")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if args.list:
            if not __sessions__.sessions:
                self.log('info', "There are no opened sessions")
                return

            rows = []
            for session in __sessions__.sessions:
                current = ''
                if session == __sessions__.current:
                    current = 'Yes'

                rows.append([
                    session.id,
                    session.file.name,
                    session.file.md5,
                    session.created_at,
                    current
                ])

            self.log('info', "Opened Sessions:")
            self.log("table", dict(header=['#', 'Name', 'MD5', 'Created At', 'Current'], rows=rows))
        elif args.switch:
            for session in __sessions__.sessions:
                if args.switch == session.id:
                    __sessions__.switch(session)
                    return

            self.log('warning', "The specified session ID doesn't seem to exist")
        else:
            self.parser.print_usage()


class Stats(Command):
    ##
    # STATS
    #
    # This command allows you to generate basic statistics for the stored files.
    cmd = "stats"
    description = "Viper Collection Statistics"

    def __init__(self):
        super(Stats, self).__init__()

        self.parser.add_argument('-t', '--top', type=int, help='Top x Items')

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # Set all Counters Dict
        extension_dict = defaultdict(int)
        mime_dict = defaultdict(int)
        tags_dict = defaultdict(int)
        size_list = []

        # Find all
        items = db.find('all')

        if len(items) < 1:
            self.log('info', "No items in database to generate stats")
            return

        # Sort in to stats
        for item in items:
            if isinstance(item.name, bytes):
                # NOTE: In case you there are names stored as bytes in the database
                name = item.name.decode()
            else:
                name = item.name
            if '.' in name:
                ext = name.split('.')
                extension_dict[ext[-1]] += 1
            mime_dict[item.mime] += 1
            size_list.append(item.size)
            for t in item.tag:
                if t.tag:
                    tags_dict[t.tag] += 1

        avg_size = sum(size_list) / len(size_list)
        # all_stats = {'Total': len(items), 'File Extension': extension_dict, 'Mime': mime_dict, 'Tags': tags_dict,
        #             'Avg Size': avg_size, 'Largest': max(size_list), 'Smallest': min(size_list)}

        # Counter for top x
        if args.top:
            counter = args.top
            prefix = 'Top {0} '.format(counter)
        else:
            counter = len(items)
            prefix = ''

        # Project Stats Last as i have it iterate them all

        # Print all the results

        self.log('info', "Projects")
        self.log('table', dict(header=['Name', 'Count'], rows=[['Main', len(items)], ['Next', '10']]))

        # For Current Project
        self.log('info', "Current Project")

        # Extension
        self.log('info', "{0}Extensions".format(prefix))
        header = ['Ext', 'Count']
        rows = []

        for k in sorted(extension_dict, key=extension_dict.get, reverse=True)[:counter]:
            rows.append([k, extension_dict[k]])
        self.log('table', dict(header=header, rows=rows))

        # Mimes
        self.log('info', "{0}Mime Types".format(prefix))
        header = ['Mime', 'Count']
        rows = []
        for k in sorted(mime_dict, key=mime_dict.get, reverse=True)[:counter]:
            rows.append([k, mime_dict[k]])
        self.log('table', dict(header=header, rows=rows))

        # Tags
        self.log('info', "{0}Tags".format(prefix))
        header = ['Tag', 'Count']
        rows = []
        for k in sorted(tags_dict, key=tags_dict.get, reverse=True)[:counter]:
            rows.append([k, tags_dict[k]])
        self.log('table', dict(header=header, rows=rows))

        # Size
        self.log('info', "Size Stats")
        self.log('item', "Largest  {0}".format(convert_size(max(size_list))))
        self.log('item', "Smallest  {0}".format(convert_size(min(size_list))))
        self.log('item', "Average  {0}".format(convert_size(avg_size)))


class Store(Command):
    ##
    # STORE
    #
    # This command stores the opened file in the local repository and tries
    # to store details in the database.
    cmd = "store"
    description = "Store the opened file to the local repository"
    fs_path_completion = True

    def __init__(self):
        super(Store, self).__init__()

        self.parser.add_argument('-d', '--delete', action='store_true', help="Delete the original file")
        self.parser.add_argument('-f', '--folder', type=str, nargs='+', help="Specify a folder to import")
        self.parser.add_argument('-s', '--file-size', type=int, help="Specify a maximum file size")
        self.parser.add_argument('-y', '--file-type', type=str, help="Specify a file type pattern")
        self.parser.add_argument('-n', '--file-name', type=str, help="Specify a file name pattern")
        self.parser.add_argument('-t', '--tags', type=str, nargs='+', help="Specify a list of comma-separated tags")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if args.folder is not None:
            # Allows to have spaces in the path.
            args.folder = " ".join(args.folder)

        if args.tags is not None:
            # Remove the spaces in the list of tags
            args.tags = "".join(args.tags)

        def add_file(obj, tags=None):
            if get_sample_path(obj.sha256):
                self.log('warning', "Skip, file \"{0}\" appears to be already stored".format(obj.name))
                return False

            if __sessions__.is_attached_misp(quiet=True):
                if tags is not None:
                    tags += ',misp:{}'.format(__sessions__.current.misp_event.event.id)
                else:
                    tags = 'misp:{}'.format(__sessions__.current.misp_event.event.id)

            # Try to store file object into database.
            status = db.add(obj=obj, tags=tags)
            if status:
                # If succeeds, store also in the local repository.
                # If something fails in the database (for example unicode strings)
                # we don't want to have the binary lying in the repository with no
                # associated database record.
                new_path = store_sample(obj)
                self.log("success", "Stored file \"{0}\" to {1}".format(obj.name, new_path))

            else:
                return False

            # Delete the file if requested to do so.
            if args.delete:
                try:
                    os.unlink(obj.path)
                except Exception as e:
                    self.log('warning', "Failed deleting file: {0}".format(e))

            return True

        # If the user specified the --folder flag, we walk recursively and try
        # to add all contained files to the local repository.
        # This is note going to open a new session.
        # TODO: perhaps disable or make recursion optional?
        if args.folder is not None:
            # Check if the specified folder is valid.
            if os.path.isdir(args.folder):
                # Walk through the folder and subfolders.
                for dir_name, dir_names, file_names in walk(args.folder):
                    # Add each collected file.
                    for file_name in file_names:
                        file_path = os.path.join(dir_name, file_name)

                        if not os.path.exists(file_path):
                            continue
                        # Check if file is not zero.
                        if not os.path.getsize(file_path) > 0:
                            continue

                        # Check if the file name matches the provided pattern.
                        if args.file_name:
                            if not fnmatch.fnmatch(file_name, args.file_name):
                                # self.log('warning', "Skip, file \"{0}\" doesn't match the file name pattern".format(file_path))
                                continue

                        # Check if the file type matches the provided pattern.
                        if args.file_type:
                            if args.file_type not in File(file_path).type:
                                # self.log('warning', "Skip, file \"{0}\" doesn't match the file type".format(file_path))
                                continue

                        # Check if file exceeds maximum size limit.
                        if args.file_size:
                            # Obtain file size.
                            if os.path.getsize(file_path) > args.file_size:
                                self.log('warning', "Skip, file \"{0}\" is too big".format(file_path))
                                continue

                        file_obj = File(file_path)

                        # Add file.
                        add_file(file_obj, args.tags)
                        if add_file and cfg.get('autorun').enabled:
                            autorun_module(file_obj.sha256)
                            # Close the open session to keep the session table clean
                            __sessions__.close()

            else:
                self.log('error', "You specified an invalid folder: {0}".format(args.folder))
        # Otherwise we try to store the currently opened file, if there is any.
        else:
            if __sessions__.is_set():
                if __sessions__.current.file.size == 0:
                    self.log('warning', "Skip, file \"{0}\" appears to be empty".format(__sessions__.current.file.name))
                    return False

                # Add file.
                if add_file(__sessions__.current.file, args.tags):
                    # Open session to the new file.
                    Open().run(*[__sessions__.current.file.sha256])
                    if cfg.get('autorun').enabled:
                        autorun_module(__sessions__.current.file.sha256)
            else:
                self.log('error', "No open session")


class Tags(Command):
    ##
    # TAGS
    #
    # This command is used to modify the tags of the opened file.
    cmd = "tags"
    description = "Modify tags of the opened file"

    def __init__(self):
        super(Tags, self).__init__()

        self.parser.add_argument('-a', '--add', metavar='TAG', help="Add tags to the opened file (comma separated)")
        self.parser.add_argument('-d', '--delete', metavar='TAG', help="Delete a tag from the opened file")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            self.log('error', "No open session")
            self.parser.print_usage()
            return

        # If no arguments are specified, there's not much to do.
        # However, it could make sense to also retrieve a list of existing
        # tags from this command, and not just from the "find" command alone.
        if args.add is None and args.delete is None:
            self.parser.print_usage()
            return

        # TODO: handle situation where addition or deletion of a tag fail.

        if not db.find(key='sha256', value=__sessions__.current.file.sha256):
            self.log('error', "The opened file is not stored in the database. "
                     "If you want to add it use the `store` command.")
            return

        if args.add:
            # Add specified tags to the database's entry belonging to
            # the opened file.
            db.add_tags(__sessions__.current.file.sha256, args.add)
            self.log('info', "Tags added to the currently opened file")

            # We refresh the opened session to update the attributes.
            # Namely, the list of tags returned by the 'info' command
            # needs to be re-generated, or it wouldn't show the new tags
            # until the existing session is closed a new one is opened.
            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if args.delete:
            # Delete the tag from the database.
            db.delete_tag(args.delete, __sessions__.current.file.sha256)
            # Refresh the session so that the attributes of the file are
            # updated.
            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)
