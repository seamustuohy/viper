# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

'''
Code based on the python-oletools package by Philippe Lagadec 2012-10-18
http://www.decalage.info/python/oletools
'''

import os
import struct
import zipfile
import xml.etree.ElementTree as ET
import sys

from viper.common.utils import string_clean, string_clean_hex
from viper.common.abstracts import Module
from viper.core.session import __sessions__

from io import BytesIO, open

try:
    from oletools import rtfobj
    HAVE_RTFOBJ = True
except ImportError:
    HAVE_RTFOBJ = False

class RTF(Module):
    cmd = 'rtf'
    description = 'Rich Text Format (RTF)'
    authors = ['seamus tuohy']

    def __init__(self):
        super(Office, self).__init__()
        self.parser.add_argument('-m', '--meta', action='store_true', help='Get the metadata')
        self.parser.add_argument('-o', '--oleid', action='store_true', help='Get the OLE information')
        self.parser.add_argument('-s', '--streams', action='store_true', help='Show the document streams')
        self.parser.add_argument('-e', '--export', metavar='dump_path', help='Export all objects')
        self.parser.add_argument('-v', '--vba', action='store_true', help='Analyse Macro Code')
        self.parser.add_argument('-c', '--code', metavar="code_path", help='Export Macro Code to File')
        self.parser.add_argument('-d', '--dde', action='store_true', help='Get DDE Links')

    # Main starts here
    def run(self):
        super(RTF, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return

        if not HAVE_RTFOBJ:
            self.log('error', "Missing dependency, install rtfobj (`pip install olefile oletools`)")
            return

        file_data = __sessions__.current.file.data

        rtfp = RtfObjParser(file_data)
        rtfp.parse()

        # header = ['#', 'Object ID', 'Size', 'Type']
        # if arg_dump or arg_open:
        #     header.append('Dumped To')
        # self.log('table', dict(header=header, rows=streams))
        # rtf_objects = {}
        # rtf_packages = {
        #     "title":"OLE Package objects",
        #     "headers":["Filename", "Source path", "Temp path", "File extension", "Is Executable"],
        #     "objects":[]}
        # rtf_ole_object = {
        #     "title":"OLE Package objects",
        #     "headers":["Filename", "Source path", "Temp path", "File extension", "Is Executable"],
        #     "objects":[]}

        # ole_obj_base_headers = ['Format Id', 'Format Type', 'Class Name','Data Size']


        for rtfobj in rtfp.objects:
            cur_rtf = {}
            cur_rtf['ID'] = rtfp.objects.index(rtfobj)
            cur_rtf['index'] = '{:08X}h'.format(rtfobj.start)
            if rtfobj.is_ole:
                cur_rtf['Format Id'] = rtfobj.format_id
                cur_rtf['Format Type'] =
                if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                    cur_rtf['Format Type'] = 'Embedded'
                elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                    cur_rtf['Format Type'] = 'Linked'
                else:
                    cur_rtf['Format Type'] = 'Unknown'
                cur_rtf['Class Name'] = rtfobj.class_name

                # if the object is linked and not embedded, data_size=None:
                if rtfobj.oledata_size is None:
                    cur_rtf['Data Size'] = 'N/A'
                else:
                    cur_rtf['Data Size'] = rtfobj.oledata_size
                if rtfobj.is_package:
                    cur_rtf['Is Package'] = True
                    cur_rtf["Filename"] = rtfobj.filename
                    cur_rtf["Source path"] = rtfobj.src_path
                    cur_rtf["Temp path"] = rtfobj.temp_path
                    # check if the file extension is executable:
                    _, ext = os.path.splitext(rtfobj.filename)
                    cur_rtf["File extension"] = ext
                    if re_executable_extensions.match(ext):
                        cur_rtf["Is Executable"] = True
                    else:
                        cur_rtf["Is Executable"] = False
                else:
                    cur_rtf['Is Package'] = False

                if rtfobj.clsid is not None:
                    # A CLSID is a globally unique identifier that identifies a COM class object.
                    # https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf
                    # https://medium.com/@Sebdraven/a-quick-analysis-malicious-rtf-to-write-yara-rule-part-1-234fa34db551
                    cur_rtf['CLSID'] = rtfobj.clsid
                    cur_rtf['CLSID Description'] = rtfobj.clsid_desc
                    if 'CVE' in rtfobj.clsid_desc:
                        cur_rtf['Has_CVE'] = True
                    else:
                        cur_rtf['Has_CVE'] = False
                # Detect OLE2Link exploit
                # http://www.kb.cert.org/vuls/id/921560
                if rtfobj.class_name == b'OLE2Link':
                    cur_rtf.setdefault('warn', {})
                    cur_rtf['warn']['Possible OLE2Link'] = 'Possibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)'
            else:
                cur_rtf.setdefault('Warn', {})
                cur_rtf['warn']['Malformed OLE object'] = 'Not a well-formed OLE object'
