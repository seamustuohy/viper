# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import sys

import pytest

from tests.conftest import FIXTURE_DIR

from viper.modules import apk
from viper.modules.apk import HAVE_ANDROGUARD
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__


class TestAPK:
    def teardown_method(self):
        __sessions__.close()

    def test_init(self):
        instance = apk.AndroidPackage()
        assert isinstance(instance, apk.AndroidPackage)
        assert isinstance(instance, Module)

    def test_androguard_installed(self):
        assert HAVE_ANDROGUARD is True

    # def test_androguard_not_installed(self):
    #     # assert HAVE_ANDROGUARD is True
    #     HAVE_ANDROGUARD = False
    #     instance = apk.AndroidPackage()
    #     assert isinstance(instance, apk.AndroidPackage)
    #     assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = apk.AndroidPackage()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Parse Android Applications.*")

    def test_no_session(self, capsys):
        instance = apk.AndroidPackage()
        instance.command_line = ["-i"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*No open session.*", out)
        # assert out == ""

    @pytest.mark.parametrize("filename", ["hello-world.apk"])
    def test_info(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-i"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Package Name: de.rhab.helloworld*", out)

    @pytest.mark.parametrize("filename", ["hello-world.apk"])
    def test_perm(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-p"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*APK Permissions.*", out)

    @pytest.mark.parametrize("filename", ["hello-world.apk"])
    def test_file(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-f"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*APK Contents.*", out)

    @pytest.mark.parametrize("filename", ["hello-world.apk"])
    def test_url(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-u"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*http://schemas.android.com/apk/res/android.*", out)
        assert not re.search(r".*http://foo.example.bar.*", out)

    @pytest.mark.parametrize("filename", ["hello-world.apk"])
    def test_cert(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-c"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r"SHA1: 65 2F 61 29 C8 7D 05 40 BF 98 6F C0 0E FD 9A B8 A7 87 84 DE", out)
        assert re.search(r"SHA256: 6E 56 64 27 DA 36 DD 91 36 39 B1 11 2F 74 7B 77 40 88 51 B4 85 7A 1D 63 EB F9 1E 02 B0 6F 20 88", out)

    @pytest.mark.parametrize("filename,pkg_name", [("hello-world.apk", "de.rhab.helloworld")])
    def test_all(self, capsys, filename, pkg_name):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-a"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Package Name: {}.*".format(pkg_name), out)

    @pytest.mark.parametrize("filename", ["hello-world.apk"])
    def test_dump_no_parameter(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-d"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*argument -d/--dump: expected one argument.*", out)

    @pytest.mark.skipif(sys.version_info < (3, 3), reason="Too slow on python2.7, makes travis fail.")
    @pytest.mark.skipif(sys.version_info >= (3, 3), reason="Uses way too much memory. Running the same commands in the client works fine...")
    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["hello-world.apk"])
    def test_dump(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = apk.AndroidPackage()
        instance.command_line = ["-d hello-world.dump"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Decompiling Code.*", out)
        assert re.search(r".*Decompiled code saved to.*", out)
