"""Makefile dependency rule output plugin

"""

import optparse
import sys
import os.path

from pyang import plugin
from pyang import error, statements


def pyang_plugin_init():
    plugin.register_plugin(ListFeaturePlugin())


class ListFeaturePlugin(plugin.PyangPlugin):
    def add_opts(self, optparser):
        optlist = [
            optparse.make_option("--submodule-only",
                                 action="store_true",
                                 dest="submoduleonly",
                                 default=False,
                                 help="Return 'True' if only submodules are defined in model"
                                      "and 'False' if module is defined inside model"),
        ]
        g = optparser.add_option_group("Feature output specific options")
        g.add_options(optlist)

    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['submodule'] = self

    def emit(self, ctx, modules, fd):

        # cannot do this unless everything is ok for our module
        modulenames = [m.arg for m in modules]
        for (epos, etag, eargs) in ctx.errors:
            if ((epos.top is None or epos.top.arg in modulenames) and
                    error.is_error(error.err_level(etag))):
                raise error.EmitError("%s contains errors" % epos.top.arg)
        emit_depend(ctx, modules, fd)


def emit_depend(ctx, modules, fd):
    is_bool = True
    for module in modules:
        if module.keyword == 'module':
            is_bool = False
            break

    fd.write('%s\n' % is_bool)
