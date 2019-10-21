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
            optparse.make_option("--is-type-only",
                                 action="store_true",
                                 dest="typeonly",
                                 default=False,
                                 help="Return 'True' if module only defines types"
                                      "and 'False' if module contains leafs"),
        ]
        g = optparser.add_option_group("Feature output specific options")
        g.add_options(optlist)

    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['listfeature'] = self

    def emit(self, ctx, modules, fd):

        # cannot do this unless everything is ok for our module
        modulenames = [m.arg for m in modules]
        for (epos, etag, eargs) in ctx.errors:
            if ((epos.top is None or epos.top.arg in modulenames) and
                    error.is_error(error.err_level(etag))):
                raise error.EmitError("%s contains errors" % epos.top.arg)
        emit_depend(ctx, modules, fd)


def emit_depend(ctx, modules, fd):
    for module in modules:
        if ctx.opts.typeonly is False:
            for feature in module.i_features:
                fd.write('%s\n' % feature)
        else:
            is_bool = True
            for kid in module.i_children:
                if type(kid) == statements.ListStatement or \
                        type(kid) == statements.ContainerStatement or \
                        type(kid) == statements.LeafLeaflistStatement:
                    is_bool = False
                    break
            fd.write('%s\n' % is_bool)
