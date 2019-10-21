"""Makefile dependency rule output plugin

"""

import optparse
import sys
import os.path
import codecs

from pyang import plugin
from pyang import error
from pyang import statements

from pyang.translators import yang


def pyang_plugin_init():
    plugin.register_plugin(ClearMustStatementsPlugin())


class ClearMustStatementsPlugin(plugin.PyangPlugin):
    def add_opts(self, optparser):
        g = optparser.add_option_group("Feature output specific options")

    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['clearmust'] = self

    def emit(self, ctx, modules, fd):
        # cannot do this unless everything is ok for our module
        modulenames = [m.arg for m in modules]
        for (epos, etag, eargs) in ctx.errors:
            if ((epos.top is None or epos.top.arg in modulenames) and
                    error.is_error(error.err_level(etag))):
                raise error.EmitError("%s contains errors" % epos.top.arg)
        emit_depend(ctx, modules, fd)


def emit_depend(ctx, modules, fd):
    context = clear_must_statements(ctx)

    yang_parser = yang.YANGPlugin()
    for mod in context.modules.values():
        fd_for_module = codecs.open(mod.arg + '.yang', "w", encoding="utf-8")
        mod.i_ctx = context
        modules_list = [mod]
        yang_parser.emit(context, modules_list, fd_for_module)
        fd_for_module.close()


def clear_must_statements(ctx):
    for module in ctx.modules.values():
        process_children(module)
        proces_groupings(module)

    return ctx


def proces_groupings(module):
    for grouping in module.i_groupings.values():
        process_children(grouping)


def process_children(node):
    if node.i_children is None or len(node.i_children) == 0:
        return
    else:
        for child in node.i_children:
            remove_must_from_node(child)


def remove_must_from_node(node):
    if type(node) is statements.ContainerStatement:
        must_statement = node.search_one('must')
        if must_statement is not None:
            node.substmts.remove(must_statement)
        process_children(node)
    elif type(node) is statements.ListStatement:
        must_statement = node.search_one('must')
        if must_statement is not None:
            node.substmts.remove(must_statement)
        process_children(node)
    elif type(node) is statements.LeafLeaflistStatement:
        must_statement = node.search_one('must')
        if must_statement is not None:
            node.substmts.remove(must_statement)
