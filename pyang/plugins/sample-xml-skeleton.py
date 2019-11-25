# Copyright (c) 2014 by Ladislav Lhotka, CZ.NIC <lhotka@nic.cz>
#
# Pyang plugin generating a sample XML instance document..
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""sample-xml-skeleton output plugin

This plugin takes a YANG data model and generates an XML instance
document containing sample elements for all data nodes.

* An element is present for every leaf, container or anyxml.

* At least one element is present for every leaf-list or list. The
  number of entries in the sample is min(1, min-elements).

* For a choice node, sample element(s) are present for each case.

* Leaf, leaf-list and anyxml elements are empty (exception:
  --sample-xml-skeleton-defaults option).
"""

import sys
import optparse
from lxml import etree
import copy

from pyang import plugin, error, statements, xpath_parser, util, xpath

from pyang import types as pType
from random import choice, randrange, getrandbits, randint
from string import ascii_uppercase
import uuid
import rstr
import datetime
import exrex
import re
from ipaddress import IPv4Address, IPv6Address
import base64


def pyang_plugin_init():
    plugin.register_plugin(SampleXMLSkeletonPlugin())


def make_target_for_xpath(target, current_node):
    if target[0] == '/':
        target = './' + target
    else:
        target = target.replace("../", "")
        target = './/' + target

    target = re.sub('/[^:^/]+:', '/', target)
    target = re.sub('\[[^:^\]]+:', '[', target)

    current_index = target.find('current()/')
    if current_index > 0:
        last_index = target.find(']', current_index)
        beginning_index = current_index + len('current()/')
        path = target[beginning_index:last_index]
        target_node = current_node
        for step in path.split('/'):
            if step == '..':
                target_node = target_node.getparent()
            else:
                for kid in target_node:
                    if kid.tag == step:
                        target_node = kid
                        break
                break
        target = "'".join((target[:current_index], target_node.text, target[last_index:]))

    return target


def generate_random_ipaddr(version):
    if version == 4:
        bits = getrandbits(32)  # generates an integer with 32 random bits
        addr = IPv4Address(bits)  # instances an IPv4Address object from those bits
        addr_str = str(addr)  # get the IPv4Address object's string representation
    elif version == 6:
        bits = getrandbits(128)  # generates an integer with 128 random bits
        addr = IPv6Address(bits)  # instances an IPv6Address object from those bits
        # .compressed contains the short version of the IPv6 address
        # str(addr) always returns the short address
        # .exploded is the opposite of this, always returning the full address with all-zero groups and so on
        addr_str = addr.compressed
    return addr_str


def generate_random_macaddr():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (randint(0, 255),
                             randint(0, 255),
                             randint(0, 255),
                             randint(0, 255),
                             randint(0, 255),
                             randint(0, 255))


def is_when_statement_present(node):
    when_statement = node.search_one('when')
    if when_statement is not None:
        return when_statement, node
    if hasattr(node, 'i_augment') and node.i_augment is not None:
        when_statement = node.i_augment.search_one('when')
        if when_statement is not None:
            return when_statement, node.i_augment.i_target_node
    if node.parent is not None:
        return is_when_statement_present(node.parent)
    else:
        return None, None


def verify_when_in_xml(target_node_name, target_node_module, node_value, xml_node, eq):
    where_to_find = xml_node
    while where_to_find is not None:
        target_node = where_to_find.find('.//' + target_node_name)
        if target_node is not None:
            break
        where_to_find = where_to_find.getparent()

    if eq == '=':
        return target_node.text == node_value
    elif eq == '!=':
        return target_node.text != node_value


def delete_remaining_leafrefs(root):

    for child in root.getiterator():
        if child.text is not None and "leafref" in child.text:
            parent = child.getparent()
            parent.remove(child)


def verify_xml_xpath_expr(returned_xpath, xml_node):
    if returned_xpath is None:
        return False
    if returned_xpath['type'] == 'comp' or returned_xpath['type'] == 'comp_idref':
        return verify_when_in_xml(returned_xpath['name'], returned_xpath['module'], returned_xpath['value'],
                                  xml_node, returned_xpath['operator'])
    elif returned_xpath['type'] == 'bool':
        operand_1 = returned_xpath['operand_1']
        operand_2 = returned_xpath['operand_2']
        if operand_1 is None or operand_2 is None:
            return False
        if returned_xpath['pred'] == 'or':
            return verify_xml_xpath_expr(operand_1, xml_node) or \
                   verify_xml_xpath_expr(operand_2, xml_node)
        elif returned_xpath['pred'] == 'and':
            return verify_xml_xpath_expr(operand_1, xml_node) and \
                   verify_xml_xpath_expr(operand_2, xml_node)


class SampleXMLSkeletonPlugin(plugin.PyangPlugin):

    def add_opts(self, optparser):
        optlist = [
            optparse.make_option("--sample-xml-skeleton-doctype",
                                 dest="doctype",
                                 default="data",
                                 help="Type of sample XML document " +
                                      "(data or config)."),
            optparse.make_option("--sample-xml-skeleton-defaults",
                                 action="store_true",
                                 dest="sample_defaults",
                                 default=False,
                                 help="Insert leafs with defaults values."),
            optparse.make_option("--sample-xml-skeleton-annotations",
                                 action="store_true",
                                 dest="sample_annots",
                                 default=False,
                                 help="Add annotations as XML comments."),
            optparse.make_option("--sample-xml-skeleton-path",
                                 dest="sample_path",
                                 help="Subtree to print"),
            optparse.make_option("--sample-xml-list-entries",
                                 dest="list_entries",
                                 type="int",
                                 action="store",
                                 default=1,
                                 help="Number of entries in list, if minimum is not defined in the YANG model"),
        ]
        g = optparser.add_option_group(
            "Sample-xml-skeleton output specific options")
        g.add_options(optlist)

    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['sample-xml-skeleton'] = self

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):
        """Main control function.

        Set up the top-level parts of the sample document, then process
        recursively all nodes in all data trees, and finally emit the
        sample XML document.
        """
        if ctx.opts.sample_path is not None:
            path = ctx.opts.sample_path.split('/')
            if path[0] == '':
                path = path[1:]
        else:
            path = []

        for (epos, etag, eargs) in ctx.errors:
            if error.is_error(error.err_level(etag)):
                raise error.EmitError(
                    "sample-xml-skeleton plugin needs a valid module")
        self.doctype = ctx.opts.doctype
        if self.doctype not in ("config", "data"):
            raise error.EmitError("Unsupported document type: %s" %
                                  self.doctype)
        self.annots = ctx.opts.sample_annots
        self.defaults = ctx.opts.sample_defaults
        self.node_handler = {
            "container": self.container,
            "leaf": self.leaf,
            "anyxml": self.anyxml,
            "choice": self.process_choice,
            "case": self.process_children,
            "list": self.list,
            "leaf-list": self.leaf_list
        }

        self.leaf_entries = ctx.opts.list_entries

        self.layer_protocol_name = ["OTU", "ODU", "ETH", "ETY", "MWPS", "MWS", "ETC"]
        self.excluded_modules = ["ietf-netconf-acm", "ietf-netconf-monitoring", "ietf-yang-library"]

        self.ctx = ctx

        self.constraints = []
        self.when_values = []

        for yam in modules:
            self.count_leafref_entries(yam)
            self.search_when_constraints(yam)

        # we generate the identityref values
        self.identity_refs = []
        self.generate_identity_refs(modules)

        self.ns_uri = {}
        for yam in modules:
            if yam.keyword == 'module':
                self.ns_uri[yam] = yam.search_one("namespace").arg

        self.top = etree.Element(
            self.doctype,
            {"xmlns": "urn:ietf:params:xml:ns:netconf:base:1.0"})
        tree = etree.ElementTree(self.top)
        for yam in modules:
            if yam.i_children is not None and len(yam.i_children) > 0 and yam.arg not in self.excluded_modules:
                res = etree.SubElement(self.top, yam.arg)
                self.process_children(yam, res, None, path)

        self.leafref_dict = {}
        # we need a second iteration through the model, to fill in the leafref elements
        # even a third iteration, if we have leafref to leafref
        root = tree.getroot()

        emergency_stop = 1
        while self.resolve_leafrefs(root, True) is True:
            emergency_stop += 1
            if emergency_stop > 1000:
                break
        while self.resolve_leafrefs(root, False) is True:
            emergency_stop += 1
            if emergency_stop > 1000:
                break

        # remove duplicate consecutive elements
        # need to check if it affects min-elements
        # should be applicable only for leafref elements, the others are
        # randomly generated and the probability of collision is low
        for child in root.getiterator():
            if child.text is not None:
                prev = child.getprevious()
                if prev is not None:
                    if child.text == prev.text and child.tag == prev.tag:
                        child.getparent().remove(child)

        if sys.version > "3":
            fd.write(str(etree.tostring(tree, pretty_print=True,
                                        encoding="UTF-8",
                                        xml_declaration=True), "UTF-8"))
        elif sys.version > "2.7":
            self.create_edit_config()
            #tree.write(fd, encoding="UTF-8", pretty_print=True,
            #           xml_declaration=False)
        else:
            tree.write(fd, pretty_print=True, encoding="UTF-8")

    def ignore(self, node, elem, module, path):
        """Do nothing for `node`."""
        pass

    def create_edit_config(self):
        edit_config = etree.Element(
            "edit-config",
            {"xmlns": "urn:ietf:params:xml:ns:netconf:base:1.0"})
        target = etree.SubElement(edit_config, "target")
        etree.SubElement(target, "running")
        config = etree.SubElement(edit_config, "config")
        for child in self.top:
            for kid in child:
                config.append(copy.deepcopy(kid))
        fd_for_module = open('edit_config_operation.xml', 'w')
        module_tree = etree.ElementTree(edit_config)
        module_tree.write(fd_for_module, encoding="UTF-8", pretty_print=True,
                          xml_declaration=False)

    def process_children(self, node, elem, module, path, omit=[]):
        """Proceed with all children of `node`."""
        for ch in node.i_children:
            if ch not in omit and (ch.i_config or self.doctype == "data"):
                self.node_handler.get(ch.keyword, self.ignore)(
                    ch, elem, module, path)

    def process_choice(self, node, elem, module, path, omit=[]):
        """Proceed with a random child of `node`."""
        ch = choice(node.i_children)
        while True:
            if ch not in omit and (ch.i_config or self.doctype == "data"):
                self.node_handler.get(ch.keyword, self.ignore)(
                    ch, elem, module, path)
                break
            else:
                ch = choice(node.i_children)

    def container(self, node, elem, module, path):
        """Create a sample container element and proceed with its children."""
        nel, newm, path = self.sample_element(node, elem, module, path)
        if path is None:
            return
        if nel is None:
            return
        if self.annots:
            pres = node.search_one("presence")
            if pres is not None:
                nel.append(etree.Comment(" presence: %s " % pres.arg))
        self.process_children(node, nel, newm, path)

    def leaf(self, node, elem, module, path):
        """Create a sample leaf element."""

        if node.i_default is None:
            nel, newm, path = self.sample_element(node, elem, module, path)
            if path is None:
                return
            if nel is None:
                return
            nel.text, nsmap = self.get_random_text(node, elem)
            if nsmap is not None:
                parent = nel.getparent()
                for i in range(0, len(parent)):
                    if parent[i].tag == nel.tag:
                        new_child = etree.Element(nel.tag, nsmap=nsmap)
                        new_child.text = nel.text
                        parent[i] = new_child
                        break
            if self.annots:
                nel.append(etree.Comment(
                    " type: %s " % node.search_one("type").arg))
        else:
            nel, newm, path = self.sample_element(node, elem, module, path)
            if path is None:
                return
            if nel is None:
                return
            if self.defaults:
                nel.text = str(node.i_default_str)
            else:
                nel.text, nsmap = self.get_random_text(node, elem)
                if nsmap is not None:
                    parent = nel.getparent()
                    for i in range(0, len(parent)):
                        if parent[i].tag == nel.tag:
                            new_child = etree.Element(nel.tag, nsmap=nsmap)
                            new_child.text = nel.text
                            parent[i] = new_child
                            break

    def anyxml(self, node, elem, module, path):
        """Create a sample anyxml element."""
        nel, newm, path = self.sample_element(node, elem, module, path)
        if path is None:
            return
        if nel is None:
            return
        if self.annots:
            nel.append(etree.Comment(" anyxml "))

    def list_base(self, node, elem, module, path, prev_keys=[]):
        """Create sample entries of a list."""
        nel, newm, path = self.sample_element(node, elem, module, path)
        if path is None:
            return
        if nel is None:
            return

        duplicate_key = False
        list_for_tuple = []
        for kn in node.i_key:
            self.node_handler.get(kn.keyword, self.ignore)(
                kn, nel, newm, path)
            if nel is not None:
                for kid in nel.getchildren():
                    if 'leafref' in kid.text:
                        break
                    else:
                        list_for_tuple.append(kid.text)

        keys_tuple = tuple(list_for_tuple)

        if len(prev_keys) == 0:
            if len(keys_tuple) > 0:
                prev_keys.append(keys_tuple)
        elif keys_tuple in prev_keys and len(keys_tuple) > 0:
            duplicate_key = True

        if duplicate_key:
            parent = nel.getparent()
            if parent is not None:
                parent.remove(nel)
        else:
            self.process_children(node, nel, newm, path, node.i_key)

    def list(self, node, elem, module, path):
        keys = []
        self.list_base(node, elem, module, path, prev_keys=keys)
        rep = self.get_num_reps(node)

        for i in range(0, rep):
            self.list_base(node, elem, module, path, keys)

    def get_num_reps(self, node):
        minel = node.search_one("min-elements")
        maxel = node.search_one('max-elements')

        #we hardcode some values here, regardless of other configuration
        #e.g.: layer-protocol we need to have only 1 entry!
        if node.arg == 'layer-protocol':
            return 0

        num_entries_constraint = 0
        for constraint in self.constraints:
            if constraint['module'] == node.i_module.arg and constraint['name'] == node.arg:
                num_entries_constraint = constraint['instances']
                break
        leaf_entries = max(num_entries_constraint, self.leaf_entries)
        # rep = 0 if minel is None else int(minel.arg) - 1
        if minel is None and maxel is None:
            # no min and max are set, we can have what the user suggested
            rep = leaf_entries
        elif minel is None:
            # we need to have a value lower than max
            rep = min(int(maxel.arg), leaf_entries)
        elif maxel is None:
            # we need to have a value higher than min
            rep = max(int(minel.arg), leaf_entries)
        else:
            # we need to check if value defined by user is between min and max
            rep = max(int(minel.arg), leaf_entries)
            rep = min(int(maxel.arg), rep)

        # we already have an entry in the list, this is the number of copies, thus we decrease one
        rep = rep - 1

        return rep

    def leaf_list(self, node, elem, module, path):
        self.leaf_list_base(node, elem, module, path)
        rep = self.get_num_reps(node)

        for i in range(0, rep):
            self.leaf_list_base(node, elem, module, path)

    def leaf_list_base(self, node, elem, module, path):
        """Create sample entries of a leaf-list."""
        nel, newm, path = self.sample_element(node, elem, module, path)
        if path is None:
            return
        if nel is None:
            return
        # self.list_comment(node, nel, minel)

        nel.text, nsmap = self.get_random_text(node, elem)
        if nsmap is not None:
            parent = nel.getparent()
            for i in range(0, len(parent)):
                if parent[i].tag == nel.tag:
                    new_child = etree.Element(nel.tag, nsmap=nsmap)
                    new_child.text = nel.text
                    parent[i] = new_child
                    break

    def sample_element(self, node, parent, module, path):
        """Create element under `parent`.

        Declare new namespace if necessary.
        """
        if parent is None:
            return None, module, path
        if path is None:
            return parent, module, None
        elif path == []:
            # GO ON
            pass
        else:
            if node.arg == path[0]:
                path = path[1:]
            else:
                return parent, module, None

        status = node.search_one("status")
        if status is not None:
            if status.arg == 'deprecated':
                return None, module, path

        # if the node is under a when statement, we just remove it from the generated XML
        when_statement, target_node = is_when_statement_present(node)
        if when_statement is not None:
            q = xpath_parser.parse(when_statement.arg)
            try:
                val = self.chk_xpath_expr(self.ctx, when_statement.i_orig_module,
                                        when_statement.pos, target_node, target_node, q)
                when_in_xml = verify_xml_xpath_expr(val, parent)
                if when_in_xml is False or when_in_xml is None:
                    return None, module, path

            except TypeError as exc:
                return None, module, path

        res = etree.SubElement(parent, node.arg)
        mm = node.main_module()
        if mm != module:
            res.attrib["xmlns"] = self.ns_uri[mm]
            module = mm
        #if when is not None:
        #    res.attrib['when'] = when
        return res, module, path

    def get_random_text(self, node, elem=None, ntype=None):
        if ntype is None:
            n_type = node.search_one("type")
        else:
            n_type = ntype

        if node.i_leafref is not None:
            # target = node.i_leafref.i_expanded_path
            # the above is buggy, we need to construct our own path with prefixes for the target leaf
            target = ''
            is_key = None
            if hasattr(node, 'i_is_key'):
                is_key = node.i_is_key
            # we iterate through all the nodes in the leafref
            for list_elem in node.i_leafref.i_path_list:
                # we extract the node element from the path_list
                target_node = list_elem[1]
                # we extract the prefix of the node
                target_node_prefix = target_node.i_module.i_prefix
                # we extract the node name
                target_node_name = target_node.arg
                if list_elem[0] == 'up':
                    #target = '../' + target
                    continue
                target = target + '/'
                # if we are in the same module as the target node, we do not add the prefix, it is redundant
                if target_node_prefix != node.i_module.i_prefix:
                    target = target + target_node_prefix + ':'
                # we append the node name
                target = target + target_node_name
            if hasattr(node.i_leafref, 'i_expanded_path'):
                target = node.i_leafref.i_expanded_path

            if is_key is True:
                return "leafrefkey:%s" % target, None
            return "leafref:%s" % target, None


        if n_type is not None:
            # search the "when" constraints for a value
            if node.arg is not None and node.i_module is not None and \
                    not isinstance(n_type.i_type_spec, pType.IdentityrefTypeSpec):
                value = self.get_when_entry(node.arg, node.i_module.arg)
                if value is not None:
                    return value, None

            if isinstance(n_type.i_type_spec, pType.EnumTypeSpec):
                randenum = choice(n_type.i_type_spec.enums)
                return randenum[0], None
            if isinstance(n_type.i_type_spec, pType.StringTypeSpec):
                if 'universal-id' in n_type.arg:
                    return str(uuid.uuid4()), None
                elif n_type.arg == 'layer-protocol-name':
                    return choice(self.layer_protocol_name), None
                else:
                    # we generate a random string with length between 5 and 20, domainsafe - letters, digits and "-"
                    rand_string = rstr.rstr(rstr.domainsafe(), 5, 20)
                    return rand_string, None
                    # return ''.join(choice(ascii_uppercase) for i in range(10))
            if isinstance(n_type.i_type_spec, pType.LengthTypeSpec):
                if isinstance(n_type.i_type_spec.base, pType.StringTypeSpec):
                    if len(n_type.i_type_spec.lengths) > 0:
                        min = n_type.i_type_spec.lengths[0][0]
                        max = n_type.i_type_spec.lengths[0][1]
                        if min == 'min':
                            min = 1
                        if max == 'max':
                            max = 255
                        rand_string = rstr.rstr(rstr.domainsafe(), min, max)
                        return rand_string, None
            elif isinstance(n_type.i_type_spec, pType.IntTypeSpec):
                return str(randrange(n_type.i_type_spec.min, n_type.i_type_spec.max)), None
            elif isinstance(n_type.i_type_spec, pType.BooleanTypeSpec):
                return choice(["true", "false"]), None
            elif isinstance(n_type.i_type_spec, pType.PatternTypeSpec):
                if 'date-and-time' in n_type.arg:
                    rand_datetime = datetime.datetime.utcnow() - datetime.timedelta(seconds=randrange(1, 59),
                                                                                    minutes=randrange(10, 59),
                                                                                    hours=randrange(0, 1000),
                                                                                    days=randrange(0,30))
                    rand_string = rand_datetime.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-5] + "Z"
                    return rand_string, None
                elif 'ipv4-address' in n_type.arg:
                    return generate_random_ipaddr(4), None
                elif 'ipv6-address' in n_type.arg:
                    return generate_random_ipaddr(6), None
                elif 'password-type' in n_type.arg:
                    regex = n_type.i_type_spec.res[0][4]
                    if isinstance(n_type.i_type_spec.base, pType.LengthTypeSpec):
                        if len(n_type.i_type_spec.base.lengths) > 0:
                            min = n_type.i_type_spec.base.lengths[0][0]
                            max = n_type.i_type_spec.base.lengths[0][1]
                            if min == 'min':
                                min = 1
                            if max == 'max':
                                max = 255
                            emergency_stop = 1
                            while True:
                                emergency_stop = emergency_stop + 1
                                if emergency_stop > 1000:
                                    break
                                rand_string = exrex.getone(regex)
                                if len(rand_string) > min and len(rand_string) < max:
                                    return rand_string, None
                    else:
                        rand_string = exrex.getone(regex)
                        return rand_string, None
                elif 'mac-address' in n_type.arg:
                    return generate_random_macaddr(), None
                else:
                    regex = n_type.i_type_spec.res[0][4]
                    rand_string = exrex.getone(regex)
                    return rand_string, None
            elif isinstance(n_type.i_type_spec, pType.RangeTypeSpec):
                if len(n_type.i_type_spec.ranges) > 0:
                    rand_range = choice(n_type.i_type_spec.ranges)
                    if rand_range[0] is not None and rand_range[1] is not None and n_type.i_type_spec.name != 'decimal64':
                        if rand_range[0] == 'min':
                            min = n_type.i_type_spec.min
                        else:
                            min = rand_range[0]
                        if rand_range[1] == 'max':
                            max = n_type.i_type_spec.max
                        else:
                            max = rand_range[1]
                        return str(randrange(min, max)), None
                    elif n_type.i_type_spec.name == 'decimal64':
                        min = n_type.i_type_spec.min.value
                        max = n_type.i_type_spec.max.value
                        rand_str = str(randrange(min, max))
                        rand_str = rand_str[:-(n_type.i_type_spec.fraction_digits)] + '.' + \
                                   rand_str[-(n_type.i_type_spec.fraction_digits):]
                        return rand_str, None
                    else:
                        return str(rand_range[0]), None
                else:
                    return str(randrange(n_type.i_type_spec.min, n_type.i_type_spec.max)), None
            elif isinstance(n_type.i_type_spec, pType.IdentityrefTypeSpec):
                identity = n_type.i_type_spec.idbases[0].i_identity.arg
                while True:
                    when_value = self.get_when_entry(node.arg, node.i_module.arg)
                    ref_list = []
                    for id_ref in self.identity_refs:
                        values = id_ref['ref_list']
                        if len(values) > 0:
                            try:
                                id_name = values[-1]
                            except IndexError:
                                continue
                            if id_name == identity:
                                ref_list.append(id_ref)
                    if len(ref_list) == 0:
                        for id_ref in self.identity_refs:
                            if id_ref['identity_name'] == identity:
                                random_identity = id_ref
                                break
                        pass
                    else:
                        random_identity = choice(ref_list)
                        pass
                    random_identity_value = random_identity['prefix'] + ':' + random_identity['identity_name']
                    if when_value is None:
                        break
                    elif when_value == random_identity_value:
                        break

                if random_identity['prefix'] != node.i_module.i_prefix:
                    nsmap = {random_identity['prefix']: random_identity['namespace']}
                    return random_identity['prefix'] + ':' + random_identity['identity_name'], nsmap
                else:
                    return random_identity['identity_name'], None
                #text = n_type.i_type_spec.name + ':' + n_type.i_type_spec.idbases[0].i_identity.arg
                #return text
            elif isinstance(n_type.i_type_spec, pType.EmptyTypeSpec):
                return "", None
            elif isinstance(n_type.i_type_spec, pType.UnionTypeSpec):
                #union_type = choice(n_type.i_type_spec.types)
                #we choose the first union type, which in theory is the most restrictive
                union_type = n_type.i_type_spec.types[0]
                return self.get_random_text(node=node, elem=None, ntype=union_type)
            elif isinstance(n_type.i_type_spec, pType.BitTypeSpec):
                text = ''
                bool_choice = [True, False]
                for bit in n_type.i_type_spec.bits:
                    rand_choice = choice(bool_choice)
                    if rand_choice:
                        text += bit[0] + ' '
                return text, None
            elif isinstance(n_type.i_type_spec, pType.Decimal64TypeSpec):
                rand_num = randrange(n_type.i_type_spec.min.value, n_type.i_type_spec.max.value)
                rand_str = str(rand_num)
                rand_str = rand_str[:-(n_type.i_type_spec.fraction_digits)] + '.' + \
                        rand_str[-(n_type.i_type_spec.fraction_digits):]
                return rand_str, None
            elif isinstance(n_type.i_type_spec, pType.BinaryTypeSpec):
                while True:
                    rand_bits = getrandbits(128)
                    encoded = base64.b64encode(str(rand_bits).encode("utf-8"))
                    if len(encoded) % 4 == 0:
                        break
                return encoded, None
        return "dummystring", None

    def resolve_leafrefs(self, root, is_leafref_key):

        leafref_entries = []

        def getmodule(xml_node):
            while xml_node.getparent() is not None and xml_node.getparent().getparent() is not None:
                xml_node = xml_node.getparent()

            return xml_node.tag

        def add_leafref_entry(node_name, node_module, value):
            modified = False
            for node in leafref_entries:
                if node['name'] == node_name and node['module'] == node_module:
                    if value not in node['values']:
                        node['values'].append(value)
                        modified = True
            if modified is False:
                new_node = {'name': node_name, 'module': node_module, 'values': []}
                new_node['values'].append(value)
                leafref_entries.append(new_node)

        def leafref_entry_exists(node_name, node_module, value):
            for node in leafref_entries:
                if node['name'] == node_name and node['module'] == node_module:
                    existing_values = node['values']
                    if value in existing_values:
                        return True
            return False

        def remove_child(kid, is_key):
            if is_key is True:
                par = kid.getparent()
                grandpar = par.getparent()
                grandpar.remove(par)
            else:
                par = kid.getparent()
                par.remove(kid)

        found_kid = False
        for child in root.getiterator():
            if is_leafref_key is True:
                string_to_search = "leafrefkey:"
            else:
                string_to_search = "leafref:"
            if child.text is not None and string_to_search in child.text:
                found_kid = True
                target = child.text.replace(string_to_search, "")

                target = make_target_for_xpath(target, child)
                node_module_name = getmodule(child)
                node_name = child.tag

                try:
                    leafref_targets = root.xpath(target)
                except etree.XPathEvalError as exc:
                    remove_child(child, is_leafref_key)
                if len(leafref_targets) > 0:
                    leafref_target = choice(leafref_targets)
                    emergency_stop = 1
                    while True:
                        if emergency_stop > 1000:
                            break
                        emergency_stop += 1
                        if leafref_entry_exists(node_name, node_module_name, leafref_target.text) is False:
                            add_leafref_entry(node_name, node_module_name, leafref_target.text)
                            break
                        else:
                            leafref_target = choice(leafref_targets)
                    child.text = leafref_target.text
                    if emergency_stop > 1000:
                        remove_child(child, is_leafref_key)
                else:
                    remove_child(child, is_leafref_key)
        return found_kid

    def generate_identity_refs(self, modules):
        for yam in modules:
            if len(yam.i_identities) > 0:
                for name in yam.i_identities:
                    identity = yam.i_identities[name]
                    identity_ref = {}
                    identity_name = identity.arg
                    identity_ref['identity_name'] = identity_name
                    namespace_prefix = identity.i_module.i_prefix
                    identity_ref['prefix'] = namespace_prefix
                    identity_ref['namespace'] = identity.i_module.search_one('namespace').arg
                    base_list = []
                    current_identity = identity
                    while True:
                        parent_base = current_identity.search_one('base')
                        if parent_base is None:
                            break
                        else:
                            parent_identity = parent_base.i_identity
                            base_list.append(parent_identity.arg)
                            current_identity = parent_identity
                    identity_ref['ref_list'] = base_list
                    self.identity_refs.append(identity_ref)

    def count_leafref_entries(self, node):
        try:
            leafref = node.i_leafref
            if leafref is not None:
                target = leafref.i_target_node
                while target.parent is not None:
                    target_parent = target.parent
                    if type(target_parent) is statements.ListStatement:
                        target_module = target_parent.i_module.arg
                        target_name = target_parent.arg
                        self.increase_instances(target_module, target_name)
                        break
                    else:
                        target = target.parent
        except Exception as exc:
            pass

        # we iterate further down the tree recursively
        #TODO see what happens in 'case', possible bug
        if type(node) in [statements.ModSubmodStatement, statements.ContainerStatement, statements.ListStatement]:
            try:
                kids = node.i_children
                if kids is not None and len(kids) > 0:
                    for kid in kids:
                        self.count_leafref_entries(kid)
            except Exception as exc:
                return

    def search_when_constraints(self, node):
        when_statement, target_node = is_when_statement_present(node)

        # TODO find a solution to integrate the nodes that have when statements
        if when_statement is not None:
            q = xpath_parser.parse(when_statement.arg)
            val = self.chk_xpath_expr(self.ctx, when_statement.i_orig_module,
                                      when_statement.pos, target_node, target_node, q)
            self.add_xml_xpath_expr(val)
            return None

        if type(node) in [statements.ModSubmodStatement, statements.ContainerStatement, statements.ListStatement]:
            try:
                kids = node.i_children
                if kids is not None and len(kids) > 0:
                    for kid in kids:
                        self.search_when_constraints(kid)
            except Exception as exc:
                return

    def increase_instances(self, module_name, target_node_name):
        modified = False
        for node in self.constraints:
            if node['module'] == module_name and node['name'] == target_node_name:
                node['instances'] = node['instances'] + 1
                modified = True

        if modified is False:
            new_node = {}
            new_node['module'] = module_name
            new_node['name'] = target_node_name
            new_node['instances'] = 1
            self.constraints.append(new_node)

    def chk_xpath_expr(self, ctx, mod, pos, initial, node, q):
        if type(q) == type([]):
            self.chk_xpath_path(ctx, mod, pos, initial, node, q)
        elif type(q) == type(()):
            if q[0] == 'absolute':
                return self.chk_xpath_path(ctx, mod, pos, initial, 'root', q[1])
            elif q[0] == 'relative':
                return self.chk_xpath_path(ctx, mod, pos, initial, node, q[1])
            elif q[0] == 'union':
                for qa in q[1]:
                    self.chk_xpath_path(ctx, mod, pos, initial, node, qa)
            elif q[0] == 'comp':
                target_node = self.chk_xpath_expr(ctx, mod, pos, initial, node, q[2])
                value = self.chk_xpath_expr(ctx, mod, pos, initial, node, q[3])
                if target_node is not None and \
                        value is not None and \
                        type(target_node) == statements.LeafLeaflistStatement and \
                        isinstance(value, basestring):
                    target_node_module = target_node.i_module.arg
                    target_node_name = target_node.arg
                    new_dict = {'name': target_node_name, 'module': target_node_module, 'value': value, 'operator': q[1],
                                'type': 'comp'}
                    return new_dict
                pass
            elif q[0] == 'arith':
                node = self.chk_xpath_expr(ctx, mod, pos, initial, node, q[2])
                self.chk_xpath_expr(ctx, mod, pos, initial, node, q[3])
            elif q[0] == 'bool':
                operand_1 = self.chk_xpath_expr(ctx, mod, pos, initial, node, q[2])
                operand_2 = self.chk_xpath_expr(ctx, mod, pos, initial, node, q[3])
                retval = {'type': 'bool', 'operand_1': operand_1, 'operand_2': operand_2, 'pred': q[1]}
                return retval
            elif q[0] == 'negative':
                self.chk_xpath_expr(ctx, mod, pos, initial, node, q[1])
            elif q[0] == 'function_call':
                self.chk_xpath_function(ctx, mod, pos, initial, node, q[1], q[2])
                if q[1] == 'derived-from-or-self':
                    target_node = self.chk_xpath_expr(ctx, mod, pos, initial, node, q[2][0])
                    value = self.chk_xpath_expr(ctx, mod, pos, initial, node, q[2][1])
                    if target_node is not None and \
                            value is not None and \
                            type(target_node) == statements.LeafLeaflistStatement and \
                            isinstance(value, basestring):
                        target_node_module = target_node.i_module.arg
                        target_node_name = target_node.arg
                        new_dict = {'name': target_node_name, 'module': target_node_module, 'value': value,
                                    'operator': '=', 'type': 'comp_idref'}
                        return new_dict
            elif q[0] == 'path_expr':
                return self.chk_xpath_expr(ctx, mod, pos, initial, node, q[1])
            elif q[0] == 'path':  # q[1] == 'filter'
                self.chk_xpath_expr(ctx, mod, pos, initial, node, q[2])
                self.chk_xpath_expr(ctx, mod, pos, initial, node, q[3])
            elif q[0] == 'var':
                # NOTE: check if the variable is known; currently we don't
                # have any variables in YANG xpath expressions
                pass
            elif q[0] == 'literal':
                # kind of hack to detect qnames, and mark the prefixes
                # as being used in order to avoid warnings.
                s = q[1]
                if s[0] == s[-1] and s[0] in ("'", '"'):
                    s = s[1:-1]
                    return s
                else:
                    return s

    def chk_xpath_function(self, ctx, mod, pos, initial, node, func, args):
        signature = None
        if func in xpath.core_functions:
            signature = xpath.core_functions[func]
        elif func in xpath.yang_xpath_functions:
            signature = xpath.yang_xpath_functions[func]
        elif (mod.i_version != '1' and func in xpath.yang_1_1_xpath_functions):
            signature = xpath.yang_1_1_xpath_functions[func]
        elif ctx.strict and func in xpath.extra_xpath_functions:
            # ERROR
            return None
        elif not (ctx.strict) and func in xpath.extra_xpath_functions:
            signature = xpath.extra_xpath_functions[func]

        if signature is None:
            # ERROR
            return None

        # check that the number of arguments are correct
        nexp = len(signature[0])
        nargs = len(args)
        if (nexp == nargs):
            pass
        elif (nexp == 0 and nargs != 0):
            # ERROR
            pass
        elif (signature[0][-1] == '?' and nargs == (nexp - 1)):
            pass
        elif signature[0][-1] == '?':
            # ERROR
            pass
        elif (signature[0][-1] == '*' and nargs >= (nexp - 1)):
            pass
        elif signature[0][-1] == '*':
            # ERROR
            pass
        elif nexp != nargs:
            # ERROR
            pass

        # FIXME implement checks from check_function()

        # check the arguments - FIXME check type
        for arg in args:
            self.chk_xpath_expr(ctx, mod, pos, initial, node, arg)
        return signature[1]

    def chk_xpath_path(self, ctx, mod, pos, initial, node, path):
        if len(path) == 0:
            return node
        head = path[0]
        if head[0] == 'var':
            # check if the variable is known as a node-set
            # currently we don't have any variables, so this fails
            # ERROR
            pass
        elif head[0] == 'function_call':
            func = head[1]
            args = head[2]
            rettype = self.chk_xpath_function(ctx, mod, pos, initial, node, func, args)
            if rettype is not None:
                # known function, check that it returns a node set
                if rettype != 'node-set':
                    # ERROR
                    pass
            if func == 'current':
                self.chk_xpath_path(ctx, mod, pos, initial, initial, path[1:])
        elif head[0] == 'step':
            axis = head[1]
            nodetest = head[2]
            preds = head[3]
            node1 = None
            if node is None:
                # we can't check the path
                pass
            elif axis == 'self':
                node1 = node
                pass
            elif axis == 'child' and nodetest[0] == 'name':
                prefix = nodetest[1]
                name = nodetest[2]
                if prefix is None:
                    pmodule = initial.i_module
                else:
                    pmodule = util.prefix_to_module(mod, prefix, pos, ctx.errors)
                if pmodule is not None:
                    if node == 'root':
                        children = pmodule.i_children
                    elif hasattr(node, 'i_children'):
                        children = node.i_children
                    else:
                        children = []
                    child = util.search_data_node(children, pmodule.i_modulename, name)
                    if child is None and node == 'root':
                        # ERROR
                        pass
                    elif child is None and node.i_module is not None:
                        # ERROR
                        pass
                    elif child is None:
                        # ERROR
                        pass
                    else:
                        node1 = child
            elif axis == 'parent' and nodetest == ('node_type', 'node'):
                p = util.data_node_up(node)
                if p is None:
                    # ERROR
                    pass
                else:
                    node1 = p
            else:
                # we can't validate the steps on other axis, but we can validate
                # functions etc.
                pass
            for p in preds:
                return self.chk_xpath_expr(ctx, mod, pos, initial, node1, p)
            return self.chk_xpath_path(ctx, mod, pos, initial, node1, path[1:])

    def add_when_entry(self, node_name, node_module, node_value):
        modified = False
        for node in self.when_values:
            if node['name'] == node_name and node['module'] == node_module:
                if node_value not in node['values']:
                    node['values'].append(node_value)
                modified = True
                break

        if modified is False:
            new_node = {'name': node_name, 'module': node_module, 'values': []}
            new_node['values'].append(node_value)
            self.when_values.append(new_node)

    def get_when_entry(self, node_name, node_module):
        for node in self.when_values:
            if node['name'] == node_name and node['module'] == node_module:
                random_value = choice(node['values'])
                return random_value
        return None

    def add_xml_xpath_expr(self, returned_xpath):
        if returned_xpath['type'] == 'comp' or returned_xpath['type'] == 'comp_idref':
            return self.add_when_entry(returned_xpath['name'], returned_xpath['module'], returned_xpath['value'])
        elif returned_xpath['type'] == 'bool':
            operand_1 = returned_xpath['operand_1']
            operand_2 = returned_xpath['operand_2']
            self.add_xml_xpath_expr(operand_1)
            self.add_xml_xpath_expr(operand_2)
