/*
 * Copyright 2012-2017 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Homepage: http://pax.grsecurity.net/
 *
 * Usage:
 * $ # for 4.5/4.6/C based 4.7
 * $ gcc -I`gcc -print-file-name=plugin`/include -I`gcc -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o rap_plugin.so rap_plugin.c
 * $ # for C++ based 4.7/4.8+
 * $ g++ -I`g++ -print-file-name=plugin`/include -I`g++ -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o rap_plugin.so rap_plugin.c
 * $ gcc -fplugin=./rap_plugin.so -fplugin-arg-rap_plugin-check=call test.c -O2
 */

#include "rap.h"

__visible int plugin_is_GPL_compatible;

static struct plugin_info rap_plugin_info = {
	.version	= "201612091515",
	.help		= "opt\tenable rap optimizations of HardenedLinux\n"
		          "hl_cfi\tenable the cfi implementation of HardenedLinux"
			  "and replace the original forwaed cfi of rap\n"
		          "typecheck=ret,call\tenable the corresponding type hash checking based features\n"
			  "retabort=ud2\t\t\toverride __builtin_trap with specified asm for both kinds of return address checking\n"
			  "callabort=ud2\t\t\toverride __builtin_trap with specified asm for indirect call checking\n"
			  "hash=abs,abs-finish,abs-ops,abs-attr,const,volatile\n"
			  "report=runtime\t\t\taid runtime reporting by passing the violating address in a designated register\n"
			  "report=func,fptr,abs\n"
};

rap_hash_flags_t imprecise_rap_hash_flags = {
	.qual_const	= 1,
	.qual_volatile	= 1,
};

tree rap_hash_type_node;

static bool report_func_hash, report_abs_hash;
const char *rap_abort_ret;
const char *rap_abort_call;

static const struct gcc_debug_hooks *old_debug_hooks;
static struct gcc_debug_hooks rap_debug_hooks;

static bool __rap_cgraph_indirectly_callable(cgraph_node_ptr node, void *data __unused)
{
#if BUILDING_GCC_VERSION >= 4008
	if (NODE_SYMBOL(node)->externally_visible)
#else
	if (node->local.externally_visible)
#endif
		return true;

	if (NODE_SYMBOL(node)->address_taken)
		return true;

	return false;
}

static bool rap_cgraph_indirectly_callable(cgraph_node_ptr node)
{
	return cgraph_for_node_and_aliases(node, __rap_cgraph_indirectly_callable, NULL, true);
}

static void rap_hash_align(const_tree decl)
{
	unsigned HOST_WIDE_INT rap_hash_offset;
	unsigned HOST_WIDE_INT skip;

	skip = 1ULL << align_functions_log;
	if (DECL_USER_ALIGN(decl))
		return;

	if (!optimize_function_for_speed_p(cfun))
		return;

	if (UNITS_PER_WORD == 8)
		rap_hash_offset = 2 * sizeof(rap_hash_t);
	else if (UNITS_PER_WORD == 4)
		rap_hash_offset =  sizeof(rap_hash_t);
	else
		gcc_unreachable();

	if (skip <= rap_hash_offset)
		return;

#ifdef TARGET_386
	{
		char padding[skip - rap_hash_offset];

		// this byte sequence helps disassemblers not trip up on the following rap hash
		memset(padding, 0xcc, sizeof padding - 1);
		padding[sizeof padding - 1] = 0xb8;
		if (TARGET_64BIT && sizeof padding > 1)
			padding[sizeof padding - 2] = 0x48;
		ASM_OUTPUT_ASCII(asm_out_file, padding, sizeof padding);
	}
#else
	ASM_OUTPUT_SKIP(asm_out_file, skip - rap_hash_offset);
#endif
}

static void rap_begin_function(tree decl)
{
	cgraph_node_ptr node;
	rap_hash_t imprecise_rap_hash;

	gcc_assert(debug_hooks == &rap_debug_hooks);

	// chain to previous callback
	if (old_debug_hooks && old_debug_hooks->begin_function)
		old_debug_hooks->begin_function(decl);

	// align the rap hash if necessary
	rap_hash_align(decl);

	// don't compute hash for functions called only directly
	node = cgraph_get_node(decl);
	gcc_assert(node);
	if (!rap_cgraph_indirectly_callable(node)) {
		imprecise_rap_hash.hash = 0;
	} else {
		imprecise_rap_hash = rap_hash_function_node_imprecise(node);
	}

	if (report_func_hash)
		inform(DECL_SOURCE_LOCATION(decl), "func rap_hash: %x %s", imprecise_rap_hash.hash, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));

	/* We do not have any risk, we do not need the hash key before the function. */
	if (0 == imprecise_rap_hash.hash 
	     || 
	     ! is_rap_function_maybe_roped (decl)) {
		return;
	}

	if (UNITS_PER_WORD == 8)
		fprintf(asm_out_file, "\t.quad %#llx\t%s __rap_hash_call_%s\n", (long long)imprecise_rap_hash.hash, ASM_COMMENT_START, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));
	else
		fprintf(asm_out_file, "\t.long %#x\t%s __rap_hash_call_%s\n", imprecise_rap_hash.hash, ASM_COMMENT_START, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));
}

static void rap_emit_hash_symbol(const char *type, const char *asmname, rap_hash_t hash)
{
	char *name = NULL;

	gcc_assert(asprintf(&name, "__rap_hash_%s_%s", type, asmname) != -1);

	fprintf(asm_out_file, "\t.pushsection .text\n");

	fprintf(asm_out_file, GLOBAL_ASM_OP " %s\n", name);
	if (UNITS_PER_WORD == 8)
		fprintf(asm_out_file, "\t.offset %#018llx\n", (long long)hash.hash);
	else if (UNITS_PER_WORD == 4)
		fprintf(asm_out_file, "\t.offset %#010x\n", hash.hash);
	else
		gcc_unreachable();

	ASM_OUTPUT_TYPE_DIRECTIVE(asm_out_file, name, "object");
	ASM_OUTPUT_LABEL(asm_out_file, name);
	free(name);

	fprintf(asm_out_file, "\t.popsection\n");
}

static void rap_emit_hash_symbols(const char *asmname, rap_hash_t hash)
{

	rap_emit_hash_symbol("call", asmname, hash);
	hash.hash = -hash.hash;
	rap_emit_hash_symbol("ret", asmname, hash);
}

/*
   emit an absolute symbol for each function that may be referenced through the plt
     - all externs
     - non-static functions
       - use visibility instead?

   .globl __rap_hash_call_func
   .offset 0xhash_for_func
   .type __rap_hash_call_func, @object
   __rap_hash_call_func:
   .previous
*/
static void rap_finish_unit(void *gcc_data __unused, void *user_data __unused)
{
	cgraph_node_ptr node;
	rap_hash_t hash;

	gcc_assert(debug_hooks == &rap_debug_hooks);

	hash.hash = 0;
	FOR_EACH_FUNCTION(node) {
		tree fndecl;
		const char *asmname;

		if (node->thunk.thunk_p || node->alias)
			continue;
		if (cgraph_function_body_availability(node) >= AVAIL_INTERPOSABLE) {
			if (!rap_cgraph_indirectly_callable(node))
				continue;
		}

#if BUILDING_GCC_VERSION >= 4007
		gcc_assert(cgraph_function_or_thunk_node(node, NULL) == node);
#endif

		fndecl = NODE_DECL(node);
		gcc_assert(fndecl);
		if (DECL_IS_BUILTIN(fndecl) && DECL_BUILT_IN_CLASS(fndecl) == BUILT_IN_NORMAL)
			continue;

		if (!TREE_PUBLIC(fndecl))
			continue;

		if (DECL_ARTIFICIAL(fndecl))
			continue;

		if (DECL_ABSTRACT_ORIGIN(fndecl) && DECL_ABSTRACT_ORIGIN(fndecl) != fndecl)
			continue;

		gcc_assert(DECL_ASSEMBLER_NAME(fndecl));
		asmname = IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fndecl));
		if (strchr(asmname, '.'))
			continue;

		if (asmname[0] == '*')
			asmname++;

		gcc_assert(asmname[0]);

		hash = rap_hash_function_node_imprecise(node);
		if (report_abs_hash)
			inform(DECL_SOURCE_LOCATION(fndecl), "abs rap_hash: %x %s", hash.hash, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fndecl)));
		rap_emit_hash_symbols(asmname, hash);
	}
}

// emit the rap hash as an absolute symbol for all functions seen in the frontend
// this is necessary as later unreferenced nodes will be removed yet we'd like to emit as many hashes as possible
static void rap_emit_hash_symbols_finish_decl(void *event_data, void *data __unused)
{
	tree fndecl = (tree)event_data;
	rap_hash_t hash;
	const char *asmname;

	if (fndecl == error_mark_node)
		return;

	if (TREE_CODE(fndecl) != FUNCTION_DECL)
		return;

	if (!TREE_PUBLIC(fndecl))
		return;

	if (DECL_ARTIFICIAL(fndecl))
		return;

	if (DECL_ABSTRACT_ORIGIN(fndecl) && DECL_ABSTRACT_ORIGIN(fndecl) != fndecl)
		return;

	asmname = DECL_NAME_POINTER(fndecl);
	gcc_assert(asmname[0]);

	if (strchr(asmname, '.'))
		return;

	hash = rap_hash_function_decl(fndecl, imprecise_rap_hash_flags);
	rap_emit_hash_symbols(asmname, hash);
	if (report_abs_hash)
		inform(DECL_SOURCE_LOCATION(fndecl), "abs rap_hash: %x %s", hash.hash, asmname);
}

static void rap_emit_hash_symbols_finish_decl_attr(void *event_data, void *data)
{
	tree fndecl = (tree)event_data;

	if (fndecl == error_mark_node)
		return;

	if (TREE_CODE(fndecl) != FUNCTION_DECL)
		return;

	if (!lookup_attribute("rap_hash", TYPE_ATTRIBUTES(TREE_TYPE(fndecl))))
		return;

	rap_emit_hash_symbols_finish_decl(event_data, data);
}

static void rap_emit_hash_symbols_type(const_tree type, const char *prefix)
{
	const_tree field;

	if (TYPE_FIELDS(type) == NULL_TREE)
		return;

	// TODO skip constified types for now
	if (TYPE_READONLY(type))
		return;

	// create the prefix if it hasn't been done yet
	if (!*prefix) {
		const_tree name = type_name(type);

		// skip an anonymous struct embedded inside another one
		// we'll see it when we walk the parent later
		if (!name)
			return;

		prefix = IDENTIFIER_POINTER(name);
		gcc_assert(*prefix);
	}

	for (field = TYPE_FIELDS(type); field; field = TREE_CHAIN(field)) {
		const_tree fieldtype, fieldname;
		char *hashname = NULL, *newprefix = NULL;
		rap_hash_t hash;

		fieldtype = TREE_TYPE(field);
		switch (TREE_CODE(fieldtype)) {
		default:
			continue;

		case RECORD_TYPE:
		case UNION_TYPE:
			fieldname = DECL_NAME(field);
			if (!fieldname)
				continue;
			gcc_assert(asprintf(&newprefix, "%s.%s", prefix, IDENTIFIER_POINTER(fieldname)) != -1);
			rap_emit_hash_symbols_type(fieldtype, newprefix);
			free(newprefix);
			continue;

		case POINTER_TYPE:
			fieldtype = TREE_TYPE(fieldtype);
			if (TREE_CODE(fieldtype) != FUNCTION_TYPE)
				continue;

			hash = rap_hash_function_type(fieldtype, imprecise_rap_hash_flags);
			fieldname = DECL_NAME(field);
			gcc_assert(fieldname);
			gcc_assert(asprintf(&hashname, "%s.%s", prefix, IDENTIFIER_POINTER(fieldname)) != -1);
			if (report_abs_hash)
				inform(DECL_SOURCE_LOCATION(field), "abs rap_hash: %x %s", hash.hash, hashname);
			rap_emit_hash_symbols(hashname, hash);
			free(hashname);
			continue;
		}
	}
}

static void rap_emit_hash_symbols_finish_type(void *event_data, void *data __unused)
{
	const_tree type = (const_tree)event_data;

	if (type == NULL_TREE || type == error_mark_node)
		return;

	if (!lookup_attribute("rap_hash", TYPE_ATTRIBUTES(type)))
		return;

	switch (TREE_CODE(type)) {
	default:
		debug_tree(type);
		gcc_unreachable();

#if BUILDING_GCC_VERSION >= 5000
	case ENUMERAL_TYPE:
#endif
	case UNION_TYPE:
		break;

	case RECORD_TYPE:
		rap_emit_hash_symbols_type(type, "");
		break;
	}
}

static void rap_assembly_start(void)
{
	gcc_assert(debug_hooks == &rap_debug_hooks);

	// chain to previous callback
	if (old_debug_hooks && old_debug_hooks->assembly_start)
		old_debug_hooks->assembly_start();

#ifdef TARGET_386
	if (1) {
		fprintf(asm_out_file,
			"\t.macro rap_indirect_call target hash\n"
			"\t\tjmp 2001f\n"
			"\t\t%s __rap_hash_ret_\\hash\n"
			"\t\t.skip 8-(2002f-2001f),0xcc\n"
			"\t2001:	call \\target\n"
			"\t2002:\n"
			"\t.endm\n",
			(UNITS_PER_WORD == 8 ? ".quad" : ".long")
		);

		fprintf(asm_out_file,
			"\t.macro rap_direct_call target hash=""\n"
			"\t\t.ifb \\hash\n"
			"\t\trap_indirect_call \\target \\target\n"
			"\t\t.else\n"
			"\t\trap_indirect_call \\target \\hash\n"
			"\t\t.endif\n"
			"\t.endm\n"
		);
	}

	if (1) {
		fprintf(asm_out_file,
			"\t.macro rap_ret target\n"
			"\t\tret\n"
			"\t.endm\n"
		);
	}
#else
#error unsupported target
#endif
}

static void (*old_override_options_after_change)(void);

static void rap_override_options_after_change(void)
{
	if (old_override_options_after_change)
		old_override_options_after_change();

#if BUILDING_GCC_VERSION >= 5000
	flag_ipa_icf_functions = 0;
#endif
	flag_crossjumping = 0;
	flag_optimize_sibling_calls = 0;
}

static void rap_start_unit_common(void *gcc_data __unused, void *user_data __unused)
{
	rap_hash_type_node = long_integer_type_node;

	if (debug_hooks)
		rap_debug_hooks = *debug_hooks;

	if (1)
		rap_debug_hooks.assembly_start = rap_assembly_start;
	rap_debug_hooks.begin_function = rap_begin_function;

	old_debug_hooks = debug_hooks;
	debug_hooks = &rap_debug_hooks;

	old_override_options_after_change = targetm.override_options_after_change;
	targetm.override_options_after_change = rap_override_options_after_change;
}


static bool rap_version_check(struct plugin_gcc_version *gcc_version, struct plugin_gcc_version *plugin_version)
{
	if (!gcc_version || !plugin_version)
		return false;
#if BUILDING_GCC_VERSION >= 5000
	if (strncmp(gcc_version->basever, plugin_version->basever, 4))
#else
	if (strcmp(gcc_version->basever, plugin_version->basever))
#endif
		return false;
#if 0
	if (strcmp(gcc_version->datestamp, plugin_version->datestamp))
		return false;
	if (strcmp(gcc_version->devphase, plugin_version->devphase))
		return false;
	if (strcmp(gcc_version->revision, plugin_version->revision))
		return false;
//	if (strcmp(gcc_version->configuration_arguments, plugin_version->configuration_arguments))
//		return false;
#endif
        return true;
}

static tree handle_rap_hash_attribute(tree *node, tree name, tree args __unused, int flags, bool *no_add_attrs)
{
	*no_add_attrs = true;

	gcc_assert(TYPE_P(*node));

	switch (TREE_CODE(*node)) {
	default:
		error("%qE attribute applies to structure and function types only (%qT)", name, *node);
		return NULL_TREE;

	case FUNCTION_TYPE:
	case RECORD_TYPE:
		break;
	}

	*no_add_attrs = false;
	return NULL_TREE;
}


static struct attribute_spec rap_hash_attr = {
	.name			= "rap_hash",
	.min_length		= 0,
	.max_length		= 0,
	.decl_required		= false,
	.type_required		= true,
	.function_type_required	= false,
	.handler		= handle_rap_hash_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity	= true
#endif
};

static void register_attributes(void *event_data __unused, void *data __unused)
{
	register_attribute(&rap_hash_attr);
}

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable_abs = false;
	bool enable_abs_finish = false;
	bool enable_abs_ops = false;
	bool enable_abs_attr = false;

	// hl-cfi & pointer set build pass insert.
	PASS_INFO(hl_gather,		"pta",	        1, PASS_POS_INSERT_AFTER);
	PASS_INFO(hl_cfi,		"hl_gather",	1, PASS_POS_INSERT_AFTER);

	if (!rap_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

#if BUILDING_GCC_VERSION >= 5000
	if (flag_ipa_icf_functions) {
//		warning_at(UNKNOWN_LOCATION, 0, G_("-fipa-icf is incompatible with %s, disabling..."), plugin_name);
//		inform(UNKNOWN_LOCATION, G_("-fipa-icf is incompatible with %s, disabling..."), plugin_name);
		flag_ipa_icf_functions = 0;
	}
#endif

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "disable"))
			continue;
		/* Request rap optimizations.  */
		if (! strcmp(argv[i].key, "opt"))
		  {
		    require_call_hl_gather = true;
		    continue;
		  }
		/* Request cfi replace.  */
		if (! strcmp(argv[i].key, "hl_cfi"))
		  {
		    require_call_hl_cfi = true;
		    continue;
		  }
		/* dumps.  */
		if (! strcmp(argv[i].key, "hl_cfi_dump"))
		  {
		    require_hl_cfi_dump = true;
		    continue;    
		  }
		if (!strcmp(argv[i].key, "typecheck")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "ret"))
					;//enable_type_ret = true;
				else if (!strcmp(value, "call"))
					;//enable_type_call = true;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		if (!strcmp(argv[i].key, "retabort")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			rap_abort_ret = xstrdup(argv[i].value);
			continue;
		}

		if (!strcmp(argv[i].key, "cullabort")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			rap_abort_call = xstrdup(argv[i].value);
			continue;
		}

		if (!strcmp(argv[i].key, "hash")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "abs"))
					enable_abs = enable_abs_finish = true;
				else if (!strcmp(value, "abs-finish"))
					enable_abs_finish = true;
				else if (!strcmp(value, "abs-ops"))
					enable_abs_ops = true;
				else if (!strcmp(value, "abs-attr"))
					enable_abs_attr = true;
//				else if (!strcmp(value, "const"))
//					imprecise_rap_hash_flags.qual_const = 1;
//				else if (!strcmp(value, "volatile"))
//					imprecise_rap_hash_flags.qual_volatile = 1;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		if (!strcmp(argv[i].key, "report")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "func"))
					report_func_hash = true;
				else if (!strcmp(value, "abs"))
					report_abs_hash = true;
				else if (!strcmp(value, "runtime"))
					;//report_runtime = true;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &rap_plugin_info);
	/* register the rap optimization*/
        register_callback(plugin_name, PLUGIN_OVERRIDE_GATE, rap_try_call_ipa_pta, 
			  (void *)&cfi_gcc_optimize_level);


	if (enable_abs)
#if BUILDING_GCC_VERSION >= 4007
		register_callback(plugin_name, PLUGIN_FINISH_DECL, rap_emit_hash_symbols_finish_decl, NULL);
#else
		register_callback(plugin_name, PLUGIN_PRE_GENERICIZE, rap_emit_hash_symbols_finish_decl, NULL);
#endif
	if (enable_abs_ops)
		register_callback(plugin_name, PLUGIN_FINISH_TYPE, rap_emit_hash_symbols_finish_type, NULL);
	if (enable_abs_attr)
#if BUILDING_GCC_VERSION >= 4007
		register_callback(plugin_name, PLUGIN_FINISH_DECL, rap_emit_hash_symbols_finish_decl_attr, NULL);
#else
		register_callback(plugin_name, PLUGIN_PRE_GENERICIZE, rap_emit_hash_symbols_finish_decl_attr, NULL);
#endif
	
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);
	register_callback(plugin_name, PLUGIN_START_UNIT, rap_start_unit_common, NULL);
	if (enable_abs_finish)
		register_callback(plugin_name, PLUGIN_FINISH_UNIT, rap_finish_unit, NULL);
	register_callback(plugin_name, PLUGIN_ALL_IPA_PASSES_START, rap_calculate_func_hashes, NULL);

	if (require_call_hl_gather)
	  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hl_gather_pass_info);
	// 
	if (require_call_hl_cfi)
	  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hl_cfi_pass_info);

	return 0;
}
