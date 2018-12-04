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
};

rap_hash_flags_t imprecise_rap_hash_flags = {
	.qual_const	= 1,
	.qual_volatile	= 1,
};


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


static void rap_assembly_start(void)
{
	gcc_assert(debug_hooks == &rap_debug_hooks);

	// chain to previous callback
	if (old_debug_hooks && old_debug_hooks->assembly_start)
		old_debug_hooks->assembly_start();

#ifdef TARGET_386
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

	if (debug_hooks)
		rap_debug_hooks = *debug_hooks;

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


__visible int plugin_init(struct plugin_name_args *plugin_info, 
		          struct plugin_gcc_version *version)
{
	int i;
	const char *const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument *const argv = plugin_info->argv;

	// hl-cfi & pointer set build pass insert.
	PASS_INFO(hl_gather,		"pta",	        1, PASS_POS_INSERT_AFTER);
	PASS_INFO(hl_cfi,		"hl_gather",	1, PASS_POS_INSERT_AFTER);

	if (!rap_version_check(version, &gcc_version)) 
	{
	  error_gcc_version(version);
	  return 1;
	}


	for (i = 0; i < argc; ++i) 
	{
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

	  error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &rap_plugin_info);
	/* register the rap optimization*/
        register_callback(plugin_name, PLUGIN_OVERRIDE_GATE, rap_try_call_ipa_pta, 
			  (void *)&cfi_gcc_optimize_level);
	register_callback(plugin_name, PLUGIN_START_UNIT, rap_start_unit_common, NULL);
	register_callback(plugin_name, PLUGIN_ALL_IPA_PASSES_START, rap_calculate_func_hashes, NULL);
	
	if (require_call_hl_gather)
	  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hl_gather_pass_info);
	if (require_call_hl_cfi)
		;
        register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hl_cfi_pass_info);

	return 0;
}
