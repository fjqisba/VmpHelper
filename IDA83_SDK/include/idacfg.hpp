/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef IDACFG_HPP
#define IDACFG_HPP

/// Get one of config parameters defined by CC_PARMS in ida.cfg.
/// All parameters for all compilers are stored in local map during last read
/// of ida.cfg - this function just returns previously stored parameter value for
/// given compiler (nullptr if no such parameter)
idaman const char *ida_export cfg_get_cc_parm(comp_t compid, const char *name);


/// Get header path config parameter from ida.cfg.
/// Also see cfg_get_cc_parm()

inline const char *cfg_get_cc_header_path(comp_t compid)
{
  return cfg_get_cc_parm(compid, "HEADER_PATH");
}


/// Get predefined macros config parameter from ida.cfg.
/// Also see cfg_get_cc_parm()

inline const char *cfg_get_cc_predefined_macros(comp_t compid)
{
  return cfg_get_cc_parm(compid, "PREDEFINED_MACROS");
}

/// Process one or more config directive(s).
/// \param directive the directives to process
/// \param priority priority \ref IDPOPT_RET
/// In the case of errors this function displays a message and exits.

idaman void ida_export process_config_directive(
        const char *directive,
        int priority=IDPOPT_PRI_HIGH);


#endif // IDACFG_HPP
