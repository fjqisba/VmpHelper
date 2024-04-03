#pragma once
#include <hexrays.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include "IDAPlugin.h"

//--------------------------------------------------------------------------
static plugmod_t* idaapi init()
{
    if (!is_idaq()) {
        return nullptr;
    }
    if (!init_hexrays_plugin()) {
        return nullptr;
    }
    //only support x86 currently
    std::string procName = inf.procname;
    if (procName != "metapc") {
        return nullptr;
    }
    return new IDAPlugin();
}

//--------------------------------------------------------------------------
static char comment[] = "It's a tool used to fuck vmp";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Revampire",			// the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};