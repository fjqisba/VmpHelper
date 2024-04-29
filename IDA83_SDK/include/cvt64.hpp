/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2005-2023 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 *
 *      Convert 'idb' file to 'i64' file.
 *
 *      Conversion is performed by IDA64 in the special conversion mode.
 *      To convert data we need to read it in the 32-bit format from the idb file,
 *      convert it to the 64-bit format and write it to the i64 file.
 *
 *      This file contains the conversion helpers functions for plugins.
 *
 *      Also see the following events:
 *        * processor_t::ev_cvt64_supval
 *        * processor_t::ev_cvt64_hashval
 *
 *      For more information check the cvt64.md file.
 */

#pragma once

//-------------------------------------------------------------------------
// Conversion of 32-bit databases to 64-bit is performed by ida64,
// only in IDA Pro and IDA Teams
#if defined(__EA64__) && !defined(DEMO_OR_FREE) && !defined(IDAHOME)
#define CVT64
#endif

//------------------------------------------------------------------------
// This class keeps 32-bit addresses regardless of IDA bitness
struct range32_t
{
  ea32_t start_ea = 0;
  ea32_t end_ea = 0;

  range32_t() {}
  range32_t(ea_t ea1, ea_t ea2) : start_ea(ea1), end_ea(ea2) {}
};

//------------------------------------------------------------------------
/// Unpack an address.
/// This helper deserializes an address from its serialialed form.
/// If IDA is running in the conversion mode, it reads a 32-bit address, otherwise
/// the number of bits in the address depends on the bitness of IDA (IDA32 assumes
/// 32-bit addresses, and IDA64 assumes 64-bit addresses).
/// 32-bit BADADDR is converted into 64-bit BADADDR in the conversion mode.
THREAD_SAFE inline ea_t mmdsr_unpack_ea(memory_deserializer_t &mmdsr, ea_t base = 0)
{
#ifdef CVT64
  if ( is_cvt64() )
  {
    ea_t ea = ea32_t(mmdsr.unpack_dd()+base);
    return ea == BADADDR32 ? BADADDR : ea;
  }
#endif
  return mmdsr.unpack_ea()+base;
}

//------------------------------------------------------------------------
/// Unpack an address relative to the specified base address.
THREAD_SAFE inline ea_t mmdsr_unpack_ea_neg(memory_deserializer_t &mmdsr, ea_t base)
{
#ifdef CVT64
  if ( is_cvt64() )
  {
    ea_t ea = ea32_t(base - mmdsr.unpack_dd());
    return ea == BADADDR32 ? BADADDR : ea;
  }
#endif
  return base - mmdsr.unpack_ea();
}

//------------------------------------------------------------------------
/// Unpack a netnode index
THREAD_SAFE inline ea_t mmdsr_unpack_node2ea(memory_deserializer_t &mmdsr)
{
  nodeidx_t ndx = mmdsr_unpack_ea(mmdsr);
  return node2ea(ndx);
}

//------------------------------------------------------------------------
/// Unpack as a signed value
THREAD_SAFE inline sval_t mmdsr_unpack_sval(memory_deserializer_t &mmdsr, sval_t base=0)
{
#ifdef CVT64
  if ( is_cvt64() )
    return (int32)(mmdsr.unpack_dd() + base);
#endif
  return mmdsr.unpack_ea() + base;
}

//------------------------------------------------------------------------
/// Unpack vector of addresses.
THREAD_SAFE inline void mmdsr_unpack_eavec(
        eavec_t *vec,
        memory_deserializer_t &mmdsr,
        ea_t ea)
{
#ifdef CVT64
  if ( is_cvt64() )
  {
    ea_t old = ea;
    int n = mmdsr.unpack_dw();
    vec->resize_noinit(n);
    for ( int i=0; i < n; ++i )
    {
      old = mmdsr_unpack_ea(mmdsr, old);
      vec->at(i) = old;
    }
    return;
  }
#endif
  return mmdsr.unpack_eavec(vec, ea);
}

//------------------------------------------------------------------------
/// Read a stored (without packing) address.
THREAD_SAFE inline ea_t mmdsr_read_ea(memory_deserializer_t &mmdsr)
{
#ifdef CVT64
  if ( is_cvt64() )
  {
    ea32_t ea32 = BADADDR32;
    mmdsr.read(&ea32, sizeof(ea32));
    return ea32;
  }
#endif
  ea_t ea = BADADDR;
  mmdsr.read(&ea, sizeof(ea));
  return ea;
}

//------------------------------------------------------------------------
/// Convert a blob whose content does not depend on the IDA bitness.
/// This function is very simple: it reads from a netnode and writes back to the
/// same netnode. While this action looks superfluous, we need it because the
/// netnode level functions read from the input 32-bit btree and write the
/// output 64-bit btree. In other words, this function copies blob of information
/// from one btree to another.
inline int cvt64_blob(netnode node, nodeidx_t start, uchar tag)
{
  bytevec_t buf;
  if ( node.getblob(&buf, start, tag) > 0 )
  {
    node.setblob(buf.begin(), buf.size(), start, tag);
    return 1;
  }
  return 0;
}

#ifdef CVT64
//------------------------------------------------------------------------
/// Descriptor of information stored in a netnode.
/// Each NETNODE+TAG require a separate descriptor.
/// One descriptor can be used for a single index or for all indexes.
/// This description is used by cvt64_node_supval_for_event() to convert
/// netnode data.
struct cvt64_node_tag_t
{
  /// netnode id
  nodeidx_t node;

  /// tag, can be supplemented with NETMAP_... and additional CVT64_ZERO_IDX flags
  /// use the following flags to specify:
  ///   NETMAP_VAL      - value type is nodeidx32_t that will be converted into nodeidx64_t
  ///                     example: any altval()
  ///   NETMAP_VAL_NDX  - value is a netnode index or address
  ///                     valid with NETMAP_VAL,
  ///                     BADADDR32 will be converted to BADADDR
  ///   NETMAP_V8       - uchar value
  /// If none of the above flags are set, then the value will be copied without any conversion.
  /// For example, if value was written to database using the following call:
  ///   helper.easet(ea, dxref, DXREF_TAG)
  /// then use the following value for TAG:
  ///   NETMAP_VAL|NETMAP_VAL_NDX|DXREF_TAG
#define CVT64_ZERO_IDX  0x00800000    ///< EXACT_ALT specifies the single value at index 0
  int tag;

  /// The index described by the descriptor.
  /// For all indexes of the given tag, set EXACT_ALT to 0.
  /// For a single index, set EXACT_ALT to the index. If the index to convert
  /// is zero, also set CVT64_ZERO_IDX.
  /// Note:
  ///   Place descriptors with EXACT_ALT above all other descriptors in the table.
  nodeidx_t exact_alt;
};

// Descriptors for popular database values
#define CVT64_NODE_DEVICE    { helper, stag, nodeidx_t(-1) }
#define CVT64_NODE_IDP_FLAGS { helper, atag|NETMAP_VAL, nodeidx_t(-1) }

/// Helper for the processor_t::ev_cvt64_supval event.
/// This function converts the information stored in netnodes. It can
/// handle standard types of information like altvals, addreses, supvals.
/// If information is stored as a blob with complex structure, then it must
/// be handled manually: read, convert, and write back to the same netnode.
/// \param va             - arguments for processor_t::ev_cvt64_supval
/// \param node_info      - descriptors
/// \param node_info_qty  - size of the descriptors array
/// \return result of processor_t::ev_cvt64_supval event processing

idaman int ida_export cvt64_node_supval_for_event(
        va_list va,
        const cvt64_node_tag_t *node_info,
        size_t node_info_qty);

#endif // CVT64
