#ifndef SRCLANG_H
#define SRCLANG_H

#include <typeinf.hpp>

/*! \file srclang.hpp

  \brief Third-party compiler support
*/

/// \defgroup SRCLANG_ Source language IDs
//@{
#define SRCLANG_C     0x01 ///< C
#define SRCLANG_CPP   0x02 ///< C++
#define SRCLANG_OBJC  0x04 ///< Objective-C
#define SRCLANG_SWIFT 0x08 ///< Swift  (not supported yet)
#define SRCLANG_GO    0x10 ///< Golang (not supported yet)
//@}

/// Bitmask that describes all source languages supported by a compiler. Combination of \ref SRCLANG_ values
typedef int srclang_t;


/// Set the parser with the given name as the current parser.
/// Pass nullptr or an empty string to select the default parser.
/// \return false if no parser was found with the given name

idaman bool ida_export select_parser_by_name(const char *name);


/// Set the parser that supports the given language(s) as the current parser.
/// The selected parser must support all languages specified by the given ::srclang_t.
/// \return false if no such parser was found

idaman bool ida_export select_parser_by_srclang(srclang_t lang);


/// Set the command-line args to use for invocations of the parser with the given name
/// \param parser_name  name of the target parser
/// \param argv         argument list
/// \retval -1    no parser was found with the given name
/// \retval -2    the operation is not supported by the given parser
/// \retval  0    success

idaman int ida_export set_parser_argv(const char *parser_name, const char *argv);


/// Parse type declarations in the specified language
/// \param lang     the source language(s) expected in the input
/// \param til      type library to store the types
/// \param input    input source. can be a file path or decl string
/// \param is_path  true if input parameter is a path to a source file, false if the input is an in-memory source snippet
/// \retval -1    no parser was found that supports the given source language(s)
/// \retval else  the number of errors encountered in the input source

idaman int ida_export parse_decls_for_srclang(
        srclang_t lang,
        til_t *til,
        const char *input,
        bool is_path);


/// Parse type declarations using the parser with the specified name
/// \param parser_name  name of the target parser
/// \param til          type library to store the types
/// \param input        input source. can be a file path or decl string
/// \param is_path      true if input parameter is a path to a source file, false if the input is an in-memory source snippet
/// \retval -1    no parser was found with the given name
/// \retval else  the number of errors encountered in the input source

idaman int ida_export parse_decls_with_parser(
        const char *parser_name,
        til_t *til,
        const char *input,
        bool is_path);



#endif // !SRCLANG_H
